import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.connections import (connection_path, connection_record, exposure_for,
                                   migrate_connection, save_connection)
from dot_herdr.core import Rejected
from dot_herdr.setup import doctor, validate_config


EXPOSURE = {'provider': 'cloudflare', 'hostname': 'connector.example.test',
            'tunnel_id': '00112233-4455-6677-8899-aabbccddeeff', 'mode': 'api'}


class SharedKeysTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config.json'
        self.cfg = {'store': str(self.root / 'connector.sqlite'),
                    'socket': str(self.root / 'source.sock'), 'subjects': [],
                    'session_users': ['fixture'], 'signin': 'builtin',
                    'resource': 'https://connector.example.test/mcp',
                    'issuer': 'https://connector.example.test',
                    'jwks_url': 'https://connector.example.test/.well-known/jwks.json'}

    def write_config(self, cfg=None):
        self.config.write_text(json.dumps(self.cfg if cfg is None else cfg))
        self.config.chmod(0o600)

    def record(self, exposure=EXPOSURE):
        return {'version': 1, 'stage': 'client', 'route': 'https',
                'wiring': 'registered-plugin', 'endpoint': self.cfg['resource'],
                'client_app': 'chatgpt-web', 'exposure': exposure}

    def test_exposure_round_trip_and_helper(self):
        for mode in ('api', 'login'):
            value = {**EXPOSURE, 'mode': mode}
            record = self.record(value)
            self.assertIs(exposure_for(record), value)
            save_connection(self.config, record)
            self.assertEqual(connection_record(self.config), record)
            self.assertEqual(exposure_for(self.config), value)
        self.assertIsNone(exposure_for({}))
        self.assertIsNone(exposure_for(self.root / 'missing-config.json'))

    def test_exposure_invalid_shapes_rejected_on_load_and_save(self):
        invalid = [None, False, 1, '', [], list(EXPOSURE), {},
                   {k: v for k, v in EXPOSURE.items() if k != 'mode'},
                   {**EXPOSURE, 'extra': 'unexpected'},
                   {**EXPOSURE, 'provider': 'other'},
                   {**EXPOSURE, 'provider': ['cloudflare']},
                   {**EXPOSURE, 'mode': 'other'}, {**EXPOSURE, 'mode': ['api']}]
        for hostname in (None, 123, '', 'https://connector.example.test',
                         'connector.example.test:443', 'connector.example.test/mcp',
                         'connector_example.test', 'a..test', '.test', 'test.',
                         '-bad.test', 'bad-.test', 'a' * 64 + '.test',
                         '.'.join(['a' * 63] * 4), 'cönnector.test', 'a.test\n'):
            invalid.append({**EXPOSURE, 'hostname': hostname})
        for tunnel_id in (None, 123, '', 'not-a-uuid', '00112233445566778899aabbccddeeff',
                          '{00112233-4455-6677-8899-aabbccddeeff}',
                          '00112233-4455-6677-8899-aabbccddeefg'):
            invalid.append({**EXPOSURE, 'tunnel_id': tunnel_id})
        path = connection_path(self.config)
        for value in invalid:
            with self.subTest(exposure=value):
                record = self.record(value)
                self.assertIsNone(exposure_for(record))
                path.unlink(missing_ok=True)
                with self.assertRaisesRegex(Rejected, '^invalid_connection_record$'):
                    save_connection(self.config, record)
                self.assertFalse(path.exists())
                path.write_text(json.dumps(record))
                path.chmod(0o600)
                with self.assertRaisesRegex(Rejected, '^invalid_connection_record$'):
                    connection_record(self.config)

    def test_hostname_and_uuid_boundaries(self):
        for hostname in ('A-b.Example.TEST', 'a', '.'.join(['a' * 63] * 3 + ['a' * 61])):
            record = self.record({**EXPOSURE, 'hostname': hostname,
                                  'tunnel_id': EXPOSURE['tunnel_id'].upper()})
            save_connection(self.config, record)
            self.assertEqual(connection_record(self.config), record)

    def test_migration_preserves_exposure(self):
        self.write_config()
        save_connection(self.config, self.record())
        migrate_connection(self.config, 'loopback', 'registered-plugin',
                           home=self.root, codex_home=self.root / '.codex',
                           say=lambda _: None)
        record = connection_record(self.config)
        self.assertEqual(record['exposure'], EXPOSURE)
        self.assertEqual(record['route'], 'loopback')
        self.assertEqual(record['wiring'], 'registered-plugin')
        self.assertNotIn('migration', record)

    def test_builtin_config_valid(self):
        self.assertIs(validate_config(self.cfg), self.cfg)
        cfg = {**self.cfg, 'resource': 'https://connector.example.test:8443/other/mcp',
               'issuer': 'https://connector.example.test:8443',
               'jwks_url': 'https://connector.example.test:8443/.well-known/jwks.json'}
        self.assertEqual(validate_config(cfg), cfg)

    def test_builtin_config_invalid(self):
        invalid = [{**self.cfg, 'signin': value} for value in (None, False, {}, [], 'external', '')]
        invalid.extend([{k: v for k, v in self.cfg.items() if k != 'jwks_url'},
                        {**self.cfg, 'public_key': str(self.root / 'public.pem')}])
        for issuer in ('https://auth.example.test', 'https://connector.example.test/oauth',
                       'https://connector.example.test/', None):
            invalid.append({**self.cfg, 'issuer': issuer})
        for jwks in (None, 'https://connector.example.test/keys',
                     'https://auth.example.test/.well-known/jwks.json'):
            invalid.append({**self.cfg, 'jwks_url': jwks})
        for resource in (None, 'http://connector.example.test/mcp'):
            invalid.append({**self.cfg, 'resource': resource})
        for cfg in invalid:
            with self.subTest(cfg=cfg), self.assertRaisesRegex(
                    Rejected, '^invalid_builtin_signin_configuration$'):
                validate_config(cfg)

    def test_external_config_keeps_existing_validation(self):
        cfg = {k: v for k, v in self.cfg.items() if k != 'signin'}
        cfg['issuer'] = 'https://auth.example.test/oauth'
        cfg['jwks_url'] = 'https://auth.example.test/keys'
        self.assertEqual(validate_config(cfg), cfg)
        cfg.pop('jwks_url')
        cfg['public_key'] = str(self.root / 'public.pem')
        self.assertEqual(validate_config(cfg), cfg)
        cfg['jwks_url'] = 'https://auth.example.test/keys'
        with self.assertRaisesRegex(Rejected, '^exactly_one_auth_key_source_required$'):
            validate_config(cfg)

    def test_doctor_builtin_check_read_only(self):
        self.write_config()
        root = self.root / 'signin'
        def snapshot():
            return {str(p): (p.stat().st_mode, p.read_bytes() if p.is_file() else None)
                    for p in self.root.rglob('*')}
        with patch('dot_herdr.signin.signin_root', side_effect=AssertionError('mkdir forbidden')), \
             patch('dot_herdr.signin.initialize', side_effect=AssertionError('initialize forbidden')):
            for password, keys in ((False, False), (True, False), (False, True), (True, True)):
                if password or keys:
                    root.mkdir(mode=0o700, exist_ok=True)
                for name, present in (('password.json', password), ('keys.json', keys)):
                    path = root / name
                    if present:
                        path.write_text('{}')
                    else:
                        path.unlink(missing_ok=True)
                before = snapshot()
                report = doctor(self.config)
                checks = [c for c in report['checks'] if c['name'] == 'builtin_signin']
                self.assertEqual(checks, [{'name': 'builtin_signin',
                                          'status': 'pass' if password and keys else 'blocked'}])
                self.assertEqual(snapshot(), before)
                if not password and not keys:
                    self.assertFalse(root.exists())

    def test_doctor_external_config_omits_builtin_check(self):
        self.write_config({k: v for k, v in self.cfg.items() if k != 'signin'})
        self.assertNotIn('builtin_signin', [c['name'] for c in doctor(self.config)['checks']])
        self.assertFalse((self.root / 'signin').exists())


if __name__ == '__main__':
    unittest.main()
