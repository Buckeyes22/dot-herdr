"""Offline regressions for the setup/status/update release fixes."""
import contextlib
import io
import json
import os
import socket
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from dot_herdr import cli, installation
from dot_herdr.connections import connection_record, save_connection
from dot_herdr.onboarding import draft_path, guided_setup, pending_auth, pending_auth_path, save_config
from dot_herdr.status import render, status


class SetupReleaseFixes(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / 'config.json'
        self.socket = self.root / 'herdr.sock'
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.socket))
        self.addCleanup(sock.close)
        self.cfg = {'store': str(self.root / 'state.sqlite'), 'socket': str(self.socket),
                    'issuer': 'https://auth.example.test', 'resource': 'https://connector.example.test/mcp',
                    'jwks_url': 'https://auth.example.test/jwks',
                    'subjects': [{'key': 'old', 'user_subject': 'replace-with-approved-issuer-subject',
                                  'owner': 'operator', 'pane': 'pane', 'terminal': 'terminal-old',
                                  'native': None, 'control': True, 'content': True}], 'session_users': []}

    async def test_changed_draft_source_recovers_with_fresh_selection(self):
        save_config(draft_path(self.config), self.cfg)
        record = connection_record(self.config)
        record.update(route='https', wiring='registered-plugin', client_app='chatgpt-web',
                      exposure={'provider': 'cloudflare', 'hostname': 'connector.example.test', 'mode': 'api',
                                'tunnel_id': '12345678-1234-1234-1234-123456789abc'},
                      owned={'fixture': 'retained'})
        save_connection(self.config, record)
        pending_auth(self.config, str(self.socket), resource=self.cfg['resource'], issuer=self.cfg['issuer'])
        class Source:
            async def request(self, method, params):
                if method == 'ping': return {'version': '0.9.3', 'protocol': 22}
                if method == 'agent.list': return {'agents': [await self.agent('pane')]}
                raise AssertionError(method)
            async def agent(self, pane):
                return {'pane_id': 'pane', 'terminal_id': 'terminal-new', 'agent_session': None, 'agent': 'codex'}
        first = await guided_setup(self.config, interactive=False, say=lambda _: None, client_factory=lambda _: Source())
        self.assertEqual(first['stage'], 'source')
        self.assertIn('dot-herdr setup', first['next_action'])
        self.assertNotIn('dot-herdr access', first['next_action'])
        replacement = self.root / 'replacement.sock'
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(replacement)); self.addCleanup(sock.close)
        answers = iter(['1', '1', 'n'])
        async def provider(*args): return {'jwks_url': self.cfg['jwks_url']}
        with patch('dot_herdr.auth.discover_provider', side_effect=provider):
            result = await guided_setup(self.config, str(replacement), prepare=False,
                                        ask=lambda _: next(answers), say=lambda _: None, client_factory=lambda _: Source())
        self.assertEqual(result['stage'], 'wiring')
        cfg = json.loads(draft_path(self.config).read_text())
        self.assertEqual(cfg['socket'], str(replacement))
        self.assertEqual(cfg['subjects'][0]['terminal'], 'terminal-new')
        self.assertFalse(cfg['subjects'][0]['control']); self.assertFalse(cfg['subjects'][0]['content'])
        self.assertEqual(cfg['subjects'][0]['user_subject'], 'replace-with-approved-issuer-subject')
        self.assertEqual(cfg['session_users'], [])
        self.assertFalse(self.config.exists())
        saved = connection_record(self.config)
        for field in ('exposure', 'owned', 'route', 'wiring', 'client_app'):
            self.assertEqual(saved[field], record[field])
        self.assertEqual(json.loads(pending_auth_path(self.config).read_text())['socket'], str(replacement))
        self.assertEqual(json.loads(pending_auth_path(self.config).read_text())['issuer'], self.cfg['issuer'])

    async def test_live_unsupported_source_is_overall_failure(self):
        self.cfg['subjects'][0]['user_subject'] = 'approved-user'
        save_config(self.config, self.cfg)
        record = connection_record(self.config)
        record.update(route='https', wiring='registered-plugin', endpoint=self.cfg['resource'])
        save_connection(self.config, record)
        class Source:
            async def request(self, *args): return {'version': '0.9.2', 'protocol': 21}
        with patch('dot_herdr.status.runtime_observation', return_value={'state': 'running'}), \
             patch('dot_herdr.status.port_in_use', return_value=False), \
             patch('dot_herdr.service.service_status', return_value={'state': 'active', 'installed': True}), \
             patch('dot_herdr.login.public_metadata_status', return_value=('reachable (HTTP 200)', True)):
            report = await status(self.config, live=True, client_factory=lambda _: Source())
        self.assertEqual(report['observations']['source']['state'], 'unsupported')
        self.assertEqual(report['overall']['verdict'], 'the Herdr version/protocol is unsupported')
        self.assertEqual(report['overall']['next_action'], report['observations']['source']['next_action'])
        self.assertIn('0.9.3', render(report))
        self.assertEqual(json.loads(json.dumps(report))['overall'], report['overall'])


class UpdateReleaseFixes(unittest.TestCase):
    def test_cli_failed_pip_retains_current_installation_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); prefix = root / 'owned'; bin_dir = root / 'bin'; source = root / 'fixture.whl'
            with zipfile.ZipFile(source, 'w') as wheel:
                wheel.writestr('dot_herdr.data/data/share/dot-herdr/requirements.lock', 'mcp==2.3.0\n')
            def build(path):
                (path / 'bin').mkdir()
                (path / 'bin/python').write_text('fixture')
                entry = path / 'bin/dot-herdr'; entry.write_text('fixture'); entry.chmod(0o700)
            def execute(args, **kwargs):
                output = {'demo': 'passed'} if args[-1] == 'demo' else {'checks': [{'status': 'pass'}]}
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(output), stderr='')
            with patch.object(installation.venv.EnvBuilder, 'create', side_effect=build), \
                 patch.object(installation.subprocess, 'run', side_effect=execute):
                initial = installation.stage(source, prefix, bin_dir)
            installation.activate(initial)
            error = io.StringIO()
            failure = subprocess.CalledProcessError(1, ['pip'], output='', stderr='token=private-value download failed')
            with patch.object(installation.venv.EnvBuilder, 'create', side_effect=build), \
                 patch.object(installation.subprocess, 'run', side_effect=failure), \
                 patch('dot_herdr.access.service_adapter', return_value=None), \
                 patch('sys.argv', ['dot-herdr', 'update', '--source', str(source), '--prefix', str(prefix), '--config', str(root / 'config.json')]), \
                 contextlib.redirect_stderr(error):
                with self.assertRaises(SystemExit) as rejected:
                    cli.main()
            self.assertEqual(rejected.exception.code, 2)
            self.assertIn('pip', error.getvalue())
            self.assertIn('current installation retained', error.getvalue())
            self.assertNotIn('private-value', error.getvalue())
            self.assertEqual(os.readlink(prefix / 'venv'), initial['release'])
            self.assertEqual(installation.inventory(prefix)['current'], initial['release'])
            self.assertEqual(list((prefix / 'releases').iterdir()), [Path(initial['release'])])
