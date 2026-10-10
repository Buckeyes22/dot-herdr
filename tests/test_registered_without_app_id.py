"""Registered Settings plugins complete local setup without a technical mapping ID."""
import asyncio
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.connections import NAME, connection_record, migrate_connection, prepare_connections, save_connection
from dot_herdr.core import Rejected
from dot_herdr.endpoint import principal_key
from dot_herdr.onboarding import draft_path, guided_setup, save_config
from dot_herdr.setup import load_config
from dot_herdr.status import status


class RegisteredWithoutAppIdTests(unittest.IsolatedAsyncioTestCase):
    async def test_authenticated_candidate_is_approved_and_setup_reaches_connection_check(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            config = root / 'config.json'
            source_socket = root / 'source.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(source_socket))
            try:
                issuer = 'https://auth.example.test'
                resource = 'https://connector.example.test/mcp'
                subject = 'verified-user'
                principal = principal_key(issuer, subject)
                cfg = {
                    'store': str(root / 'store.sqlite'), 'socket': str(source_socket),
                    'issuer': issuer, 'resource': resource, 'jwks_url': issuer + '/jwks',
                    'subjects': [{'key': 'agent', 'user_subject': 'replace-with-approved-issuer-subject',
                                  'owner': 'operator', 'pane': 'pane', 'terminal': 'terminal',
                                  'native': None, 'content': False, 'control': True}],
                    'session_users': [],
                }
                save_config(draft_path(config), cfg)
                record = connection_record(config)
                record.update(route='https', wiring='registered-plugin',app_id='asdk_app_saved_synthetic',identity='prior-approved-profile',last_authentication=1)
                save_connection(config, record)

                class Source:
                    async def request(self, method, params):
                        self_test.assertEqual(method, 'ping')
                        return {'version': '0.9.3', 'protocol': 22}
                    async def agent(self, pane):
                        return {'pane_id': 'pane', 'terminal_id': 'terminal',
                                'agent_session': None, 'agent': 'codex'}

                class Pairing:
                    def __init__(self, actual_issuer, ttl):
                        self_test.assertEqual(actual_issuer, issuer)
                        self.deadline = 10**20
                        self.clock = lambda: 0
                    def candidates(self):
                        return [{'subject': subject, 'principal': principal,'client_id':'synthetic-client','scopes':['herdr:observe'],'expires_at':__import__('time').time()+120}]
                    def observe(self, token):
                        raise Rejected('pairing_identity_denied')
                    def confirm(self, selected):
                        self_test.assertEqual(selected, principal)
                        return {'issuer': issuer, 'subject': subject, 'principal': principal,'client_id':'synthetic-client','scopes':['herdr:observe'],'expires_at':__import__('time').time()+120}
                    def close(self):
                        pass

                class HTTP:
                    def __init__(self, config):
                        self.started = False
                        self.should_exit = False
                    async def serve(self):
                        self.started = True
                        while not self.should_exit:
                            await asyncio.sleep(.01)

                async def idle(*args, **kwargs):
                    await asyncio.Event().wait()
                async def check(*args, **kwargs):
                    return {'status': 'pending', 'phase': 'destination_confirmation'}
                class RejectingVerifier:
                    async def verify_token(self, token):
                        return None

                self_test = self
                prompts = []
                messages = []
                def ask(prompt):
                    prompts.append(prompt)
                    if 'Approve account' in prompt:
                        return 'y'
                    if 'Keep the connector running in the background' in prompt:
                        return 'n'
                    self.fail('Unexpected prompt: ' + prompt)
                with patch('dot_herdr.auth.discover_provider', return_value={'jwks_url': cfg['jwks_url']}), \
                     patch('dot_herdr.status.port_in_use', return_value=False), \
                     patch('dot_herdr.auth.verifier_from_config', return_value=RejectingVerifier()), \
                     patch('dot_herdr.endpoint.PairingSession', Pairing), \
                     patch('dot_herdr.endpoint.build_pairing') as build_pairing, \
                     patch('uvicorn.Server', HTTP), \
                     patch('dot_herdr.status.runtime_observation', side_effect=[{'state':'stopped'}, {'state':'running'}]), \
                     patch('dot_herdr.runtime.run', side_effect=idle), \
                     patch('dot_herdr.connection_check.check_connection', side_effect=check), \
                     patch('pathlib.Path.home', return_value=root):
                    result = await guided_setup(config, ask=ask, say=messages.append,
                                                client_factory=lambda _: Source(), launch=True)
                build_pairing.return_value.streamable_http_app.assert_called_once()
                self.assertIn('Your Herdr plugin is already added in ChatGPT in a web browser (chatgpt.com). In that ChatGPT conversation, ask the Herdr plugin to run get_profile.', ' '.join(messages))
                self.assertIn('do not type anything in this terminal until it does.', ' '.join(messages))
                self.assertIsNone(await build_pairing.call_args.args[0].verify_token('private-token'))
                self.assertIn('Authenticated pairing request rejected: token_verification_failed.', messages)
                with self.assertRaisesRegex(Rejected, 'pairing_identity_denied'):
                    build_pairing.call_args.args[3].observe('private-token')
                self.assertIn('Authenticated pairing request rejected: pairing_identity_denied.', messages)
                self.assertFalse(any('private-token' in message for message in messages))
                self.assertEqual(result['phase'], 'destination_confirmation')
                self.assertEqual(load_config(config)['subjects'][0]['user_subject'], subject)
                self.assertEqual(len([prompt for prompt in prompts if prompt.startswith('Approve account ')]), 1)
                self.assertEqual(sum('ChatGPT Settings, add ' in message for message in messages), 0)
                self.assertFalse(any('technical ID' in value or 'plugin ID' in value for value in prompts + messages))
                self.assertEqual(connection_record(config)['wiring'], 'registered-plugin')
                self.assertEqual(connection_record(config)['app_id'],'asdk_app_saved_synthetic')
                self.assertEqual(connection_record(config)['local_package'],
                                 {'status':'not_prepared','reason':'plugin_created_in_chatgpt_settings'})
                self.assertFalse((root/'.codex').exists());self.assertFalse((root/'.agents').exists())
                self.assertFalse(any('codex://plugins/' in message for message in messages))
            finally:
                listener.close()

    async def test_settings_plugin_preparation_status_and_migration_need_no_id(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            config = root / 'config.json'
            resource = 'https://connector.example.test/mcp'
            cfg = {'store':str(root/'store.sqlite'), 'socket':str(root/'source.sock'),
                   'issuer':'https://auth.example.test', 'resource':resource,
                   'public_key':str(root/'key.pem'), 'subjects':[], 'session_users':['user']}
            save_config(config, cfg)
            result = prepare_connections(cfg, home=root, codex_home=root/'.codex',
                                         wiring='registered-plugin', launch=False, say=lambda _: None)
            self.assertEqual(result['registration']['status'], 'settings_plugin')
            self.assertEqual(result['local_package'], {'status':'not_prepared',
                                                       'reason':'plugin_created_in_chatgpt_settings'})
            self.assertFalse((root/'.codex').exists())
            record = connection_record(config)
            record.update(route='https', wiring='registered-plugin', endpoint=resource,
                          local_package=result['local_package'], owned={})
            save_connection(config, record)
            with patch('dot_herdr.status.port_in_use', return_value=False):
                observations = (await status(config))['observations']
            self.assertEqual(observations['wiring']['state'], 'settings_plugin')
            self.assertEqual(observations['route']['local_preparation'], 'not_prepared')
            self.assertEqual(observations['route']['local_package_reason'],
                             'plugin_created_in_chatgpt_settings')
            record = connection_record(config)
            record.update(route='https', wiring='standalone', endpoint=resource,app_id='asdk_app_saved_synthetic')
            save_connection(config, record)
            migrated = migrate_connection(config, 'https', 'registered-plugin', home=root,
                                          codex_home=root/'.codex', launch=False, say=lambda _: None)
            self.assertEqual(migrated['registration']['status'], 'settings_plugin')
            self.assertNotIn('app_id', connection_record(config))
            self.assertFalse((root/'.codex/plugins').exists())

    async def test_migrating_from_owned_local_plugin_to_settings_plugin_removes_local_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            config = root/'config.json'
            resource = 'https://connector.example.test/mcp'
            cfg = {'store':str(root/'store.sqlite'), 'socket':str(root/'source.sock'),
                   'issuer':'https://auth.example.test', 'resource':resource,
                   'public_key':str(root/'key.pem'), 'subjects':[], 'session_users':['user']}
            save_config(config, cfg)
            previous = prepare_connections(cfg, home=root, codex_home=root/'.codex',
                                           wiring='plugin-http', launch=False, say=lambda _: None)
            plugin = root/'.codex/plugins'/NAME
            self.assertTrue((plugin/'mcp.json').exists())
            record = connection_record(config)
            record.update(route='https', wiring='plugin-http', endpoint=resource,
                          owned=previous['owned'])
            save_connection(config, record)
            result = migrate_connection(config, 'https', 'registered-plugin', home=root,
                                        codex_home=root/'.codex', launch=False,
                                        say=lambda _: None)
            self.assertEqual(result['registration']['status'], 'settings_plugin')
            self.assertFalse((plugin/'mcp.json').exists())
            self.assertFalse((plugin/'plugin.json').exists())
            self.assertEqual(connection_record(config)['owned'], {})
