"""OAuth handoff preserves grants and delegates secrets to the supported client."""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.connections import LOCAL_URL, NAME
from dot_herdr.core import Rejected
from dot_herdr.login import discovery_ready, login_mcp


class LoginTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.cfg = {'store': '/private/state.sqlite', 'socket': '/private/herdr.sock',
                    'issuer': 'https://auth.example.test', 'resource': 'https://connector.example.test/mcp',
                    'public_key': '/private/public.pem', 'subjects': [{'key': 'agent', 'user_subject': 'user',
                        'owner': 'owner', 'pane': 'pane', 'terminal': 'term', 'control': False}], 'session_users': []}
        self.messages = []
    def tearDown(self):
        self.temp.cleanup()
    async def login(self, **kwargs):
        return await login_mcp(self.cfg, codex_home=self.home, say=self.messages.append, **kwargs)
    async def test_pending_settings_missing_cli_and_unready_server_never_start_auth(self):
        with patch('dot_herdr.login.asyncio.create_subprocess_exec') as launch:
            self.cfg['issuer'] = 'https://replace.invalid'
            self.assertEqual((await self.login())['status'], 'pending_settings')
            self.assertFalse((self.home/'config.toml').exists())
            self.cfg['issuer'] = 'https://auth.example.test'
            with patch('dot_herdr.login.shutil.which', return_value=None):
                self.assertEqual((await self.login())['status'], 'missing_codex')
            with patch('dot_herdr.login.shutil.which', return_value='/codex'), patch('dot_herdr.login.discovery_ready', return_value=False):
                self.assertEqual((await self.login())['status'], 'pending_server')
            launch.assert_not_called()
        self.assertIn(self.cfg['resource'], (self.home/'config.toml').read_text())
        self.assertNotIn('authenticated', '\n'.join(self.messages))
    async def test_client_receives_correct_scopes_and_home_without_credentials_in_argv(self):
        class Child:
            returncode = 0
            async def wait(self): return 0
        with patch('dot_herdr.login.shutil.which', return_value='/codex'), patch('dot_herdr.login.discovery_ready', return_value=True), \
             patch('dot_herdr.login.asyncio.create_subprocess_exec', return_value=Child()) as launch:
            self.assertEqual((await self.login())['status'], 'authenticated')
            self.assertEqual(launch.call_args.args, ('/codex', 'mcp', 'login', NAME, '--scopes', 'herdr:observe'))
            self.assertEqual(launch.call_args.kwargs['env']['CODEX_HOME'], str(self.home))
            self.cfg['subjects'][0]['control'] = True
            await self.login(browser=False)
            self.assertEqual(launch.call_args.args[-3:], ('--scopes', 'herdr:observe,herdr:control', '--no-browser'))
            self.cfg['subjects'][0]['control'] = False
            self.cfg['session_users'] = ['user']
            await self.login()
            self.assertIn('herdr:observe,herdr:control', launch.call_args.args)
        self.assertNotIn('user_subject', (self.home/'config.toml').read_text())
    async def test_repeat_login_uses_saved_https_endpoint_and_retains_settings(self):
        from dot_herdr.connections import register_mcp
        register_mcp(self.home, self.cfg['resource'], resource=self.cfg['resource'])
        before=(self.home/'config.toml').read_bytes()
        class Child:
            returncode=0
            async def wait(self):return 0
        with patch('dot_herdr.login.shutil.which',return_value='/codex'), patch('dot_herdr.login.discovery_ready',return_value=True) as ready, \
             patch('dot_herdr.login.asyncio.create_subprocess_exec',return_value=Child()):
            self.assertEqual((await self.login())['status'],'authenticated')
        self.assertEqual(ready.call_args.args[1],self.cfg['resource'])
        self.assertEqual((self.home/'config.toml').read_bytes(),before)
    async def test_endpoint_conflict_and_relative_home_do_not_launch_client(self):
        with patch('dot_herdr.login.asyncio.create_subprocess_exec') as launch:
            with self.assertRaisesRegex(Rejected, 'endpoint_must'): await self.login(endpoint='https://unrelated.example.test/mcp')
            with patch('dot_herdr.login.shutil.which', return_value='/codex'):
                with self.assertRaisesRegex(Rejected, 'absolute_codex_home'):
                    await login_mcp(self.cfg, codex_home='relative')
                (self.home/'config.toml').write_text('[mcp_servers."'+NAME+'"]\nurl="https://other.example.test/mcp"\n')
                before = (self.home/'config.toml').read_bytes()
                with self.assertRaisesRegex(Rejected, 'existing_mcp'): await self.login(endpoint=LOCAL_URL)
                self.assertEqual((self.home/'config.toml').read_bytes(), before)
            launch.assert_not_called()
    async def test_failed_or_timed_out_client_does_not_claim_success_or_leak_errors(self):
        class Child:
            returncode = None
            terminated = False
            async def wait(self):
                if self.returncode is None: await asyncio.Event().wait()
                return self.returncode
            def terminate(self): self.terminated = True; self.returncode = -15
        child = Child()
        with patch('dot_herdr.login.shutil.which', return_value='/codex'), patch('dot_herdr.login.discovery_ready', return_value=True):
            with patch('dot_herdr.login.asyncio.create_subprocess_exec', side_effect=OSError('secret-fixture')):
                self.assertEqual((await self.login())['status'], 'failed')
            with patch('dot_herdr.login.asyncio.create_subprocess_exec', return_value=child):
                self.assertEqual((await self.login(timeout=.01))['status'], 'timed_out')
            self.assertTrue(child.terminated)
        self.assertNotIn('secret-fixture', '\n'.join(self.messages))
    async def test_cancellation_terminates_login_child(self):
        class Child:
            returncode = None
            async def wait(self):
                if self.returncode is None: await asyncio.Event().wait()
                return self.returncode
            def terminate(self): self.returncode = -15
        child = Child()
        with patch('dot_herdr.login.shutil.which', return_value='/codex'), patch('dot_herdr.login.discovery_ready', return_value=True), \
             patch('dot_herdr.login.asyncio.create_subprocess_exec', return_value=child):
            task = asyncio.create_task(self.login())
            await asyncio.sleep(.02)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
        self.assertEqual(child.returncode, -15)
    def test_public_discovery_requires_exact_resource_issuer_and_bounded_response(self):
        class Response:
            def __init__(self, raw): self.raw = raw
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return self.raw[:size]
        valid = {'resource': self.cfg['resource'], 'authorization_servers': [self.cfg['issuer']]}
        with patch('dot_herdr.login.build_opener') as opener:
            opener.return_value.open.return_value = Response(json.dumps(valid).encode())
            self.assertTrue(discovery_ready(self.cfg, LOCAL_URL))
            self.assertEqual(opener.return_value.open.call_args.args[0], 'http://127.0.0.1:8000/.well-known/oauth-protected-resource/mcp')
            for data in ({**valid, 'resource': LOCAL_URL}, {**valid, 'authorization_servers': []}, [], None):
                opener.return_value.open.return_value = Response(json.dumps(data).encode())
                self.assertFalse(discovery_ready(self.cfg, LOCAL_URL))
            opener.return_value.open.return_value = Response(b' ' * 65537)
            self.assertFalse(discovery_ready(self.cfg, LOCAL_URL))
    async def test_real_child_exit_and_timeout_preserve_local_config(self):
        executable = self.home/'codex'
        executable.write_text('#!'+sys.executable+'\nimport sys\nsys.exit(7)\n')
        executable.chmod(0o700)
        with patch('dot_herdr.login.shutil.which', return_value=str(executable)), patch('dot_herdr.login.discovery_ready', return_value=True):
            self.assertEqual((await self.login())['status'], 'failed')
            before = (self.home/'config.toml').read_bytes()
            executable.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(30)\n')
            self.assertEqual((await self.login(timeout=.05))['status'], 'timed_out')
            self.assertEqual((self.home/'config.toml').read_bytes(), before)


class CLIHandoffTests(unittest.TestCase):
    def test_connect_prepares_one_route_without_treating_local_files_as_login(self):
        from dot_herdr.cli import main
        cfg={'resource':'https://connector.example.test/mcp'}
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'config.json'
            for options in ([],['--no-login'],['--no-open'],['--no-register']):
                with patch.object(sys,'argv',['dot-herdr','connect','--config',str(path),*options]),patch('dot_herdr.cli.load_config',return_value=cfg),patch('dot_herdr.connections.prepare_connections',return_value={'registration':{'status':'pending_registered_server'}}),patch('dot_herdr.login.login_mcp') as login:
                    main();login.assert_not_called()
    def test_explicit_login_reports_pending_as_nonzero_and_no_open_uses_manual_callback(self):
        from dot_herdr.cli import main
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'config.json'
            for status in ('authenticated', 'pending_server'):
                with patch.object(sys, 'argv', ['dot-herdr', 'login', '--config', str(path), '--no-open']), patch('dot_herdr.cli.load_config', return_value={}), \
                     patch('dot_herdr.login.login_mcp', return_value={'status':status}) as login:
                    if status == 'authenticated': main()
                    else:
                        with self.assertRaises(SystemExit) as result: main()
                        self.assertEqual(result.exception.code, 2)
                    self.assertFalse(login.call_args.kwargs['browser'])
