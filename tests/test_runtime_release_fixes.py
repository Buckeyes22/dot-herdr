"""Offline regressions for the final runtime release review."""
import asyncio
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import jwt
from dot_herdr import auth, cli, runtime, signin
from dot_herdr.connections import connection_record, save_connection
from dot_herdr.core import Rejected
from dot_herdr.endpoint import principal_key


class VerifyCallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_runtime_verified_scopes_fsync_leaves_heartbeat_responsive(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / 'config.json'
            issuer = 'https://herdr.example'
            resource = issuer + '/mcp'
            service = signin._Service(signin.signin_root(config), issuer, resource, None, time.time, None)
            with signin._db(service.root) as db:
                response = service.issue(db, {'client_id': 'offline-client', 'scope': 'herdr:observe'}, time.time())
            signed = json.loads(response.body)['access_token']
            keys = json.loads((service.root / 'keys.json').read_text())
            private = (service.root / (keys['current']['kid'] + '.pem')).read_bytes()
            from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
            public = load_pem_private_key(private, None).public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
            record = connection_record(config)
            record['identity'] = principal_key(issuer, service.subject)
            save_connection(config, record)
            captured = []
            def factory(cfg, **kwargs):
                verifier = auth.JWTVerifier(issuer, resource, public, **kwargs)
                captured.append(verifier)
                return verifier
            cfg = {'issuer': issuer, 'resource': resource, 'subjects': [], 'session_users': ['owner']}
            with patch('dot_herdr.runtime.placeholders', return_value=False), \
                 patch('dot_herdr.auth.verifier_from_config', side_effect=factory), \
                 patch('dot_herdr.runtime.tunnel_provider', side_effect=Rejected('offline_capture')):
                with self.assertRaisesRegex(Rejected, 'offline_capture'):
                    await runtime.run(config, cfg=cfg)
            loop_thread = threading.get_ident()
            writer_threads = []
            real_fsync = os.fsync
            def delayed_fsync(fd):
                writer_threads.append(threading.get_ident())
                time.sleep(.2)
                real_fsync(fd)
            async def heartbeat():
                start = time.monotonic()
                await asyncio.sleep(.01)
                return time.monotonic() - start
            with patch('dot_herdr.connections.os.fsync', side_effect=delayed_fsync):
                elapsed, verified = await asyncio.gather(heartbeat(), captured[0].verify_token(signed))
            self.assertIsNotNone(verified)
            self.assertEqual(connection_record(config)['verified_client_scopes']['offline-client']['scopes'], ['herdr:observe'])
            self.assertTrue(writer_threads)
            self.assertNotIn(loop_thread, writer_threads)
            self.assertLess(elapsed, .15)


class TunnelExitTests(unittest.TestCase):
    def test_supervised_cloudflared_exits_use_restartable_cli_status(self):
        class HTTP:
            started = True
            should_exit = False
            async def serve(self):
                while not self.should_exit:
                    await asyncio.sleep(.001)
        async def idle(*args):
            await asyncio.Event().wait()
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / 'config.json'
            config.write_text('{}')
            config.chmod(0o600)
            for code in (0, 7):
                with self.subTest(child_exit=code):
                    child = AsyncMock()
                    child.returncode = code
                    child.wait.return_value = code
                    provider = runtime.TunnelProvider('cloudflare', 'cloudflared', lambda: (['offline'], {}),
                        'cloudflared_runtime_launch_failed', 'cloudflared_runtime_stopped',
                        'cloudflared_runtime_failed_check_status', 'cloudflared_runtime_cleanup_timeout')
                    async def run(*args, **kwargs):
                        await runtime.supervise(config, {}, None, None, None, HTTP(), provider=provider)
                    with patch.object(sys, 'argv', ['dot-herdr', 'run', '--config', str(config)]), \
                         patch('dot_herdr.cli.load_config', return_value={}), \
                         patch('dot_herdr.cli.placeholders', return_value=False), \
                         patch('dot_herdr.auth.verifier_from_config'), \
                         patch('dot_herdr.runtime.run', side_effect=run), \
                         patch('dot_herdr.herdr.watch', idle), \
                         patch('dot_herdr.webhooks.deliver_one', idle), \
                         patch('asyncio.create_subprocess_exec', AsyncMock(return_value=child)):
                        with self.assertRaises(SystemExit) as exit:
                            cli.main()
                    self.assertEqual(exit.exception.code, 1)

    def test_configuration_rejection_keeps_cli_status_two(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(sys, 'argv', ['dot-herdr', 'run', '--config', str(Path(folder) / 'missing.json')]):
                with self.assertRaises(SystemExit) as exit:
                    cli.main()
            self.assertEqual(exit.exception.code, 2)


class ParentLifetimeTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == 'Linux', 'Linux parent-death signal')
    def test_cloudflared_stops_when_foreground_parent_is_sigkilled(self):
        script = '''
import asyncio, os, sys
from dot_herdr.runtime import TunnelProvider, launch_tunnel
async def main():
    provider = TunnelProvider('cloudflare', 'cloudflared',
        lambda: ([sys.executable, '-c', 'import time; time.sleep(60)'], dict(os.environ)),
        'launch_failed', 'stopped', 'failed', 'cleanup_timeout')
    child = await launch_tunnel(provider)
    print(child.pid, flush=True)
    await asyncio.Event().wait()
asyncio.run(main())
'''
        parent = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        child_pid = None
        try:
            import select
            self.assertTrue(select.select([parent.stdout], [], [], 10)[0], 'parent did not launch child')
            child_pid = int(parent.stdout.readline())
            self.assertIsNotNone(runtime.process_start(child_pid))
            parent.kill()
            parent.wait(timeout=5)
            deadline = time.monotonic() + 2
            while runtime.process_start(child_pid) is not None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertIsNone(runtime.process_start(child_pid), 'owned cloudflared survived SIGKILL of its parent')
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)
            if child_pid is not None and runtime.process_start(child_pid) is not None:
                os.kill(child_pid, signal.SIGKILL)
            parent.stdout.close()
            parent.stderr.close()


class ParentLifetimePlatformTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_platforms_and_providers_keep_launch_contract(self):
        for system, name in (('Darwin', 'cloudflare'), ('Linux', 'openai')):
            with self.subTest(system=system, provider=name):
                provider = runtime.TunnelProvider(name, name, lambda: (['offline'], {}),
                    'launch_failed', 'stopped', 'failed', 'cleanup_timeout')
                spawn = AsyncMock()
                with patch('dot_herdr.runtime.platform.system', return_value=system), \
                     patch('asyncio.create_subprocess_exec', spawn):
                    await runtime.launch_tunnel(provider)
                self.assertEqual(spawn.call_args.args[0], 'offline')
