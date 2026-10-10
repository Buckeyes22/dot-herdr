"""Only synthetic children and temporary private files; no Cloudflare access."""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from dot_herdr import cloudflare, endpoint, onboarding, runtime, signin
from dot_herdr.core import Rejected, Store
from tests.test_runtime import HTTP
from tests.test_cloudflare import FakeCloudflare

ISSUER = 'https://herdr.example'
RESOURCE = ISSUER + '/mcp'


class SupervisionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config.json'
        self.config.write_text('{}')
        self.config.chmod(0o600)
        self.store = Store(self.root / 'state.sqlite')
        self.addCleanup(self.store.close)
        self.binary = self.root / 'fake-cloudflared'
        self.proof = self.root / 'child.json'
        self.home = self.root / 'fake-home'
        env = patch.dict(os.environ, {'HOME': str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        which = patch('dot_herdr.cloudflare.shutil.which', return_value=str(self.binary))
        which.start()
        self.addCleanup(which.stop)
        self.journal = cloudflare.Journal(self.config)
        self.script()
        await self.expose('api')

    async def expose(self, mode):
        self.journal.remove()
        if mode == 'api':
            self.exposure = await cloudflare.expose_api(self.config, 'herdr.example', 8000,
                'offline-api', api=FakeCloudflare().api(), say=lambda _: None)
        else:
            self.exposure = cloudflare.expose_login(self.config, 'herdr.example', 8000,
                cloudflared=str(self.binary), home=self.home, say=lambda _: None)

    async def idle(self, *args):
        await asyncio.Event().wait()

    def script(self, code=None):
        self.binary.write_text('#!' + sys.executable + '\n' +
            'import json, os, sys, time\n' +
            'from pathlib import Path\n' +
            'args = sys.argv[1:]\n' +
            'directory = Path(os.environ["HOME"]) / ".cloudflared"\n' +
            'tid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"\n' +
            'if "run" not in args:\n' +
            '    directory.mkdir(parents=True, exist_ok=True)\n' +
            '    if "login" in args: (directory / "cert.pem").write_text("offline-cert")\n' +
            '    if "create" in args:\n' +
            '        (directory / (tid + ".json")).write_text("{}")\n' +
            '        print("Created tunnel " + tid)\n' +
            '    if args == ["tunnel", "list", "-o", "json"]:\n' +
            '        print(json.dumps([{"id": tid, "name": ' + repr('dot-herdr-' + cloudflare.install_id(self.config)) + '}]))\n' +
            '    if args[:3] == ["tunnel", "route", "dns"]:\n' +
            '        assert args[3:] == [tid, "herdr.example"]\n' +
            '    sys.exit(0)\n' +
            'proof = Path(' + repr(str(self.proof)) + ')\n' +
            'pending = proof.with_suffix(".pending")\n' +
            'pending.write_text(json.dumps({"pid": os.getpid(), "args": sys.argv[1:], "ambient_token": "TUNNEL_TOKEN" in os.environ}))\n' +
            'pending.replace(proof)\n' +
            ('sys.exit(' + str(code) + ')\n' if code is not None else 'while True: time.sleep(.01)\n'))
        self.binary.chmod(0o700)

    async def wait_until(self, predicate):
        async with asyncio.timeout(15):
            while not predicate():
                await asyncio.sleep(.05)

    async def started(self):
        await self.wait_until(self.proof.exists)
        return json.loads(self.proof.read_text())

    def provider(self, mode):
        self.assertEqual(self.exposure['mode'], mode)
        return runtime.tunnel_provider(self.config, {}, exposure=self.exposure)

    def assert_reaped(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    async def test_both_modes_launch_after_http_ready_and_reap_clean_stop(self):
        for mode in ('api', 'login'):
            with self.subTest(mode=mode):
                self.proof.unlink(missing_ok=True)
                self.script()
                await self.expose(mode)
                provider = self.provider(mode)
                http = HTTP()
                gate = asyncio.Event()
                serving = asyncio.Event()
                async def serve():
                    serving.set()
                    await gate.wait()
                    await HTTP.serve(http)
                http.serve = serve
                with patch('dot_herdr.herdr.watch', self.idle), patch('dot_herdr.webhooks.deliver_one', self.idle), \
                     patch.dict(os.environ, {'TUNNEL_TOKEN': 'offline-ambient'}):
                    task = asyncio.create_task(runtime.supervise(self.config, {}, self.store, None, None, http, provider=provider))
                    try:
                        await asyncio.wait_for(serving.wait(), 15)
                        self.assertFalse(self.proof.exists())
                        self.assertEqual(json.loads(runtime.status_path(self.config).read_text())['cloudflared'], 'starting')
                        gate.set()
                        proof = await self.started()
                        self.assertFalse(proof['ambient_token'])
                        self.assertIn('--token-file' if mode == 'api' else '--config', proof['args'])
                        await self.wait_until(lambda: json.loads(runtime.status_path(self.config).read_text())['cloudflared'] == 'running')
                        http.should_exit = True
                        await asyncio.wait_for(task, 30)
                    finally:
                        if not task.done():
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                self.assert_reaped(proof['pid'])
                record = json.loads(runtime.status_path(self.config).read_text())
                self.assertEqual((record['state'], record['cloudflared'], record['tunnel']), ('stopped', 'stopped', 'disabled'))

    async def test_every_child_exit_is_fatal_and_reaped(self):
        for mode in ('api', 'login'):
            for code in (0, 4):
                with self.subTest(mode=mode, code=code):
                    self.proof.unlink(missing_ok=True)
                    self.script(code)
                    await self.expose(mode)
                    provider = self.provider(mode)
                    http = HTTP()
                    with patch('dot_herdr.herdr.watch', self.idle), patch('dot_herdr.webhooks.deliver_one', self.idle):
                        with self.assertRaisesRegex(Rejected, provider.failed if code else provider.stopped):
                            await asyncio.wait_for(runtime.supervise(self.config, {}, self.store, None, None, http, provider=provider), 30)
                    self.assert_reaped(json.loads(self.proof.read_text())['pid'])
                    self.assertTrue(http.should_exit)
                    record = json.loads(runtime.status_path(self.config).read_text())
                    self.assertEqual(record['state'], 'failed')
                    self.assertEqual(record['error'], provider.failed if code else provider.stopped)

    async def test_launch_failure_redacted_and_shutdown(self):
        provider = self.provider('api')
        http = HTTP()
        with patch('dot_herdr.herdr.watch', self.idle), patch('dot_herdr.webhooks.deliver_one', self.idle), \
             patch('asyncio.create_subprocess_exec', side_effect=OSError('offline launch failure')):
            with self.assertRaisesRegex(Rejected, '^cloudflared_runtime_launch_failed$'):
                await asyncio.wait_for(runtime.supervise(self.config, {}, self.store, None, None, http, provider=provider), 30)
        self.assertTrue(http.should_exit)

    async def test_cancelled_runtime_reaps_child(self):
        self.script()
        with patch('dot_herdr.herdr.watch', self.idle), patch('dot_herdr.webhooks.deliver_one', self.idle):
            task = asyncio.create_task(runtime.supervise(self.config, {}, self.store, None, None, HTTP(), provider=self.provider('api')))
            try:
                proof = await self.started()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 30)
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        self.assert_reaped(proof['pid'])

    async def test_cleanup_escalates_terminate_to_kill(self):
        child = Mock(returncode=None)
        child.wait = AsyncMock(side_effect=[asyncio.TimeoutError(), 0])
        await runtime.reap_tunnel(child, self.provider('api'))
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.await_count, 2)

    async def test_provider_path_priority_fallback_missing_and_conflict(self):
        with patch('dot_herdr.runtime.shutil.which', return_value=str(self.binary)) as which:
            self.assertEqual(self.provider('api').command()[0][0], str(self.binary))
            which.assert_not_called()
            self.journal.remove()
            with self.assertRaisesRegex(Rejected, '^invalid_cloudflare_exposure$'):
                self.provider('api').command()
        with patch('dot_herdr.runtime.shutil.which', return_value=None):
            with self.assertRaisesRegex(Rejected, '^cloudflared_not_found_install_it_see_docs_reachability$'):
                self.provider('api')
        with self.assertRaisesRegex(Rejected, '^openai_tunnel_and_cloudflare_exposure_conflict$'):
            runtime.tunnel_provider(self.config, {}, tunnel=True, exposure=self.exposure)

    async def test_run_selects_exposure_without_tunnel_flag(self):
        self.script()
        cfg = {'subjects': [], 'session_users': ['owner'], 'issuer': ISSUER, 'resource': RESOURCE,
               'jwks_url': ISSUER + '/.well-known/jwks.json', 'socket': '/offline/socket', 'store': str(self.root / 'run.sqlite')}
        with patch('dot_herdr.runtime.placeholders', return_value=False), patch('dot_herdr.runtime.load_config', return_value=cfg), \
             patch('dot_herdr.connections.exposure_for', return_value=self.exposure), patch('dot_herdr.runtime.supervise', new_callable=AsyncMock) as supervisor:
            await runtime.run(self.config, cfg=cfg)
            self.assertEqual(supervisor.call_args.kwargs['provider'].name, 'cloudflare')
            with self.assertRaisesRegex(Rejected, 'openai_tunnel_and_cloudflare_exposure_conflict'):
                await runtime.run(self.config, cfg=cfg, tunnel=True)

    async def test_run_missing_recorded_binary_uses_path_or_rejects_missing(self):
        fallback = self.root / 'path-cloudflared'
        fallback.write_bytes(self.binary.read_bytes())
        fallback.chmod(0o700)
        self.binary.unlink()
        cfg = {'subjects': [], 'session_users': ['owner'], 'issuer': ISSUER, 'resource': RESOURCE,
               'jwks_url': signin.jwks_url(ISSUER), 'socket': '/offline/socket',
               'store': str(self.root / 'run.sqlite')}
        for replacement in (str(fallback), None):
            with self.subTest(path_replacement=replacement), \
                 patch('dot_herdr.runtime.placeholders', return_value=False), \
                 patch('dot_herdr.runtime.load_config', return_value=cfg), \
                 patch('dot_herdr.connections.exposure_for', return_value=self.exposure), \
                 patch('dot_herdr.runtime.shutil.which', return_value=replacement) as which, \
                 patch('dot_herdr.runtime.supervise', new_callable=AsyncMock) as supervisor:
                if replacement:
                    await runtime.run(self.config, cfg=cfg)
                    supervisor.assert_awaited_once()
                    args, _ = supervisor.call_args.kwargs['provider'].command()
                    self.assertEqual(args[0], str(fallback))
                else:
                    with self.assertRaisesRegex(Rejected, '^cloudflared_not_found_install_it_see_docs_reachability$'):
                        await runtime.run(self.config, cfg=cfg)
                    supervisor.assert_not_awaited()
                which.assert_called_once_with('cloudflared')

    async def test_pairing_mount_and_reap_in_both_exposure_modes(self):
        signin.set_password(signin.signin_root(self.config), 'offline-owner-credential')
        cfg = {'signin': 'builtin', 'issuer': ISSUER, 'resource': RESOURCE, 'jwks_url': signin.jwks_url(ISSUER), 'subjects': []}
        for mode in ('api', 'login'):
            self.proof.unlink(missing_ok=True)
            self.script()
            await self.expose(mode)
            http = HTTP()
            record = {'route': 'https', 'wiring': 'registered-plugin', 'endpoint': RESOURCE, 'exposure': self.exposure}
            with patch('uvicorn.Server', return_value=http), patch('dot_herdr.status.port_in_use', return_value=False), \
                 patch('dot_herdr.connections.save_connection'), patch('dot_herdr.endpoint.build_pairing', wraps=endpoint.build_pairing) as build:
                task = asyncio.create_task(onboarding._pairing_identity(self.config, cfg, record, say=lambda _: None, timeout=15))
                try:
                    proof = await self.started()
                    self.assertIsNone(await asyncio.wait_for(task, 30))
                    self.assertIn('/login', [r.path for r in build.call_args.kwargs['signin_routes']])
                finally:
                    if not task.done():
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
            self.assert_reaped(proof['pid'])
            self.assertTrue(http.should_exit)

    async def test_pairing_child_failure_is_fatal_and_reaped(self):
        self.script(4)
        cfg = {'issuer': ISSUER, 'resource': RESOURCE, 'jwks_url': signin.jwks_url(ISSUER), 'subjects': []}
        record = {'route': 'https', 'wiring': 'registered-plugin', 'endpoint': RESOURCE, 'exposure': self.exposure}
        with patch('uvicorn.Server', return_value=HTTP()), patch('dot_herdr.status.port_in_use', return_value=False), patch('dot_herdr.connections.save_connection'):
            with self.assertRaisesRegex(Rejected, '^cloudflared_runtime_failed_check_status$'):
                await asyncio.wait_for(onboarding._pairing_identity(self.config, cfg, record, say=lambda _: None, timeout=15), 30)
        self.assert_reaped(json.loads(self.proof.read_text())['pid'])

    async def test_pairing_builtin_without_password_refuses_before_listener(self):
        cfg = {'signin': 'builtin', 'issuer': ISSUER, 'resource': RESOURCE, 'jwks_url': signin.jwks_url(ISSUER)}
        record = {'route': 'https', 'wiring': 'registered-plugin'}
        with patch('dot_herdr.status.port_in_use', return_value=False), patch('uvicorn.Server') as server:
            with self.assertRaisesRegex(Rejected, '^builtin_signin_password_not_set_run_dot_herdr_signin_set_password$'):
                await onboarding._pairing_identity(self.config, cfg, record, say=lambda _: None)
            server.assert_not_called()

    async def test_expose_api_records_path_detection_without_running_binary(self):
        self.journal.remove()
        fake = FakeCloudflare()
        with patch('dot_herdr.cloudflare.shutil.which', return_value=str(self.binary)):
            await cloudflare.expose_api(self.config, 'herdr.example.com', 8000, 'offline-api', api=fake.api())
        self.assertEqual(cloudflare.recorded_cloudflared(self.config), str(self.binary))
        self.assertFalse(self.proof.exists())

    async def test_expose_api_records_absolute_binary_and_idempotent_rerun(self):
        self.journal.remove()
        fake = FakeCloudflare()
        for _ in range(2):
            await cloudflare.expose_api(self.config, 'herdr.example.com', 8000, 'offline-api', api=fake.api())
            self.assertEqual(cloudflare.recorded_cloudflared(self.config), str(self.binary))

    async def test_expose_login_records_binary_and_preserves_command_arguments(self):
        await self.expose('login')
        for _ in range(2):
            exposure = cloudflare.expose_login(self.config, 'herdr.example', 8000,
                cloudflared=str(self.binary), home=self.home, say=lambda _: None)
            self.assertEqual(exposure, self.exposure)
            self.assertEqual(cloudflare.recorded_cloudflared(self.config), str(self.binary))
        args, _ = self.provider('login').command()
        self.assertEqual(args, [str(self.binary), 'tunnel', '--no-autoupdate', '--config',
            str(self.journal.root / 'config.yml'), 'run', self.exposure['tunnel_id']])
