import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dot_herdr.core import Rejected, Store
from dot_herdr import runtime


class HTTP:
    def __init__(self):
        self.started = False
        self.should_exit = False

    async def serve(self):
        self.started = True
        while not self.should_exit:
            await asyncio.sleep(.001)


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = Path(self.temp.name) / 'config.json'
        self.config.write_text('{}')
        self.config.chmod(0o600)
        self.store = Store(Path(self.temp.name) / 'state.sqlite')

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    async def idle(self, *args):
        await asyncio.Event().wait()

    async def test_worker_failure_stops_http_and_redacts_error(self):
        async def bad(*args):
            await asyncio.sleep(.01)
            raise RuntimeError('callback-secret-must-not-appear')
        http = HTTP()
        with patch('dot_herdr.herdr.watch', bad), patch('dot_herdr.webhooks.deliver_one', self.idle):
            with self.assertRaisesRegex(Rejected, 'runtime_observer_failed'):
                await runtime.supervise(self.config, {}, self.store, None, None, http)
        record = json.loads(runtime.status_path(self.config).read_text())
        self.assertEqual(record['state'], 'failed')
        self.assertEqual(record['workers']['observer'], 'failed')
        self.assertTrue(http.should_exit)
        self.assertNotIn('callback-secret', json.dumps(record))
        self.assertEqual(runtime.status_path(self.config).stat().st_mode & 0o777, 0o600)

    async def test_clean_stop_cancels_worker_and_pending_login(self):
        cleaned = []
        async def worker(*args):
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.append(True)
        http = HTTP()
        with patch('dot_herdr.herdr.watch', worker), patch('dot_herdr.webhooks.deliver_one', self.idle), patch('dot_herdr.login.login_mcp', self.idle):
            task = asyncio.create_task(runtime.supervise(self.config, {}, self.store, None, None, http, login=True))
            await asyncio.sleep(.03)
            http.should_exit = True
            await asyncio.wait_for(task, 2)
        self.assertEqual(cleaned, [True])
        self.assertEqual(json.loads(runtime.status_path(self.config).read_text())['state'], 'stopped')

    async def test_tunnel_failure_is_terminal(self):
        child = AsyncMock()
        child.returncode = 4
        child.wait.return_value = 4
        http = HTTP()
        with patch('dot_herdr.herdr.watch', self.idle), patch('dot_herdr.webhooks.deliver_one', self.idle), patch('asyncio.create_subprocess_exec', AsyncMock(return_value=child)):
            with self.assertRaisesRegex(Rejected, 'tunnel_runtime_failed'):
                await runtime.supervise(self.config, {}, self.store, None, None, http, tunnel_command=(['binary'], {}))
        self.assertTrue(http.should_exit)

    async def test_shutdown_terminates_owned_tunnel(self):
        class Child:
            returncode = None
            terminated = False
            def __init__(self):
                self.exit = asyncio.Event()
            async def wait(self):
                await self.exit.wait()
                return 0
            def terminate(self):
                self.terminated = True
                self.returncode = 0
                self.exit.set()
        child = Child()
        http = HTTP()
        with patch('dot_herdr.herdr.watch', self.idle), patch('dot_herdr.webhooks.deliver_one', self.idle), patch('asyncio.create_subprocess_exec', AsyncMock(return_value=child)):
            task = asyncio.create_task(runtime.supervise(self.config, {}, self.store, None, None, http, tunnel_command=(['binary'], {})))
            await asyncio.sleep(.04)
            http.should_exit = True
            await asyncio.wait_for(task, 2)
        self.assertTrue(child.terminated)

    async def test_runtime_releases_store_on_roster_failure(self):
        cfg = {'subjects': [{'key': 'x', 'user_subject': 'u'}], 'issuer': 'https://auth.test',
               'resource': 'https://resource.test/mcp', 'store': str(Path(self.temp.name) / 'other.sqlite')}
        with patch('dot_herdr.runtime.placeholders', return_value=False), patch('dot_herdr.auth.verifier_from_config', return_value=None), patch.object(Store, 'apply_roster', side_effect=Rejected('bad_roster')):
            with patch('dot_herdr.runtime.load_config',return_value=cfg), self.assertRaisesRegex(Rejected, 'bad_roster'):
                await runtime.run(self.config, cfg=cfg)
        reopened = Store(Path(cfg['store']))
        reopened.close()

    def test_process_start_fences_missing_process(self):
        self.assertIsNotNone(runtime.process_start())
        self.assertIsNone(runtime.process_start(2147483647))

    def test_credential_is_private_bounded_and_restores_environment(self):
        key = Path(self.temp.name) / 'launch.key'
        key.write_text('test-secret\n')
        key.chmod(0o600)
        with patch.dict(os.environ, {}, clear=True), patch('dot_herdr.tunnel.runtime_command', side_effect=lambda *a, **k: ([], {'CONTROL_PLANE_API_KEY': os.environ['CONTROL_PLANE_API_KEY']})):
            _, env = runtime.tunnel_arguments(self.config, {}, key)
            self.assertEqual(env['CONTROL_PLANE_API_KEY'], 'test-secret')
            self.assertNotIn('CONTROL_PLANE_API_KEY', os.environ)
        key.chmod(0o644)
        with self.assertRaisesRegex(Rejected, 'private_service_credential'):
            runtime.credential_environment(key)


if __name__ == '__main__':
    unittest.main()
