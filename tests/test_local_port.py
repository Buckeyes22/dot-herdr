"""Loopback port selection keeps the configured Host boundary and status probe aligned."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock,MagicMock,patch

import httpx2

from dot_herdr.connections import LOCAL_URL,local_url
from dot_herdr.core import Rejected
from dot_herdr.endpoint import PairingSession,build_pairing
from dot_herdr.onboarding import save_config
from dot_herdr.setup import TEMPLATE,validate_config
from dot_herdr.status import status
from dot_herdr.runtime import run


class LocalPortTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.cfg=copy.deepcopy(TEMPLATE)
        self.cfg.update(store=str(self.root/'store.sqlite'),socket=str(self.root/'absent.sock'),
                        public_key=str(self.root/'public.pem'),issuer='https://issuer.example.test',
                        resource='https://connector.example.test/mcp',subjects=[],session_users=['fixture-user'])
    async def test_default_and_invalid_values(self):
        self.assertEqual(local_url(validate_config(self.cfg)),LOCAL_URL)
        self.assertNotIn('local_port',validate_config(self.cfg))
        for value in (None,True,False,1023,65536,0,-1,'8123',8123.0,[],{}):
            with self.subTest(value=value),self.assertRaisesRegex(Rejected,'invalid_local_port'):
                validate_config({**self.cfg,'local_port':value})
        self.assertEqual(local_url(validate_config({**self.cfg,'local_port':8123})),'http://127.0.0.1:8123/mcp')

    async def test_pairing_metadata_and_exact_host_origin(self):
        class Verifier:
            async def verify_token(self,token):return None
        server=build_pairing(Verifier(),self.cfg['issuer'],self.cfg['resource'],PairingSession(self.cfg['issuer']),local_port=8123)
        self.assertEqual(server.local_port,8123)
        app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8123',trust_env=False) as client:
                good=await client.get('/.well-known/oauth-protected-resource/mcp')
                self.assertEqual(good.status_code,200)
                self.assertEqual(good.json()['resource'],self.cfg['resource'])
                wrong=await client.get('/.well-known/oauth-protected-resource/mcp',headers={'Host':'127.0.0.1:8000'})
                self.assertEqual(wrong.status_code,421)
                bad_origin=await client.post('/mcp',headers={'Origin':'http://127.0.0.1:8000','Content-Type':'application/json'})
                self.assertEqual(bad_origin.status_code,403)

    async def test_status_probes_configured_port(self):
        self.cfg['local_port']=8123
        config=self.root/'config.json';save_config(config,self.cfg)
        with patch('dot_herdr.status.port_in_use',return_value=True) as probe:
            report=await status(config)
        probe.assert_called_once_with(8123)
        self.assertEqual(report['observations']['listener']['state'],'occupied')
        self.assertIn('port 8123',report['observations']['listener']['next_action'])

    async def test_runtime_passes_configured_port_to_endpoint_and_listener(self):
        self.cfg['local_port']=8123
        server=MagicMock();server.streamable_http_app.return_value=MagicMock()
        with patch('dot_herdr.runtime.Store') as store,patch('dot_herdr.herdr.HerdrClient'),\
             patch('dot_herdr.webhooks.PublicTransport'),patch('dot_herdr.auth.verifier_from_config'),\
             patch('dot_herdr.endpoint.build',return_value=server) as build,\
             patch('dot_herdr.runtime.supervise',new_callable=AsyncMock),\
             patch('uvicorn.Config') as listener,patch('uvicorn.Server'):
            await run(self.root/'config.json',cfg=self.cfg)
        self.assertEqual(build.call_args.kwargs['local_port'],8123)
        self.assertEqual(listener.call_args.kwargs['port'],8123)
        store.return_value.close.assert_called_once()
