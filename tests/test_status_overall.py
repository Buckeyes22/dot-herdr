"""Synthetic status verdicts; no local service or public network is contacted."""
import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from dot_herdr.connections import connection_record, save_connection
from dot_herdr.onboarding import save_config
from dot_herdr.status import render, status
from dot_herdr.login import public_metadata_status


class StatusOverallTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.config=self.root/'config.json'
        self.cfg={'store':str(self.root/'store.sqlite'),'socket':str(self.root/'herdr.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(self.root/'key.pem'),'local_port':8123,'subjects':[{'key':'agent','user_subject':'user','owner':'operator','pane':'pane','terminal':'terminal','native':None,'content':False,'control':False}],'session_users':[]}
        save_config(self.config,self.cfg)
        record=connection_record(self.config);record.update(route='https',wiring='registered-plugin',endpoint=self.cfg['resource']);save_connection(self.config,record)

    async def observed(self, *, runtime='running', installed=False, source=True, live=True, reachability='reachable (HTTP 200)', discovery=True, scopes=None, complete=False):
        class Source:
            async def request(self,*args):
                if not source:raise OSError('synthetic')
                return {'version':'0.9.3','protocol':22}
        record=connection_record(self.config)
        if scopes is not None:record['verified_client_scopes']={'client-1':{'scopes':scopes,'verified_at':time.time()-100,'expires_at':time.time()+1000}}
        if complete:record['check']={'status':'complete','checked_at':time.time()-100,'phases':{'destination_confirmation':'confirmed'}}
        save_connection(self.config,record)
        with patch('dot_herdr.status.runtime_observation',return_value={'state':runtime}),patch('dot_herdr.status.port_in_use',return_value=False),patch('dot_herdr.service.service_status',return_value={'state':'inactive','installed':installed}),patch('dot_herdr.login.public_metadata_status',return_value=(reachability,discovery)):
            return await status(self.config,live=live,client_factory=lambda _:Source())

    async def test_stopped_owned_service_and_foreground(self):
        for installed,command in ((True,'dot-herdr service start'),(False,'dot-herdr run in a normal terminal and keep it open')):
            report=await self.observed(runtime='stale',installed=installed,discovery=False)
            output=render(report)
            self.assertIn('Overall: the connector is not running. In this terminal, run '+command,output)
            self.assertIn('discovery: unavailable because the connector is not running',output)
            self.assertNotIn('Repair the selected route',output)

    async def test_public_502_and_network_error(self):
        for reachability,fragment in (('unreachable (HTTP 502)','HTTP 502'),('unreachable (ConnectError)','ConnectError')):
            report=await self.observed(reachability=reachability,discovery=False)
            self.assertIn('Overall: the connector runs on this computer, but https://connector.example.test/mcp does not reach it ('+fragment+').',render(report))
            self.assertIn("port 8123",render(report))
            self.assertEqual(report['observations']['route']['public_reachability'],reachability)
            self.assertIn('route/forwarder',report['observations']['discovery']['next_action'])

    async def test_source_unavailable(self):
        report=await self.observed(source=False)
        self.assertIn('Overall: the Herdr session is not reachable. Start the selected Herdr session ('+str(self.cfg['socket'])+')',render(report))

    async def test_healthy_live_offline_control_and_json(self):
        report=await self.observed(scopes=['herdr:observe'],complete=True)
        self.assertEqual(report['overall']['verdict'],'working')
        self.assertIn('Overall: working.',render(report))
        self.assertEqual(report['observations']['route']['public_reachability'],'reachable (HTTP 200)')
        self.assertIn('verified by the connection test on ',report['observations']['route']['account_connection'])
        offline=await self.observed(live=False)
        self.assertEqual(offline['observations']['route']['public_reachability'],'unknown')
        self.assertIn('Overall: no problems found in local checks; run status --live to test the public URL',render(offline))
        record=connection_record(self.config);record['verified_client_scopes']={'client-1':{'scopes':['herdr:observe'],'verified_at':time.time()-100,'expires_at':time.time()+1000}};save_connection(self.config,record)
        self.cfg['subjects'][0]['control']=True;save_config(self.config,self.cfg,previous=self.config.read_bytes())
        control=await self.observed(scopes=['herdr:observe'])
        self.assertIn('Also allow Herdr control',control['overall']['next_action'])
        self.assertIn('verdict',control['overall']);self.assertIn('next_action',control['overall'])

    async def test_one_bounded_metadata_get_and_safe_error_classes(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):
                self.limit=limit
                return b'{"resource":"https://connector.example.test/mcp","authorization_servers":["https://auth.example.test"]}'
        response=Response()
        with patch('dot_herdr.login.build_opener') as opener:
            opener.return_value.open.return_value=response
            self.assertEqual(public_metadata_status(self.cfg,self.cfg['resource']),('reachable (HTTP 200)',True))
            opener.return_value.open.assert_called_once()
            self.assertEqual(opener.return_value.open.call_args.kwargs['timeout'],3)
            self.assertEqual(response.limit,65537)
            error=HTTPError('https://example.test',502,'private body',{},None)
            opener.return_value.open.side_effect=error
            self.assertEqual(public_metadata_status(self.cfg,self.cfg['resource']),('unreachable (HTTP 502)',False))
            error.close()
            opener.return_value.open.side_effect=URLError(ConnectionRefusedError('private host'))
            self.assertEqual(public_metadata_status(self.cfg,self.cfg['resource']),('unreachable (ConnectionRefusedError)',False))

    async def test_setup_and_occupied_port_take_priority(self):
        with patch('dot_herdr.status.port_in_use',return_value=True),patch('dot_herdr.status.runtime_observation',return_value={'state':'stale'}),patch('dot_herdr.service.service_status',return_value={'state':'inactive','installed':False}):
            occupied=await status(self.config)
        self.assertIn('Another listener owns port 8123',occupied['overall']['next_action'])
        missing=self.root/'absent.json'
        invalid=await status(missing)
        self.assertEqual(invalid['overall']['verdict'],'setup needs attention')
        self.assertIn('Run guided setup',render(invalid))

    async def test_answering_url_with_mismatched_metadata(self):
        report=await self.observed(discovery=False)
        self.assertEqual(report['overall']['verdict'],'the public metadata does not match')
        self.assertIn('issuer/resource metadata',report['observations']['discovery']['next_action'])
