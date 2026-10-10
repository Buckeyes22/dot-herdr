"""Selected route and saved test evidence remain separate read-only observations."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.connections import connection_record,save_connection
from dot_herdr.core import Store
from dot_herdr.endpoint import principal_key
from dot_herdr.onboarding import save_config
from dot_herdr.status import render,status


class StatusRouteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.config=self.root/'config.json';self.cfg={'store':str(self.root/'store.sqlite'),'socket':str(self.root/'missing.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(self.root/'key.pem'),'subjects':[{'key':'agent','user_subject':'user','owner':'operator','pane':'pane','terminal':'terminal','native':None,'content':False,'control':False}],'session_users':[]}
        save_config(self.config,self.cfg)
        record=connection_record(self.config);record.update(route='https',wiring='registered-plugin',endpoint=self.cfg['resource'],last_authentication=time.time()-3600,check={'status':'pending','started_at':time.time()-20,'phases':{'transport_acceptance':'callback_2xx','triage_report':'authenticated_report','destination_confirmation':'pending'}});save_connection(self.config,record)
    def tearDown(self):self.temp.cleanup()
    async def test_public_route_missing_source_occupied_port_and_saved_test(self):
        with patch('dot_herdr.status.port_in_use',return_value=True):report=await status(self.config)
        checks=report['observations'];self.assertEqual(checks['source']['state'],'missing')
        self.assertEqual(checks['listener']['state'],'occupied');self.assertEqual(checks['tunnel']['state'],'not_applicable')
        self.assertEqual(checks['route']['url'],self.cfg['resource']);self.assertEqual(checks['route']['wiring'],'registered-plugin')
        self.assertEqual(checks['route']['public_reachability'],'unknown')
        self.assertEqual(checks['guided_connection_test']['destination_confirmation'],'pending')
        self.assertEqual(checks['authentication']['state'],'historically_verified');self.assertEqual(checks['authentication']['token_currently_usable'],'unknown')
        self.assertEqual(report['correct_dot_delivery'],'unknown')
        text=render(report);self.assertIn('tunnel: not_applicable',text);self.assertNotIn('Prepare a tunnel',text)
        self.assertIn('guided_connection_test:',text);self.assertIn(self.cfg['resource'],text)

    async def test_worker_failure_expired_watch_and_route_failure(self):
        store=Store(Path(self.cfg['store']));store.apply_roster([{**self.cfg['subjects'][0],'principal':principal_key(self.cfg['issuer'],'user')}])
        store.activate(principal_key(self.cfg['issuer'],'user'),'herdr.attention.detected',{'subject_key':'agent'},'https://callback.example.test','secret',60)
        store.close()
        class Source:
            async def request(self,*args):return {'version':'0.9.3','protocol':22}
        with patch('dot_herdr.status.runtime_observation',return_value={'state':'failed','error':'observer_failed'}),patch('dot_herdr.status.port_in_use',return_value=False),patch('dot_herdr.login.public_metadata_status',return_value=('unreachable (HTTP 502)',False)):
            report=await status(self.config,live=True,client_factory=lambda _:Source())
        checks=report['observations'];self.assertEqual(checks['runtime']['state'],'failed')
        self.assertEqual(checks['source']['state'],'compatible');self.assertEqual(checks['discovery']['state'],'unavailable')
        self.assertEqual(checks['tunnel']['state'],'not_applicable')
        self.assertEqual(report['correct_dot_delivery'],'unknown')
        with patch('dot_herdr.status.time.time',return_value=time.time()+65):expired=await status(self.config)
        self.assertGreaterEqual(expired['observations']['monitoring']['expired'],1)
        self.assertIn('Renew an expired watch',expired['observations']['monitoring']['next_action'])
