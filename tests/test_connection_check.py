"""Saved connection-check evidence and recovery stay scoped to one request."""
import tempfile
import time
import unittest
from pathlib import Path

from dot_herdr.connection_check import WATCH,recover_connection,test_instruction
from dot_herdr.connections import connection_record,save_connection
from dot_herdr.core import Store
from dot_herdr.endpoint import principal_key
from dot_herdr.onboarding import save_config
from dot_herdr.status import status


class ConnectionCheckTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name);self.config=root/'config.json'
        self.cfg={'store':str(root/'store.sqlite'),'socket':str(root/'missing.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(root/'key.pem'),'subjects':[{'key':'agent','user_subject':'user','owner':'local','pane':'pane','terminal':'terminal','native':None,'content':False,'control':True}],'session_users':['user']}
        save_config(self.config,self.cfg);self.who=principal_key(self.cfg['issuer'],'user');self.store=Store(Path(self.cfg['store']));self.store.apply_roster([{**self.cfg['subjects'][0],'principal':self.who}])
    def tearDown(self):self.store.close();self.temp.cleanup()
    def seed(self,**updates):
        check={'target':'agent','watch_event':WATCH,'nonce':'00112233445566778899aabb','request_id':'connection-check-seeded-001','started_at':time.time(),'status':'pending','phases':{p:'pending' for p in ('authenticated_read','source_submission','source_response','event_capture','callback_verification','transport_acceptance','triage_report','destination_confirmation','unsubscribe','no_further_delivery')},'prior_watch_ids':[]}
        check.update(updates);record=connection_record(self.config);record['check']=check;save_connection(self.config,record);return check

    async def test_status_and_recovery_preserve_history(self):
        old=self.seed();inspected=await recover_connection(self.config,'inspect',say=lambda _:None)
        self.assertEqual(inspected['action_inspection']['ledger'],'not_submitted')
        abandoned=await recover_connection(self.config,'abandon',say=lambda _:None)
        new=await recover_connection(self.config,'start-new',request_id='connection-check-fresh-001',say=lambda _:None)
        observed=(await status(self.config))['observations']['guided_connection_test']
        self.assertEqual(observed['request_id'],new['request_id']);self.assertEqual(new['history'][0]['request_id'],old['request_id'])
        self.assertEqual(new['history'][0]['status'],'abandoned');self.assertEqual(abandoned['fence_result'],'no_test_watch')

    async def test_instruction_uses_old_host_compatible_receipt(self):
        instruction=test_instruction(self.seed())
        for fragment in ('automations.create_for_aeon','automations.list_event_sources','record_triage_receipt','subscription_key \\"\\"','send_agent_message','request_id','automations.update','is_enabled false'):
            self.assertIn(fragment,instruction)
        for fragment in ('ttlMs','events/subscribe','get_agent_state','terminal=','pane='):
            self.assertNotIn(fragment,instruction)

    async def test_late_watch_recovery_does_not_bind_or_fence(self):
        self.seed(started_at=time.time()-400);sub=self.store.activate(self.who,WATCH,{'subject_key':'agent'},'https://late.example.test/events','secret',3600)['id']
        inspected=await recover_connection(self.config,'inspect',say=lambda _:None)
        self.assertEqual(inspected['status'],'expired');self.assertNotIn('subscription_id',inspected)
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0],1)

    async def test_abandon_fences_only_bound_watch(self):
        sub=self.store.activate(self.who,WATCH,{'subject_key':'agent'},'https://test.example.test/events','secret',3600)['id']
        other=self.store.activate(self.who,WATCH,{'subject_key':'agent'},'https://other.example.test/events','secret',3600)['id']
        self.seed(subscription_id=sub,subscription_evidence=sub,subscription_epoch=1,watch_binding='operator_confirmed_local')
        abandoned=await recover_connection(self.config,'abandon',say=lambda _:None)
        self.assertEqual(abandoned['fence_result'],'connector_fenced')
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0],0)
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(other,)).fetchone()[0],1)

    async def test_unknown_action_inspection_keeps_request(self):
        check=self.seed();self.store.begin_action(self.who,check['request_id'],{'synthetic':'uncertain'})
        inspected=await recover_connection(self.config,'inspect',say=lambda _:None)
        self.assertEqual(inspected['action_inspection']['ledger'],'unknown_inspect_do_not_replay')
        self.assertEqual(inspected['request_id'],check['request_id'])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM actions').fetchone()[0],1)
