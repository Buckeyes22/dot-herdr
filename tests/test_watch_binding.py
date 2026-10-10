"""The test watch must be identified by explicit subscribe evidence."""
import tempfile
import time
import unittest
from pathlib import Path

from dot_herdr.connection_check import capture_watch,fence_test_watch,recover_connection
from dot_herdr.connections import connection_record,save_connection
from dot_herdr.core import Store
from dot_herdr.endpoint import principal_key
from dot_herdr.onboarding import save_config


class WatchBindingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.config=self.root/'config.json'
        self.cfg={'store':str(self.root/'store.sqlite'),'socket':str(self.root/'source.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(self.root/'key.pem'),'subjects':[{'key':'agent','user_subject':'user','owner':'local','pane':'pane','terminal':'terminal','native':None,'content':False,'control':True}],'session_users':[]}
        save_config(self.config,self.cfg);self.who=principal_key(self.cfg['issuer'],'user')
        self.store=Store(Path(self.cfg['store']));self.store.apply_roster([{**self.cfg['subjects'][0],'principal':self.who}])
    def tearDown(self):self.store.close();self.temp.cleanup()
    async def test_unidentified_single_new_watch_is_ambiguous_and_active_after_recovery(self):
        check={'target':'agent','watch_event':'herdr.turn.completed','request_id':'connection-check-synthetic','started_at':time.time(),'status':'pending','phases':{},'prior_watch_ids':[]}
        record=connection_record(self.config);record['check']=check;save_connection(self.config,record)
        sub=self.store.activate(self.who,'herdr.turn.completed',{'subject_key':'agent'},'https://other.example.test/callback','synthetic-secret',3600)['id']
        self.assertEqual(capture_watch(self.cfg,check),'ambiguous')
        self.assertNotIn('subscription_id',check)
        self.assertEqual(fence_test_watch(self.cfg,check),'no_test_watch')
        recovered=await recover_connection(self.config,'abandon',say=lambda _:None)
        self.assertEqual(recovered['watch_capture'],'ambiguous')
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0],1)
