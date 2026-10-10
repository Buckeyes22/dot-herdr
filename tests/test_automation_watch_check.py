"""Synthetic automation watch discovery and exact-watch fencing."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from dot_herdr.connection_check import WATCH,candidate_watches,bind_confirmed_watch,capture_watch,fence_test_watch,local_evidence
from dot_herdr.core import Store
from dot_herdr.endpoint import principal_key
from dot_herdr.onboarding import save_config


class AutomationWatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        self.cfg={'store':str(root/'store.sqlite'),'socket':str(root/'missing.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(root/'key.pem'),'subjects':[{'key':'agent','user_subject':'user','owner':'local','pane':'pane','terminal':'terminal','native':None,'content':False,'control':True},{'key':'other','user_subject':'user','owner':'local','pane':'other-pane','terminal':'other-terminal','native':None,'content':False,'control':True}],'session_users':[]}
        save_config(root/'config.json',self.cfg);self.who=principal_key(self.cfg['issuer'],'user');self.store=Store(Path(self.cfg['store']));self.store.apply_roster([{**s,'principal':self.who} for s in self.cfg['subjects']])
    def tearDown(self):self.store.close();self.temp.cleanup()
    def sub(self,url,subject='agent'):return self.store.activate(self.who,WATCH,{'subject_key':subject},url,'synthetic-secret',3600)['id']
    def check(self,**values):return {'target':'agent','watch_event':WATCH,'started_at':time.time()-1,'request_id':'connection-check-watch','prior_watch_ids':[],**values}

    async def test_single_candidate_can_be_bound_and_fenced(self):
        check=self.check();sub=self.sub('https://one.example.test/events');rows=candidate_watches(self.cfg,check)
        self.assertEqual(len(rows),1);bind_confirmed_watch(check,rows[0]);self.assertEqual(check['subscription_id'],sub)
        self.assertEqual(fence_test_watch(self.cfg,check),'connector_fenced')

    async def test_two_candidates_are_not_auto_bound(self):
        check=self.check();self.sub('https://one.example.test/events');self.sub('https://two.example.test/events')
        self.assertEqual(len(candidate_watches(self.cfg,check)),2);self.assertEqual(capture_watch(self.cfg,check),'ambiguous')
        self.assertNotIn('subscription_id',check);self.assertEqual(fence_test_watch(self.cfg,check),'no_test_watch')

    async def test_operator_id_binds_only_exact_candidate(self):
        check=self.check();one=self.sub('https://one.example.test/events');two=self.sub('https://two.example.test/events')
        check['subscription_evidence']=two;self.assertEqual(capture_watch(self.cfg,check),'captured')
        self.assertEqual(check['subscription_id'],two);self.assertEqual(fence_test_watch(self.cfg,check),'connector_fenced')
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(one,)).fetchone()[0],1)

    async def test_prior_and_other_subject_are_excluded(self):
        prior=self.sub('https://prior.example.test/events');check=self.check(prior_watch_ids=[prior]);other=self.sub('https://other.example.test/events','other')
        self.assertEqual(candidate_watches(self.cfg,check),[])
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(other,)).fetchone()[0],1)

    async def test_watch_after_action_is_excluded(self):
        check=self.check();self.store.begin_action(self.who,check['request_id'],{'synthetic':'action'});self.store.finish_action(self.who,check['request_id'],{'outcome':'submitted'})
        later=time.time()+.1
        with patch('dot_herdr.connection_check.time.time',return_value=later):
            self.store.clock=lambda:later;self.sub('https://late.example.test/events')
            self.assertEqual(candidate_watches(self.cfg,check),[])

    async def test_longer_lifetime_needs_exact_subscription_id(self):
        check=self.check();self.store.begin_action(self.who,check['request_id'],{'synthetic':'action'})
        later=time.time()+.1;self.store.clock=lambda:later
        sub=self.store.activate(self.who,WATCH,{'subject_key':'agent'},'https://long.example.test/events','secret',7200)['id']
        self.assertEqual(candidate_watches(self.cfg,check),[])
        check['subscription_evidence']=sub;self.assertEqual(capture_watch(self.cfg,check),'captured')

    async def test_fence_refuses_refreshed_epoch(self):
        check=self.check();sub=self.sub('https://refresh.example.test/events');bind_confirmed_watch(check,candidate_watches(self.cfg,check)[0])
        self.assertEqual(fence_test_watch(self.cfg,check),'connector_fenced');self.sub('https://refresh.example.test/events')
        self.assertEqual(fence_test_watch(self.cfg,check),'identity_changed')

    async def test_host_stop_before_binding_is_preserved(self):
        check=self.check();sub=self.sub('https://fast.example.test/events');self.store.unsubscribe(self.who,WATCH,{'subject_key':'agent'},'https://fast.example.test/events')
        bind_confirmed_watch(check,candidate_watches(self.cfg,check)[0]);self.assertEqual(check['subscription_epoch'],1)
        self.assertEqual(fence_test_watch(self.cfg,check),'host_unsubscribed')

    async def test_inactive_epoch_proves_no_further_delivery(self):
        check=self.check();self.sub('https://stopped.example.test/events');bind_confirmed_watch(check,candidate_watches(self.cfg,check)[0])
        self.assertEqual(fence_test_watch(self.cfg,check),'connector_fenced');check['fence_result']='connector_fenced'
        evidence=local_evidence(self.cfg,check)
        self.assertEqual(evidence['no_further_delivery'],'locally_verified')
