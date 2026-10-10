import copy
import fcntl
import json
import os
import socket
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dot_herdr.access import apply_access,configure_access,rebind_keys,roster,service_adapter
from dot_herdr.core import Store,Rejected


class Service:
    def __init__(self):self.active=True;self.calls=[];self.fail=False
    def status(self):return {'owned':True,'active':self.active}
    def stop(self):self.calls.append('stop');self.active=False
    def start(self):
        self.calls.append('start')
        if self.fail:raise ValueError('start failed')
        self.active=True


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.path=self.root/'config.json';(self.root/'state').mkdir(mode=0o700)
        self.cfg={'store':str(self.root/'state/connector.sqlite'),'socket':str(self.root/'source.sock'),
                  'issuer':'https://issuer.example.test','resource':'https://resource.example.test/mcp','public_key':str(self.root/'public.pem'),
                  'subjects':[{'key':'one','user_subject':'account','owner':'owner','pane':'pane','terminal':'terminal','content':True,'control':False}], 'session_users':[]}
        self.path.write_text(json.dumps(self.cfg));self.path.chmod(0o600)
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.bind(self.cfg['socket'])
        self.store=Store(self.cfg['store']);self.store.apply_roster(roster(self.cfg));self.store.close()
    def tearDown(self):self.socket.close();self.tmp.cleanup()
    def test_content_is_mutable_and_identity_is_not(self):
        store=Store(self.cfg['store'])
        try:
            first=roster(self.cfg)[0];store.enroll(**dict(first,content=False))
            self.assertFalse(store.subject(first['principal'],'one')['content'])
            with self.assertRaisesRegex(Rejected,'rebind_required'):store.enroll(**dict(first,terminal='replacement'))
        finally:store.close()
    def test_entire_roster_is_validated_before_any_mutation(self):
        store=Store(self.cfg['store']);first=roster(self.cfg)[0]
        try:
            with self.assertRaisesRegex(Rejected,'rebind_required'):
                store.apply_roster([dict(first,key='new'),dict(first,terminal='replacement',content=False)])
            self.assertIsNone(store.db.execute("SELECT * FROM subjects WHERE key='new'").fetchone())
            self.assertTrue(store.subject(first['principal'],'one')['content'])
        finally:store.close()
    def test_foreground_owner_refused_bytes_and_grants_retained(self):
        store=Store(self.cfg['store']);previous=self.path.read_bytes();changed=copy.deepcopy(self.cfg);changed['subjects'][0]['content']=False
        try:
            with self.assertRaisesRegex(Rejected,'stop_foreground_owner'):apply_access(self.path,changed,previous)
            self.assertEqual(self.path.read_bytes(),previous)
            self.assertTrue(store.subject(roster(self.cfg)[0]['principal'],'one')['content'])
        finally:store.close()
    def test_controlled_change_preserves_history_actions_and_private_backup(self):
        store=Store(self.cfg['store']);principal=roster(self.cfg)[0]['principal'];store.begin_action(principal,'request',{'method':'send'});store.close()
        service=Service();previous=self.path.read_bytes();changed=copy.deepcopy(self.cfg);changed['subjects'][0]['content']=False
        result=apply_access(self.path,changed,previous,service)
        self.assertEqual(service.calls,['stop','start']);self.assertEqual(Path(result['backup']).read_bytes(),previous)
        self.assertEqual(Path(result['backup']).stat().st_mode&0o777,0o600)
        store=Store(self.cfg['store'])
        try:
            self.assertFalse(store.subject(principal,'one')['content'])
            self.assertEqual(store.begin_action(principal,'request',{'method':'send'})['outcome'],'unknown')
        finally:store.close()
    def test_revoke_all_fences_old_subscription_never_restores(self):
        first=roster(self.cfg)[0];store=Store(self.cfg['store']);sub=store.activate(first['principal'],'herdr.attention.detected',{'subject_key':'one'},'https://callback.example.test/events','secret')['id'];store.close()
        changed=copy.deepcopy(self.cfg);changed.update(subjects=[],session_users=[],inactive=True,access_accounts=['account']);service=Service();service.fail=True
        result=apply_access(self.path,changed,self.path.read_bytes(),service)
        self.assertEqual(result['status'],'inactive');self.assertEqual(service.calls,['stop'])
        store=Store(self.cfg['store'])
        try:
            self.assertFalse(store.db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0])
            store.apply_roster([first]);self.assertFalse(store.db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0])
        finally:store.close()
    def test_reenable_after_revoke_all_starts_the_stopped_service(self):
        inactive=copy.deepcopy(self.cfg);inactive.update(subjects=[],session_users=[],inactive=True,access_accounts=['account'])
        self.path.write_text(json.dumps(inactive));service=Service();service.active=False
        result=apply_access(self.path,copy.deepcopy(self.cfg),self.path.read_bytes(),service)
        self.assertEqual(service.calls,['start']);self.assertTrue(result['service_restarted']);self.assertTrue(service.active)
    def test_deliberately_stopped_service_stays_stopped_on_ordinary_change(self):
        service=Service();service.active=False;changed=copy.deepcopy(self.cfg);changed['subjects'][0]['content']=False
        result=apply_access(self.path,changed,self.path.read_bytes(),service)
        self.assertEqual(service.calls,[]);self.assertFalse(result['service_restarted'])
    def test_control_growth_note_skips_reconnect_when_sign_in_already_allows_control(self):
        from dot_herdr.access import control_growth_note
        granted={'client_app':'chatgpt-web','verified_client_scopes':{'client-a':{'scopes':['herdr:control','herdr:observe'],'verified_at':1,'expires_at':2}}}
        note=control_growth_note(granted)
        self.assertNotIn('remove the Herdr plugin',note);self.assertIn('already allowed control',note)
        note=control_growth_note({'client_app':'chatgpt-web','verified_client_scopes':{'client-a':{'scopes':['herdr:observe'],'verified_at':1,'expires_at':2}}})
        self.assertIn('remove the Herdr plugin, add it again',note);self.assertIn('chatgpt.com',note);self.assertNotIn('desktop',note)
        self.assertIn('desktop app',control_growth_note({'client_app':'desktop'}))
    def test_restart_failure_retains_reduced_grants(self):
        changed=copy.deepcopy(self.cfg);changed['subjects'][0]['content']=False;service=Service();service.fail=True
        with self.assertRaisesRegex(Rejected,'no_grants_restored'):apply_access(self.path,changed,self.path.read_bytes(),service)
        self.assertFalse(json.loads(self.path.read_text())['subjects'][0]['content']);self.assertFalse(service.active)
        self.assertEqual(service.calls,['stop','start','stop'])
    def test_replacement_gets_new_key_even_with_same_pane_terminal(self):
        old=dict(self.cfg['subjects'][0],native={'value':'old'});new=dict(old,native={'value':'new'})
        self.assertEqual(rebind_keys([old],[old])[0]['key'],old['key'])
        self.assertNotEqual(rebind_keys([new],[old])[0]['key'],old['key'])
    def test_sqlite_initialization_failure_releases_transferred_owner_lock(self):
        lock=Path(self.cfg['store']+'.owner.lock');fd=os.open(lock,os.O_RDONLY);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with patch('dot_herdr.core.sqlite3.connect',side_effect=sqlite3.OperationalError('unavailable')):
            with self.assertRaises(sqlite3.OperationalError):Store(self.cfg['store'],owner_fd=fd)
        replacement=os.open(lock,os.O_RDONLY)
        try:fcntl.flock(replacement,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(replacement)
    def test_symlink_ancestor_refused_before_creating_any_store(self):
        link=self.root/'alias';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(Rejected,'private_store'):Store(link/'new-state/database.sqlite')
        self.assertFalse((self.root/'new-state').exists())
    def test_service_verification_requires_matching_manager_pid_and_release(self):
        evidence=self.root/'runtime.json';evidence.write_text(json.dumps({'pid':os.getpid(),'runtime_prefix':str(self.root)}));evidence.chmod(0o600)
        with patch('dot_herdr.service.service_status',return_value={'installed':True,'state':'active','pid':os.getpid()}),patch('dot_herdr.runtime.status_path',return_value=evidence),patch('dot_herdr.status.runtime_observation',return_value={'state':'running'}):
            adapter=service_adapter(self.path);self.assertEqual(adapter.verify(self.root)['status'],'verified')
            with patch('dot_herdr.access.time.monotonic',side_effect=[0,0,11]),patch('dot_herdr.access.time.sleep'):
                with self.assertRaisesRegex(Rejected,'readiness_unverified'):adapter.verify(self.root/'different-release')
        with patch('dot_herdr.service.service_status',return_value={'installed':True,'state':'active','pid':os.getpid()+1}),patch('dot_herdr.runtime.status_path',return_value=evidence),patch('dot_herdr.status.runtime_observation',return_value={'state':'running'}),patch('dot_herdr.access.time.monotonic',side_effect=[0,0,11]),patch('dot_herdr.access.time.sleep'):
            with self.assertRaisesRegex(Rejected,'readiness_unverified'):service_adapter(self.path).verify(self.root)


class AccessWizardTests(unittest.IsolatedAsyncioTestCase):
    async def test_control_expansion_offers_settings_without_claiming_consent(self):
        test=AccessTests();test.setUp()
        try:
            class Source:
                async def request(self,*args):return {'version':'0.9.3','protocol':22}
            answers=iter(['1','2','y']);messages=[]
            selected=[dict(test.cfg['subjects'][0],control=True)]
            with patch('dot_herdr.access.choose_agents',return_value=selected),patch('dot_herdr.login.login_mcp',side_effect=AssertionError('no sign-in inside access')):
                result=await configure_access(test.path,ask=lambda _:next(answers),say=messages.append,client_factory=lambda _:Source())
            self.assertEqual(result['consent'],'pending_herdr_control_scope')
            self.assertIn('ChatGPT in a web browser (chatgpt.com), open Settings → Plugins',messages[-1]);self.assertIn('protected control request',messages[-1])
            self.assertTrue(json.loads(test.path.read_text())['subjects'][0]['control'])
        finally:test.tearDown()

    async def test_plugin_control_expansion_preserves_selected_wiring(self):
        test=AccessTests();test.setUp()
        try:
            from dot_herdr.connections import connection_record,save_connection
            record=connection_record(test.path);record.update(wiring='registered-plugin',route='https');save_connection(test.path,record)
            class Source:
                async def request(self,*args):return {'version':'0.9.3','protocol':22}
            answers=iter(['1','2','y']);selected=[dict(test.cfg['subjects'][0],control=True)]
            with patch('dot_herdr.access.choose_agents',return_value=selected),patch('dot_herdr.login.login_mcp',side_effect=AssertionError('no duplicate standalone')):
                result=await configure_access(test.path,ask=lambda _:next(answers),say=lambda _:None,client_factory=lambda _:Source())
            self.assertEqual(result['consent'],'pending_herdr_control_scope')
        finally:test.tearDown()

    async def test_revoke_and_resume_require_explicit_selection(self):
        test=AccessTests();test.setUp()
        try:
            await configure_access(test.path,revoke_all=True,say=lambda _:None)
            class Source:
                async def request(self,method,args):
                    if method=='ping':return {'version':'0.9.3','protocol':22}
                    return {'agents':[{'agent':'codex','pane_id':'pane','terminal_id':'terminal'}]}
                async def agent(self,pane):return {'agent':'codex','pane_id':'pane','terminal_id':'terminal'}
            answers=iter(['1','1','1','n','y'])
            await configure_access(test.path,ask=lambda _:next(answers),say=lambda _:None,client_factory=lambda _:Source())
            value=json.loads(test.path.read_text());self.assertNotIn('inactive',value);self.assertFalse(value['subjects'][0]['control']);self.assertFalse(value['subjects'][0]['content'])
        finally:test.tearDown()
