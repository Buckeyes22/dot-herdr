"""Operator status/setup/check must preserve state and distinguish live evidence."""
import copy
import hashlib
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock,patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from dot_herdr.core import Store,Rejected
from dot_herdr.endpoint import principal_key
from dot_herdr.runtime import RuntimeStatus,run
from dot_herdr.setup import load_config
from dot_herdr.connections import connection_record,save_connection
from dot_herdr.status import status,database_summary,runtime_observation
from dot_herdr.onboarding import guided_setup,draft_path,save_config
from dot_herdr.connection_check import local_evidence,check_connection


class UsabilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.home_patch=patch('pathlib.Path.home',return_value=self.root);self.home_patch.start();self.addCleanup(self.home_patch.stop)
        self.path=self.root/'config.json';self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.key=self.root/'key.pem';self.key.write_bytes(rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        self.cfg={'store':str(self.state/'store.sqlite'),'socket':str(self.root/'source.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(self.key),'subjects':[{'key':'agent','user_subject':'user','owner':'operator','pane':'pane','terminal':'terminal','native':None,'content':False,'control':False}],'session_users':[]}
        save_config(self.path,self.cfg)
    def tearDown(self):self.temp.cleanup()
    def store(self):
        store=Store(Path(self.cfg['store']));store.apply_roster([{**self.cfg['subjects'][0],'principal':principal_key(self.cfg['issuer'],'user')}]);return store
    def hashes(self):
        return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.state.iterdir() if p.is_file() and not p.name.endswith('-shm')}  # SQLite may update transient WAL read marks on a read-only query.
    async def test_status_preserves_active_wal_schema_sends_grants_and_owner(self):
        store=self.store();now=time.time();who=principal_key(self.cfg['issuer'],'user')
        store.activate(who,'herdr.attention.detected',{'subject_key':'agent'},'https://callback.example.test/events','private-callback-secret',60)
        store.db.execute('UPDATE subscriptions SET expires=?',(now-1,))
        before=self.hashes();schema=store.db.execute('PRAGMA user_version').fetchone()[0]
        with patch('dot_herdr.status.port_in_use',return_value=False),patch('dot_herdr.status.Store',create=True,side_effect=AssertionError('must not open Store')):
            report=await status(self.path)
        self.assertEqual(self.hashes(),before);self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0],schema)
        self.assertEqual(report['observations']['monitoring']['active_unexpired'],0);self.assertEqual(report['observations']['monitoring']['expired'],1)
        self.assertNotIn('private-callback-secret',json.dumps(report));self.assertNotIn('callback.example',json.dumps(report))
        self.assertEqual(report['correct_dot_delivery'],'unknown')
        with self.assertRaisesRegex(Rejected,'already_owned'):Store(Path(self.cfg['store']))
        store.close()
    def test_runtime_pid_freshness_stopped_and_failure_observations(self):
        record=RuntimeStatus(self.path);record.update(state='running',http_started=True,workers={'observer':'running','delivery':'running'})
        self.assertEqual(runtime_observation(self.path)['state'],'running')
        record.update(state='stopped',http_started=False);self.assertEqual(runtime_observation(self.path)['state'],'stopped')
        record.update(state='running',process_start='wrong-process');self.assertEqual(runtime_observation(self.path)['state'],'stale')
        record.update(state='failed',error='runtime_observer_failed');self.assertEqual(runtime_observation(self.path)['state'],'failed')
    async def test_stale_cached_startup_cannot_restore_revoked_access(self):
        store=self.store();store.close();cached=copy.deepcopy(self.cfg)
        inactive={**self.cfg,'subjects':[],'session_users':[],'inactive':True,'access_accounts':['user']}
        self.path.write_text(json.dumps(inactive));self.path.chmod(0o600)
        with self.assertRaisesRegex(Rejected,'configuration_changed_before_startup'):await run(self.path,cfg=cached)
        store=Store(Path(self.cfg['store']));store.close()
    async def test_no_cli_explicit_socket_and_noninteractive_pending_do_not_invent_grants(self):
        self.path.unlink()
        result=await guided_setup(self.path,interactive=False,ask=lambda _:self.fail('noninteractive prompt'),say=lambda _:None)
        self.assertEqual(result['stage'],'access');self.assertFalse(self.path.exists())
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.bind(self.cfg['socket'])
        class Source:
            async def request(self,method,params):
                if method=='ping':return {'version':'0.9.3','protocol':22}
                if method=='agent.list':return {'agents':[{'pane_id':'pane','terminal_id':'terminal','agent':'codex','agent_session':None}]}
                raise AssertionError('no writes')
            async def agent(self,pane):return {'pane_id':'pane','terminal_id':'terminal','agent':'codex','agent_session':None}
        answers=iter(['1','1','n','1','2',''])
        try:
            with patch('dot_herdr.onboarding.running_sessions',side_effect=AssertionError('CLI not required')):
                result=await guided_setup(self.path,self.cfg['socket'],ask=lambda _:next(answers),say=lambda _:None,client_factory=lambda _:Source())
            self.assertEqual(result['stage'],'provider');draft=load_config(draft_path(self.path));self.assertFalse(draft['subjects'][0]['control']);self.assertFalse(draft['subjects'][0]['content'])
            before=draft_path(self.path).read_bytes()
            result=await guided_setup(self.path,interactive=False,client_factory=lambda _:Source(),ask=lambda _:self.fail('prompt'),say=lambda _:None)
            self.assertEqual(result['stage'],'provider');self.assertEqual(draft_path(self.path).read_bytes(),before)
            self.assertEqual(connection_record(self.path)['route'],'https')
        finally:sock.close()
    def test_unrelated_watch_callback_is_not_test_evidence(self):
        store=self.store();who=principal_key(self.cfg['issuer'],'user');now=time.time()
        sub=store.activate(who,'herdr.attention.detected',{'subject_key':'agent'},'https://callback.example.test','secret',120)['id']
        store.db.execute("INSERT INTO events(id,subject,name,body,at) VALUES('event','agent','herdr.attention.detected','{}',?)",(now,))
        store.db.execute("INSERT INTO deliveries(event,sub,epoch,state) VALUES('event',?,1,'accepted')",(sub,))
        store.db.execute("INSERT INTO receipts VALUES(?,'event','finished','{}',?)",(sub,now))
        evidence=local_evidence(self.cfg,{'target':'agent','started_at':now-1,'request_id':'never-submitted','subscription_id':'a-different-test-watch'})
        self.assertEqual(evidence,{})
        evidence=local_evidence(self.cfg,{'target':'agent','started_at':now-1,'request_id':'never-submitted','subscription_id':sub})
        self.assertNotIn('transport_acceptance',evidence);self.assertNotIn('triage_report',evidence)
        store.close()
    async def test_check_without_test_control_or_interaction_performs_no_input(self):
        with patch('dot_herdr.connection_check.status',return_value={'mode':'offline_read_only','observations':{}}):
            result=await check_connection(self.path,ask=lambda _:self.fail('no test target'),say=lambda _:None)
            self.assertEqual(result['phase'],'test_target')
            result=await check_connection(self.path,interactive=False,ask=lambda _:self.fail('noninteractive'),say=lambda _:None)
            self.assertEqual(result['status'],'pending')

    async def test_guided_verified_pairing_activates_only_selected_grants_and_resumes_initialized(self):
        self.path.unlink();sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.bind(self.cfg['socket'])
        class Source:
            async def request(self,method,params):
                if method=='ping':return {'version':'0.9.3','protocol':22}
                if method=='agent.list':return {'agents':[{'pane_id':'pane','terminal_id':'terminal','agent':'codex','agent_session':None}]}
                raise AssertionError('no writes in setup')
            async def agent(self,pane):return {'pane_id':'pane','terminal_id':'terminal','agent':'codex','agent_session':None}
        prompts=[];answers=iter(['2','1','n','2','2','https://connector.example.test/mcp','n'])
        def ask(prompt):prompts.append(prompt);return next(answers)
        identity={'issuer':self.cfg['issuer'],'subject':'verified-user','principal':principal_key(self.cfg['issuer'],'verified-user')}
        async def pending_check(*args,**kwargs):return {'status':'pending','phase':'destination_confirmation'}
        async def idle(*args,**kwargs):await __import__('asyncio').Event().wait()
        try:
            with patch('dot_herdr.auth.discover_resource',return_value={'issuers':['https://auth.example.test']}),patch('dot_herdr.auth.discover_provider',return_value={'jwks_url':'https://auth.example.test/jwks'}),patch('dot_herdr.connections.prepare_connections',return_value={'registration':{'status':'registered'},'owned':{}}),patch('dot_herdr.onboarding.pairing_identity',return_value=identity) as pair,patch('dot_herdr.status.runtime_observation',side_effect=[{'state':'stopped'},{'state':'running'}]),patch('dot_herdr.status.port_in_use',return_value=False),patch('dot_herdr.runtime.run',side_effect=idle),patch('dot_herdr.connection_check.check_connection',side_effect=pending_check):
                result=await guided_setup(self.path,self.cfg['socket'],app_id='asdk_app_synthetic',ask=ask,say=lambda _:None,client_factory=lambda _:Source())
            self.assertEqual(result['phase'],'destination_confirmation');cfg=load_config(self.path)
            self.assertEqual(cfg['subjects'][0]['user_subject'],'verified-user');self.assertTrue(cfg['subjects'][0]['control']);self.assertFalse(cfg['subjects'][0]['content'])
            self.assertNotIn('public_key',cfg);self.assertEqual(cfg['jwks_url'],'https://auth.example.test/jwks')
            self.assertFalse(draft_path(self.path).exists());self.assertFalse(any('PEM' in p or 'subject (sub)' in p for p in prompts))
            store=Store(Path(cfg['store']));store.close();before=self.path.read_bytes()
            with patch('dot_herdr.auth.discover_provider',return_value={'jwks_url':cfg['jwks_url']}),patch('dot_herdr.connections.prepare_connections',return_value={'registration':{'status':'existing'},'owned':{}}),patch('dot_herdr.onboarding.pairing_identity',side_effect=AssertionError('do not pair again')),patch('dot_herdr.status.runtime_observation',return_value={'state':'running'}),patch('dot_herdr.connection_check.check_connection',side_effect=pending_check):
                result=await guided_setup(self.path,ask=lambda _:self.fail('resume must not ask grants/auth again'),say=lambda _:None,client_factory=lambda _:Source())
            self.assertEqual(self.path.read_bytes(),before);self.assertEqual(connection_record(self.path)['wiring'],'registered-plugin')
        finally:sock.close()
    def test_connection_record_stale_writer_does_not_erase_new_stage(self):
        left=connection_record(self.path);right=connection_record(self.path)
        left['stage']='identity';save_connection(self.path,left)
        right['stage']='route'
        with self.assertRaisesRegex(Rejected,'record_changed'):save_connection(self.path,right)
        self.assertEqual(connection_record(self.path)['stage'],'identity')

    def test_interrupted_setup_temporary_does_not_block_resume_or_overwrite(self):
        self.path.unlink();residue=self.path.with_name(self.path.name+'.setup-new');residue.write_text('interrupted-private-draft');residue.chmod(0o600)
        save_config(self.path,self.cfg)
        self.assertEqual(load_config(self.path),self.cfg);self.assertEqual(residue.read_text(),'interrupted-private-draft')
        with self.assertRaises(FileExistsError):save_config(self.path,self.cfg)

    def test_configured_public_client_preserves_collision_checks_and_offline_config(self):
        from dot_herdr.setup import validate_config
        from dot_herdr.connections import register_mcp
        configured={**self.cfg,'oauth_client_id':'public-client'}
        validate_config(configured)
        home=self.root/'client-config';home.mkdir(mode=0o700)
        result=register_mcp(home,self.cfg['resource'],resource=self.cfg['resource'],client_id='public-client')
        self.assertIn('client_id = "public-client"',result['owned_table'])
        self.assertIn('.oauth]',result['owned_table'])
        with self.assertRaisesRegex(Rejected,'existing_mcp_entry'):register_mcp(home,self.cfg['resource'],resource=self.cfg['resource'],client_id='different-client')

    async def test_selected_public_client_survives_provider_pending_resume(self):
        self.path.unlink();cfg={**self.cfg,'jwks_url':'https://auth.example.test/jwks'};cfg.pop('public_key')
        save_config(draft_path(self.path),cfg)
        record=connection_record(self.path);record.update(route='https',wiring='standalone');save_connection(self.path,record)
        class Source:
            async def request(self,*args):return {'version':'0.9.3','protocol':22}
            async def agent(self,*args):return {'pane_id':'pane','terminal_id':'terminal','agent_session':None}
        with patch('dot_herdr.auth.discover_provider',side_effect=Rejected('provider_unavailable')) as discover:
            result=await guided_setup(self.path,oauth_client_id='public-client',ask=lambda _:self.fail('no new access'),say=lambda _:None,client_factory=lambda _:Source())
            self.assertEqual(result['stage'],'provider')
            self.assertEqual(load_config(draft_path(self.path))['oauth_client_id'],'public-client')
            await guided_setup(self.path,ask=lambda _:self.fail('resume'),say=lambda _:None,client_factory=lambda _:Source())
            self.assertEqual(discover.call_args.args[2],'public-client')

    async def test_saved_standalone_without_cli_returns_before_pairing(self):
        record=connection_record(self.path);record.update(route='https',wiring='standalone');save_connection(self.path,record)
        class Source:
            async def request(self,*args):return {'version':'0.9.3','protocol':22}
            async def agent(self,*args):return {'pane_id':'pane','terminal_id':'terminal','agent_session':None}
        with patch('dot_herdr.onboarding.shutil.which',return_value=None),patch('dot_herdr.onboarding.pairing_identity',side_effect=AssertionError('must not wait')):
            result=await guided_setup(self.path,ask=lambda _:self.fail('must not prompt'),say=lambda _:None,client_factory=lambda _:Source())
        self.assertEqual(result['stage'],'client')

    async def test_connection_check_requires_verified_watch_before_source_instruction(self):
        cfg=copy.deepcopy(self.cfg);cfg['subjects'][0]['control']=True
        self.path.write_text(json.dumps(cfg));self.path.chmod(0o600)
        answers=iter(['1','y','']);messages=[]
        with patch('dot_herdr.connection_check.status',return_value={'mode':'offline_read_only','observations':{}}):
            result=await check_connection(self.path,ask=lambda _:next(answers),say=messages.append)
        self.assertEqual(result['phase'],'test_watch')
        self.assertFalse(any('call send_agent_message' in message for message in messages))

    def test_unsubscribe_evidence_requires_fence_of_recorded_watch_epoch(self):
        store=self.store();who=principal_key(self.cfg['issuer'],'user');now=time.time()
        sub=store.activate(who,'herdr.attention.detected',{'subject_key':'agent'},'https://callback.example.test','secret',120)['id']
        watch=store.db.execute('SELECT epoch,expires FROM subscriptions WHERE id=?',(sub,)).fetchone()
        check={'target':'agent','started_at':now,'request_id':'stable','subscription_id':sub,'subscription_evidence':sub,'watch_binding':'operator_subscription_id','subscription_epoch':watch[0],'watch_expires_at':watch[1]}
        self.assertNotIn('unsubscribe',local_evidence(self.cfg,check))
        store.unsubscribe(who,'herdr.attention.detected',{'subject_key':'agent'},'https://callback.example.test')
        self.assertEqual(local_evidence(self.cfg,check)['unsubscribe'],'test_watch_fenced')
        store.activate(who,'herdr.attention.detected',{'subject_key':'agent'},'https://callback.example.test','secret',120)
        self.assertNotIn('unsubscribe',local_evidence(self.cfg,check));store.close()

    async def test_resumed_expired_watch_does_not_issue_source_input(self):
        cfg=copy.deepcopy(self.cfg);cfg['subjects'][0]['control']=True
        self.path.write_text(json.dumps(cfg));self.path.chmod(0o600)
        store=self.store();who=principal_key(cfg['issuer'],'user');started=time.time()-200
        sub=store.activate(who,'herdr.attention.detected',{'subject_key':'agent'},'https://callback.example.test','secret',120)['id']
        store.db.execute('UPDATE subscriptions SET expires=? WHERE id=?',(started+120,sub));store.close()
        record=connection_record(self.path)
        record['check']={'target':'agent','nonce':'saved-nonce','request_id':'saved-request','started_at':started,'status':'pending','phases':{'source_submission':'pending'},'subscription_id':sub,'subscription_epoch':1,'watch_expires_at':started+120}
        save_connection(self.path,record);answers=iter(['1','y',sub]);messages=[]
        with patch('dot_herdr.connection_check.status',return_value={'mode':'offline_read_only','observations':{}}):
            result=await check_connection(self.path,ask=lambda _:next(answers),say=messages.append)
        self.assertEqual(result['phase'],'test_watch');self.assertEqual(result['request_id'],'saved-request')
        self.assertFalse(any('call send_agent_message' in message for message in messages))
