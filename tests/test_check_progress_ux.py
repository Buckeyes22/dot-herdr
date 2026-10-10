"""Synthetic regressions for the guided progress check."""
import tempfile
import time
import unittest
import os
import io
import asyncio
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from dot_herdr.connection_check import ask_live,save_check,check_connection,test_instruction,candidate_watches,fence_test_watch
from dot_herdr.connections import connection_record,save_connection
from dot_herdr.core import Store,Rejected
from dot_herdr.endpoint import principal_key
from dot_herdr.onboarding import save_config


class ProgressRegressionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name);self.config=root/'config.json'
        self.cfg={'store':str(root/'store.sqlite'),'socket':str(root/'missing.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(root/'key.pem'),'subjects':[{'key':'agent','user_subject':'user','owner':'local','pane':'pane','terminal':'terminal','native':None,'content':False,'control':True}],'session_users':[]}
        save_config(self.config,self.cfg);self.who=principal_key(self.cfg['issuer'],'user')
        self.store=Store(Path(self.cfg['store']));self.store.apply_roster([{**self.cfg['subjects'][0],'principal':self.who}]);self.run_number=0
    def tearDown(self):self.store.close();self.temp.cleanup()

    async def test_check_save_merges_concurrent_verified_scopes(self):
        check={'target':'agent','status':'pending'}
        old=connection_record(self.config)
        concurrent=connection_record(self.config);concurrent['identity']=self.who;save_connection(self.config,concurrent)
        from dot_herdr.auth import record_verified_scopes
        token=SimpleNamespace(scopes=['herdr:control'],claims={'iss':self.cfg['issuer']},subject='user',client_id='client',expires_at=time.time()+3600)
        record_verified_scopes(self.config,token)
        with patch('dot_herdr.connection_check.connection_record',side_effect=[old,connection_record(self.config)]):save_check(self.config,check)
        saved=connection_record(self.config)
        self.assertEqual(saved['check'],check);self.assertIn('client',saved['verified_client_scopes'])

    async def test_empty_receipt_key_infers_one_and_rejects_several(self):
        one=self.store.activate(self.who,'herdr.turn.completed',{'subject_key':'agent'},'https://one.example.test/events','secret',3600)['id']
        self.store.db.execute("INSERT INTO events(id,subject,name,body,at) VALUES('event','agent','herdr.turn.completed','{}',1)")
        self.store.db.execute("INSERT INTO deliveries(event,sub,epoch,state) VALUES('event',?,1,'accepted')",(one,))
        self.assertEqual(self.store.receipt(self.who,'event','','finished','observed')['subscription_key'],one)
        two=self.store.activate(self.who,'herdr.turn.completed',{'subject_key':'agent'},'https://two.example.test/events','secret',3600)['id']
        self.store.db.execute("INSERT INTO deliveries(event,sub,epoch,state) VALUES('event',?,1,'accepted')",(two,))
        with self.assertRaisesRegex(Rejected,'subscription_key_required'):self.store.receipt(self.who,'event','','started','observed')
        with self.assertRaisesRegex(Rejected,'forbidden_scope'):self.store.receipt('other','event','','started','observed')

    async def test_injected_prompt_keeps_same_line(self):
        prompts=[]
        self.assertEqual(await ask_live('Consent? [y/N]: ',lambda prompt:prompts.append(prompt) or 'y'),'y')
        self.assertEqual(prompts,['Consent? [y/N]: '])

    async def test_terminal_prompt_prints_without_newline(self):
        read_fd,write_fd=os.pipe();os.write(write_fd,b'y\n');os.close(write_fd)
        with os.fdopen(read_fd) as stream,patch('sys.stdin',stream),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(await ask_live('Consent? [y/N]: '),'y\n')
        self.assertEqual(output.getvalue(),'Consent? [y/N]: ')

    async def test_ctrl_c_saves_and_exits_130(self):
        lines=[]
        def ask(prompt):return 'y'
        async def interrupted(_):raise asyncio.CancelledError
        with patch('dot_herdr.connection_check.asyncio.sleep',side_effect=interrupted):
            with self.assertRaises(SystemExit) as stopped:await check_connection(self.config,ask=ask,say=lines.append)
        self.assertEqual(stopped.exception.code,130)
        self.assertEqual(lines[-1],'Stopped. Run dot-herdr check-connection again to resume this test.')
        self.assertEqual(connection_record(self.config)['check']['status'],'pending')

    async def simulate(self,*,control=True,receipt=True,stop=True,unknown=False,count=1,watch_subject='agent',choice=None):
        clock=[1000000.0];answers=[];output=[];subs=[];did=[False]
        self.run_number+=1;run=self.run_number
        self.store.clock=lambda:clock[0]
        def ask(prompt):
            answers.append(prompt)
            if 'Send it one harmless' in prompt:return 'y'
            if 'Which watch' in prompt:return choice or ''
            if 'Stop it here' in prompt:return 'y'
            if 'Does your ChatGPT chat' in prompt:return 'y'
            raise AssertionError(prompt)
        async def sleep(_):
            clock[0]+=1
            if did[0]:return
            did[0]=True
            record=connection_record(self.config)
            record['verified_client_scopes']={'client':{'scopes':['herdr:control'] if control else ['herdr:read'],'verified_at':clock[0],'expires_at':clock[0]+3600}}
            save_connection(self.config,record)
            if not control:return
            check=record['check']
            for i in range(count):subs.append(self.store.activate(self.who,'herdr.turn.completed',{'subject_key':watch_subject},f'https://callback{run}-{i}.example.test/events','secret',3600)['id'])
            self.store.begin_action(self.who,check['request_id'],{'synthetic':'nonce'})
            if unknown:return
            self.store.finish_action(self.who,check['request_id'],{'outcome':'submitted'})
            event=f'event-{run}'
            self.store.db.execute("INSERT INTO events(id,subject,name,body,at) VALUES(?,'agent','herdr.turn.completed','{}',?)",(event,clock[0]+1))
            if count and watch_subject=='agent':
                self.store.db.execute("INSERT INTO deliveries(event,sub,epoch,state) VALUES(?,?,1,'accepted')",(event,subs[0]))
                if receipt:self.store.db.execute("INSERT INTO receipts VALUES(?,?,'finished','{}',?)",(subs[0],event,clock[0]+1))
                if stop:self.store.unsubscribe(self.who,'herdr.turn.completed',{'subject_key':'agent'},f'https://callback{run}-0.example.test/events')
        with patch('dot_herdr.connection_check.time.time',side_effect=lambda:clock[0]),patch('dot_herdr.connection_check.asyncio.sleep',side_effect=sleep):
            result=await check_connection(self.config,ask=ask,say=output.append)
        return result,answers,output,subs

    async def test_happy_path_two_questions_and_live_progress(self):
        check,prompts,lines,subs=await self.simulate()
        self.assertEqual(check['status'],'complete',check['phases'])
        self.assertEqual(len(prompts),2,prompts)
        self.assertEqual(check['subscription_id'],subs[0])
        self.assertEqual([line for line in lines if line.startswith('  ✓')],['  ✓ ChatGPT connected as user (control allowed)','  ✓ Watch created','  ✓ Message sent to the test agent','  ✓ Test agent replied','  ✓ Event delivered to ChatGPT','  ✓ ChatGPT handled the event','  ✓ Watch stopped by ChatGPT'])
        self.assertEqual(lines[-1],'Connection check passed.')
        instruction=lines[lines.index('-'*64)+1]
        self.assertEqual(instruction,test_instruction(check));self.assertIn('subscription_key \\"\\"',instruction)

    async def test_control_missing_saved_pending(self):
        check,prompts,lines,_=await self.simulate(control=False)
        self.assertEqual(check['phase'],'control_scope');self.assertEqual(check['status'],'pending')
        self.assertEqual(connection_record(self.config)['check']['phase'],'control_scope')
        self.assertTrue(any(line.startswith('✗') and 'tool access' in line for line in lines))

    async def test_unknown_action_no_new_submission(self):
        check,_,lines,_=await self.simulate(unknown=True)
        self.assertEqual(check['phase'],'source_submission');self.assertTrue(any('check-recovery --recovery inspect' in line for line in lines))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM actions').fetchone()[0],1)

    async def test_receipt_missing_still_asks_destination(self):
        check,prompts,lines,_=await self.simulate(receipt=False)
        self.assertEqual(check['status'],'incomplete');self.assertEqual(len(prompts),2)
        self.assertIn('Connection check incomplete: ChatGPT did not record handling',lines[-1])

    async def test_two_watches_enter_binds_and_fences_nothing(self):
        check,prompts,lines,subs=await self.simulate(count=2,stop=False)
        self.assertEqual(len(prompts),2);self.assertIn('Which watch',prompts[1])
        self.assertNotIn('subscription_id',check)
        self.assertEqual(fence_test_watch(self.cfg,check),'no_test_watch')
        self.assertEqual([self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0] for sub in subs],[1,1])

    async def test_host_did_not_stop_connector_fences_bound_watch(self):
        check,prompts,lines,subs=await self.simulate(stop=False)
        self.assertIn('Stop it here?',prompts[1]);self.assertEqual(check['fence_result'],'connector_fenced')
        self.assertEqual(check['phases']['unsubscribe'],'connector_fenced')
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(subs[0],)).fetchone()[0],0)
        self.assertIn('  ✓ Watch stopped here',lines)

    async def test_completed_check_starts_new_id_keeps_history(self):
        first,_,_,_=await self.simulate()
        second,_,_,_=await self.simulate()
        self.assertNotEqual(first['request_id'],second['request_id'])
        self.assertEqual(second['history'][0]['request_id'],first['request_id'])

    async def test_stale_known_action_starts_new_id(self):
        self.store.clock=lambda:999100.0
        old={'target':'agent','watch_event':'herdr.turn.completed','nonce':'old-nonce','request_id':'connection-check-old-known','started_at':999000.0,'status':'pending','phases':{p:'pending' for p in ('authenticated_read','source_submission','source_response','event_capture','callback_verification','transport_acceptance','triage_report','destination_confirmation','unsubscribe','no_further_delivery')},'prior_watch_ids':[]}
        record=connection_record(self.config);record['check']=old;save_connection(self.config,record)
        self.store.begin_action(self.who,old['request_id'],{'synthetic':'old'});self.store.finish_action(self.who,old['request_id'],{'outcome':'submitted'})
        async def interrupted(_):raise asyncio.CancelledError
        with patch('dot_herdr.connection_check.time.time',return_value=1000000.0),patch('dot_herdr.connection_check.asyncio.sleep',side_effect=interrupted):
            with self.assertRaises(SystemExit):await check_connection(self.config,ask=lambda _: 'y',say=lambda _:None)
        new=connection_record(self.config)['check']
        self.assertNotEqual(new['request_id'],old['request_id']);self.assertEqual(new['history'][0]['request_id'],old['request_id'])

    async def test_other_subject_watch_is_not_candidate(self):
        other={**self.cfg['subjects'][0],'key':'other','pane':'other-pane','terminal':'other-terminal'}
        self.cfg['subjects'].append(other)
        self.store.apply_roster([{**s,'principal':self.who} for s in self.cfg['subjects']])
        self.store.clock=lambda:1000001.0
        sub=self.store.activate(self.who,'herdr.turn.completed',{'subject_key':'other'},'https://other.example.test/events','secret',3600)['id']
        with patch('dot_herdr.connection_check.time.time',return_value=1000001.0):
            self.assertEqual(candidate_watches(self.cfg,{'target':'agent','watch_event':'herdr.turn.completed','request_id':'new','started_at':1000000.0,'prior_watch_ids':[]}),[])
        self.assertEqual(self.store.db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0],1)

    async def test_unknown_previous_request_is_not_replayed(self):
        first,_,_,_=await self.simulate(unknown=True)
        second,prompts,lines,_=await self.simulate()
        self.assertEqual(first['request_id'],second['request_id'])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM actions').fetchone()[0],1)
        self.assertTrue(any('check-recovery --recovery inspect' in line for line in lines))
