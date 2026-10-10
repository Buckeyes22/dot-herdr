import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx2
from mcp.server.auth.provider import AccessToken
from dot_herdr.actions import READ_METHODS, WRITE_METHODS, prepare
from dot_herdr.core import Store, Rejected
from dot_herdr.endpoint import build, principal_key
from dot_herdr.herdr import HerdrClient

ISSUER='https://auth.example.invalid'
RESOURCE='https://connector.example.invalid/mcp'
USER=principal_key(ISSUER,'user-demo')


def agent(status='idle'):
    return {'pane_id':'pane_demo','terminal_id':'terminal_demo','revision':1,'agent':'codex',
            'agent_status':status,'completion_seq':0}


class Source:
    def __init__(self):self.current=agent();self.calls=[];self.failure=None;self.on_agent=None
    async def agent(self,pane):
        if self.on_agent:self.on_agent()
        return dict(self.current)
    async def request(self,method,params):
        self.calls.append((method,params))
        await asyncio.sleep(0)
        if self.failure:raise self.failure
        return {'type':'agent_prompted','agent':{**self.current,'title':'private-title','tokens':{'secret':'private-token'}}}


class Verifier:
    async def verify_token(self,token):
        if token not in ('user','observer','other'):return None
        return AccessToken(token=token,client_id='demo-client',subject='other' if token=='other' else 'user-demo',
                           resource=RESOURCE,scopes=['herdr:observe']+(['herdr:control'] if token=='user' else []),claims={'iss':ISSUER})


class ActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'connector.sqlite'
        self.store=Store(self.path);self.store.enroll('demo',USER,'owner','pane_demo','terminal_demo',content=True)
        self.source=Source();self.controls={'demo'};self.session_users={USER}
    def tearDown(self):self.store.close();self.temp.cleanup()
    async def rpc(self,name,args,token='user'):
        server=build(self.store,self.source,None,Verifier(),ISSUER,RESOURCE,controls=self.controls,session_users=self.session_users)
        app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000',trust_env=False) as client:
                r=await client.post('/mcp',headers={'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':'tools/call','Mcp-Name':name},json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args,'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}})
                self.assertEqual(r.status_code,200,r.text)
                return r.json()['result']
    def args(self,request='first',**extra):return {'subject_key':'demo','expected_generation':1,'request_id':request,**extra}
    async def test_enrolled_message_interactive_input_keys_rename_focus(self):
        response=await self.rpc('send_agent_message',self.args(text='Fix the test and rerun it'))
        self.assertEqual(response['structuredContent']['outcome'],'submitted')
        self.assertEqual(self.source.calls[-1],('agent.prompt',{'target':'pane_demo','text':'Fix the test and rerun it'}))
        self.assertNotIn('private-token',json.dumps(response));self.assertNotIn('private-title',json.dumps(response))
        self.source.current=agent('blocked')
        for name,args,method in (
            ('send_agent_keys',self.args('keys',keys=['esc']),'agent.send_keys'),
            ('send_agent_input',self.args('answer',text='Use MIT',keys=['enter']),'pane.send_input'),
            ('rename_agent',self.args('rename',name='reviewer'),'agent.rename'),
            ('focus_agent',self.args('focus'),'agent.focus')):
            result=await self.rpc(name,args);self.assertFalse(result.get('isError',False),result)
            self.assertEqual(self.source.calls[-1][0],method)
        row=self.store.db.execute('SELECT * FROM actions WHERE request_id=?',('first',)).fetchone()
        self.assertNotIn('Fix the test',json.dumps(dict(row)))
    async def test_scope_grant_identity_and_blocked_checks_before_write(self):
        for token in ('observer','other'):
            self.assertTrue((await self.rpc('send_agent_message',self.args(text='hello'),token))['isError'])
        self.controls=set()
        self.assertTrue((await self.rpc('send_agent_message',self.args(text='hello')))['isError'])
        self.controls={'demo'}
        self.assertTrue((await self.rpc('send_agent_message',{**self.args(text='hello'),'expected_generation':2}))['isError'])
        self.source.current['terminal_id']='replacement'
        self.assertTrue((await self.rpc('send_agent_message',self.args(text='hello')))['isError'])
        self.source.current=agent('blocked')
        self.assertTrue((await self.rpc('send_agent_message',self.args(text='hello')))['isError'])
        self.source.current={**agent(),'agent':None}
        self.assertTrue((await self.rpc('send_agent_input',self.args(text='shell command',keys=['enter'])))['isError'])
        self.source.current=agent();self.source.on_agent=lambda:self.store.sync_roster(set())
        self.assertTrue((await self.rpc('send_agent_message',self.args(text='hello')))['isError'])
        self.assertEqual(self.source.calls,[])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM actions').fetchone()[0],0)
    async def test_native_identity_mismatch_rejects(self):
        native={'source':'hook','agent':'codex','kind':'id','value':'session-one'}
        self.store.enroll('native',USER,'owner','pane_demo','terminal_demo',native,True);self.controls.add('native')
        response=await self.rpc('send_agent_keys',{**self.args(keys=['enter']),'subject_key':'native'})
        self.assertTrue(response['isError']);self.assertEqual(self.source.calls,[])
    async def test_exact_retry_conflict_and_restart_dedupe(self):
        args=self.args(text='One instruction')
        first=await self.rpc('send_agent_message',args)
        self.assertEqual(await self.rpc('send_agent_message',args),first)
        self.assertTrue((await self.rpc('send_agent_message',{**args,'text':'Different instruction'}))['isError'])
        self.store.close();self.store=Store(self.path)
        self.assertEqual(await self.rpc('send_agent_message',args),first)
        self.assertEqual(len(self.source.calls),1)
        self.store.sync_roster(set())
        self.assertTrue((await self.rpc('send_agent_message',args))['isError'])
    async def test_concurrent_duplicate_input_only_submitted_once(self):
        args=self.args(text='Only once')
        a,b=await asyncio.gather(self.rpc('send_agent_message',args),self.rpc('send_agent_message',args))
        self.assertEqual(len(self.source.calls),1)
        self.assertIn('submitted',[r['structuredContent']['outcome'] for r in (a,b)])
    async def test_unknown_outcome_never_retries_after_restart(self):
        self.source.failure=TimeoutError()
        args=self.args(text='Potentially delivered')
        response=await self.rpc('send_agent_message',args)
        self.assertEqual(response['structuredContent']['outcome'],'unknown')
        self.assertEqual(response['structuredContent']['retry'],'inspect_source_do_not_resubmit')
        self.store.close();self.store=Store(self.path);self.source.failure=None
        self.assertEqual(await self.rpc('send_agent_message',args),response)
        self.assertEqual(len(self.source.calls),1)
    async def test_crash_window_already_recorded_unknown_never_submits(self):
        operation={'subject_key':'demo','generation':1,'method':'agent.prompt','params':{'target':'pane_demo','text':'hello'}}
        self.assertIsNone(self.store.begin_action(USER,'first',operation))
        self.store.close();self.store=Store(self.path)
        response=await self.rpc('send_agent_message',self.args(text='hello'))
        self.assertEqual(response['structuredContent']['outcome'],'unknown');self.assertEqual(self.source.calls,[])
    async def test_session_access_actions_discovery_and_rejections(self):
        queries=await self.rpc('herdr_query',{'method':'agent.list','params':{}})
        self.assertFalse(queries.get('isError',False));self.assertEqual(self.source.calls[-1],('agent.list',{}))
        for method,params in (
            ('pane.split',{'target_pane_id':'pane_demo','direction':'right','cwd':'/tmp/demo','focus':False}),
            ('agent.start',{'pane_id':'new-pane','name':'reviewer','kind':'codex'}),
            ('pane.send_input',{'pane_id':'shell-pane','text':'python -m unittest','keys':['enter']}),
            ('workspace.move_block',{'workspace_ids':['w1','w2']})):
            r=await self.rpc('herdr_action',{'method':method,'params':params,'request_id':method})
            self.assertEqual(r['structuredContent']['outcome'],'submitted')
            self.assertEqual(self.source.calls[-1][0],method)
        count=len(self.source.calls)
        for method,params in (('client_shell.surface.set',{}),('pane.close',{}),('pane.split',{'target_pane_id':'pane_demo','direction':'right'}),('agent.prompt',{'target':'pane_demo','text':'hello','unexpected':True})):
            self.assertTrue((await self.rpc('herdr_action',{'method':method,'params':params,'request_id':'reject'+method}))['isError'])
        self.session_users=set()
        self.assertTrue((await self.rpc('herdr_query',{'method':'agent.list','params':{}}))['isError'])
        self.assertTrue((await self.rpc('herdr_action',{'method':'pane.close','params':{'pane_id':'pane_demo'},'request_id':'close'}))['isError'])
        self.assertEqual(len(self.source.calls),count)
    async def test_capabilities_and_live_wait(self):
        r=(await self.rpc('get_herdr_capabilities',{}))['structuredContent']
        self.assertTrue(r['session_access']);self.assertTrue(r['control_scope'])
        self.assertEqual(set(r['session_queries']),set(READ_METHODS));self.assertEqual(set(r['session_actions']),set(WRITE_METHODS))
        self.assertEqual(r['subjects'],[{'subject_key':'demo','control':True}])
        r=await self.rpc('get_live_agent_state',{'subject_key':'demo','expected_generation':1})
        self.assertEqual(r['structuredContent']['freshness'],'current_read')
        r=await self.rpc('wait_for_agent',{'subject_key':'demo','expected_generation':1,'timeout_ms':100})
        self.assertFalse(r.get('isError',False));self.assertEqual(self.source.calls[-1][1]['timeout_ms'],100)
        self.assertTrue((await self.rpc('wait_for_agent',{'subject_key':'demo','expected_generation':1,'timeout_ms':0}))['isError'])

    async def test_optional_control_scope_metadata_and_tool_annotations(self):
        server=build(self.store,self.source,None,Verifier(),ISSUER,RESOURCE,controls=self.controls,session_users=self.session_users)
        tools={t.name:t for t in await server.list_tools()}
        self.assertEqual(set(tools['herdr_query'].input_schema['properties']['method']['enum']),set(READ_METHODS))
        self.assertEqual(set(tools['herdr_action'].input_schema['properties']['method']['enum']),set(WRITE_METHODS))
        self.assertFalse(tools['send_agent_message'].annotations.read_only_hint)
        self.assertTrue(tools['send_agent_message'].annotations.idempotent_hint)
        self.assertTrue(tools['herdr_query'].annotations.read_only_hint)
        app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000',trust_env=False) as client:
                response=await client.get('/.well-known/oauth-protected-resource/mcp')
                self.assertEqual(response.status_code,200)
                self.assertEqual(response.json()['scopes_supported'],['herdr:observe','herdr:control'])
        self.assertTrue((await self.rpc('get_herdr_capabilities',{},token='observer'))['structuredContent']['session_access'])
        denied=await self.rpc('send_agent_keys',self.args(keys=['esc']),token='observer')
        self.assertIn('control_scope_required',json.dumps(denied));self.assertIn('Also allow Herdr control',json.dumps(denied));self.assertEqual(self.source.calls,[])


class ParameterTests(unittest.TestCase):
    def test_explicit_targets_bounded_waits_and_control_text(self):
        for method,p in (
            ('agent.wait',{'target':'a','timeout_ms':None}),
            ('agent.wait',{'target':'a','timeout_ms':30001}),
            ('agent.start',{'pane_id':'p','kind':'codex','name':'a','timeout_ms':3000}),
            ('pane.send_input',{'pane_id':'p','text':'\x1b[1A'}),
            ('agent.prompt',{'target':'a','text':'hello','wait':{}}),
            ('agent.send_keys',{'target':'a','keys':[]}),
            ('tab.create',{'cwd':'/tmp'}),
            ('layout.apply',{'root':{}}),
            ('workspace.move_block',{'workspace_ids':[]})):
            with self.subTest(method=method,params=p),self.assertRaises(Rejected):prepare(method,p)
        self.assertEqual(prepare('agent.wait',{'target':'a'})['timeout_ms'],10000)
        self.assertEqual(prepare('agent.start',{'pane_id':'p','kind':'codex','name':'a'})['timeout_ms'],30000)


class WireTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_unix_socket_prompt_keys_and_error_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            path=str(Path(temp)/'synthetic.sock');received=[]
            async def handle(reader,writer):
                request=json.loads(await reader.readline());received.append(request)
                response={'id':request['id'],'result':{'type':'agent_prompted','agent':agent()}}
                if request['method']=='agent.send_keys':response={'id':request['id'],'error':{'code':'agent_not_ready','message':'private secret should not leak'}}
                writer.write((json.dumps(response)+'\n').encode());await writer.drain();writer.close();await writer.wait_closed()
            server=await asyncio.start_unix_server(handle,path)
            async with server:
                client=HerdrClient(path)
                self.assertEqual((await client.request('agent.prompt',{'target':'pane_demo','text':'hello'}))['type'],'agent_prompted')
                with self.assertRaisesRegex(Rejected,'^agent_not_ready$'):await client.request('agent.send_keys',{'target':'pane_demo','keys':['esc']})
                with self.assertRaises(Rejected):await client.request('client_shell.surface.set',{})
            self.assertEqual(len(received),2)
            self.assertEqual(received[0]['params'],{'target':'pane_demo','text':'hello'})
