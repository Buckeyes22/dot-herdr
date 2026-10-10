import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx2
from mcp.server.auth.provider import AccessToken
from dot_herdr.access import apply_access,configure_access,rebind_keys,roster
from dot_herdr.core import Rejected,Store
from dot_herdr.endpoint import build


class Source:
    async def request(self,method,params):
        if method=='ping':return {'version':'0.9.3','protocol':22}
        if method=='agent.list':return {'agents':[{'agent':'codex','pane_id':'pane','terminal_id':'terminal','agent_session':None}]}
        raise AssertionError('unexpected source request')
    async def agent(self,pane):return {'agent':'codex','pane_id':pane,'terminal_id':'terminal','agent_session':None,'revision':1}
    async def visible(self,pane,lines):return {'text':'synthetic visible context','revision':0,'truncated':False}


class Verifier:
    async def verify_token(self,token):
        if token!='observer':return None
        return AccessToken(token=token,client_id='test',subject='account',resource='https://resource.example.test/mcp',scopes=['herdr:observe'],claims={'iss':'https://issuer.example.test'})


class AccessSessionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        state=self.root/'state';state.mkdir(mode=0o700)
        self.sockets=[self.root/'old.sock',self.root/'new.sock'];self.listeners=[]
        for path in self.sockets:
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));self.listeners.append(listener)
        self.path=self.root/'config.json'
        self.cfg={'store':str(state/'connector.sqlite'),'socket':str(self.sockets[0]),'issuer':'https://issuer.example.test',
                  'resource':'https://resource.example.test/mcp','public_key':str(self.root/'public.pem'),
                  'subjects':[{'key':'old','user_subject':'account','owner':'operator','pane':'pane','terminal':'terminal','native':None,'content':True,'control':False}],
                  'session_users':[]}
        self.path.write_text(json.dumps(self.cfg));self.path.chmod(0o600)
        store=Store(self.cfg['store']);store.apply_roster(roster(self.cfg));store.close()
    def tearDown(self):
        for listener in self.listeners:listener.close()
        self.temp.cleanup()
    def sessions(self):return [{'running':True,'name':'Old','socket_path':str(self.sockets[0])},{'running':True,'name':'New','socket_path':str(self.sockets[1])}]
    def watch(self):
        store=Store(self.cfg['store']);principal=roster(self.cfg)[0]['principal']
        store.observe('old',{'pane_id':'pane','terminal_id':'terminal','agent_status':'idle','revision':1})
        store.observe('old',{'pane_id':'pane','terminal_id':'terminal','agent_status':'blocked','revision':2})
        event=store.db.execute("SELECT id FROM events WHERE subject='old' ORDER BY seq LIMIT 1").fetchone()[0]
        watch=store.activate(principal,'herdr.attention.detected',{'subject_key':'old'},'https://callback.example.test/events','secret')['id']
        store.begin_action(principal,'original-request',{'method':'agent.prompt'});store.close()
        return principal,event,watch
    async def rpc(self,name,args):
        store=Store(self.cfg['store']);source=Source()
        try:
            server=build(store,source,None,Verifier(),self.cfg['issuer'],self.cfg['resource'],controls=set(),session_users=set())
            app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
            async with app.router.lifespan_context(app):
                async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000',trust_env=False) as client:
                    response=await client.post('/mcp',headers={'Authorization':'Bearer observer','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':'tools/call','Mcp-Name':name},
                        json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args,'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}})
                    self.assertEqual(response.status_code,200,response.text)
                    return response.json()['result']
        finally:store.close()
    async def test_content_revocation_blocks_later_read_and_observer_cannot_write(self):
        visible={'subject_key':'old','expected_generation':1}
        self.assertIn('synthetic visible context',(await self.rpc('read_visible_context',visible))['structuredContent']['text'])
        denied=await self.rpc('send_agent_message',{**visible,'request_id':'no-write','text':'hello'})
        self.assertTrue(denied['isError'])
        changed=copy.deepcopy(self.cfg);changed['subjects'][0]['content']=False
        apply_access(self.path,changed,self.path.read_bytes())
        result=await self.rpc('read_visible_context',visible)
        self.assertTrue(result['isError'])
        self.assertNotIn('synthetic visible context',json.dumps(result))
    async def test_switch_requires_approval_then_fences_old_identity(self):
        principal,event,watch=self.watch();messages=[]
        with patch('dot_herdr.onboarding.running_sessions',side_effect=self.sessions):
            answers=iter(['2','2','1','1','n','n'])
            result=await configure_access(self.path,ask=lambda _:next(answers),say=messages.append,client_factory=lambda _:Source())
        self.assertEqual(result['status'],'cancelled');self.assertEqual(json.loads(self.path.read_text())['socket'],str(self.sockets[0]))
        store=Store(self.cfg['store']);self.assertTrue(store.db.execute('SELECT active FROM subscriptions WHERE id=?',(watch,)).fetchone()[0]);store.close()
        with patch('dot_herdr.onboarding.running_sessions',side_effect=self.sessions):
            answers=iter(['2','2','1','1','n','y'])
            result=await configure_access(self.path,ask=lambda _:next(answers),say=messages.append,client_factory=lambda _:Source())
        changed=json.loads(self.path.read_text());self.assertEqual(result['status'],'saved');self.assertEqual(changed['socket'],str(self.sockets[1]))
        self.assertNotEqual(changed['subjects'][0]['key'],'old');self.assertFalse(changed['subjects'][0]['control']);self.assertFalse(changed['subjects'][0]['content'])
        store=Store(self.cfg['store'])
        try:
            self.assertFalse(store.db.execute("SELECT enabled FROM subjects WHERE key='old'").fetchone()[0])
            self.assertFalse(store.db.execute('SELECT active FROM subscriptions WHERE id=?',(watch,)).fetchone()[0])
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM events WHERE id=?',(event,)).fetchone()[0],1)
            with self.assertRaisesRegex(Rejected,'forbidden_scope'):store.event(principal,event)
            self.assertEqual(store.begin_action(principal,'original-request',{'method':'agent.prompt'})['request_id'],'original-request')
            self.assertEqual(store.subject(principal,changed['subjects'][0]['key'])['pane'],'pane')
        finally:store.close()
        self.assertTrue(any('Previous session grants will be revoked' in line for line in messages))
    async def test_missing_saved_socket_offers_running_session(self):
        self.listeners[0].close();self.sockets[0].unlink();messages=[]
        with patch('dot_herdr.onboarding.running_sessions',return_value=[self.sessions()[1]]):
            answers=iter(['1','1','n','y'])
            await configure_access(self.path,ask=lambda _:next(answers),say=messages.append,client_factory=lambda _:Source())
        changed=json.loads(self.path.read_text());self.assertEqual(changed['socket'],str(self.sockets[1]))
        self.assertNotEqual(changed['subjects'][0]['key'],'old')
        self.assertTrue(any('saved Herdr session is gone' in line for line in messages))
    async def test_unresponsive_saved_socket_offers_reselection(self):
        class Unresponsive(Source):
            async def request(self,method,params):
                if method=='ping':raise OSError('synthetic stopped session')
                return await super().request(method,params)
        with patch('dot_herdr.onboarding.running_sessions',return_value=[self.sessions()[1]]):
            answers=iter(['1','1','1','n','y'])
            await configure_access(self.path,ask=lambda _:next(answers),say=lambda _:None,
                                   client_factory=lambda selected:Unresponsive() if selected==str(self.sockets[0]) else Source())
        self.assertEqual(json.loads(self.path.read_text())['socket'],str(self.sockets[1]))
    async def test_noninteractive_requires_complete_explicit_choice(self):
        with self.assertRaisesRegex(Rejected,'noninteractive_access_requires'):
            await configure_access(self.path,interactive=False,ask=lambda _:self.fail('prompt'),say=lambda _:None,client_factory=lambda _:Source())
        await configure_access(self.path,interactive=False,user_subject='account',socket_path=str(self.sockets[1]),mode='1',agent_numbers='1',content=False,approve=True,
                               ask=lambda _:self.fail('prompt'),say=lambda _:None,client_factory=lambda _:Source())
        self.assertEqual(json.loads(self.path.read_text())['socket'],str(self.sockets[1]))
    async def test_interactive_explicit_flags_skip_selection_prompts(self):
        await configure_access(self.path,user_subject='account',socket_path=str(self.sockets[1]),mode='1',agent_numbers='1',content=False,approve=True,
                               ask=lambda _:self.fail('all choices supplied'),say=lambda _:None,client_factory=lambda _:Source())
        changed=json.loads(self.path.read_text());self.assertEqual(changed['socket'],str(self.sockets[1]));self.assertFalse(changed['subjects'][0]['content'])
    async def test_explicit_reselection_of_same_socket_fences_old_watch(self):
        _,_,watch=self.watch()
        await configure_access(self.path,interactive=False,user_subject='account',socket_path=str(self.sockets[0]),reselect_session=True,mode='1',agent_numbers='1',content=False,approve=True,
                               ask=lambda _:self.fail('prompt'),say=lambda _:None,client_factory=lambda _:Source())
        changed=json.loads(self.path.read_text());self.assertNotEqual(changed['subjects'][0]['key'],'old')
        store=Store(self.cfg['store'])
        try:self.assertFalse(store.db.execute('SELECT active FROM subscriptions WHERE id=?',(watch,)).fetchone()[0])
        finally:store.close()
    def test_initialized_expansion_reduction_removal_replacement_and_reenable(self):
        principal,event,watch=self.watch();second=dict(self.cfg['subjects'][0],pane='second',terminal='second-terminal',content=False)
        expanded=copy.deepcopy(self.cfg);expanded['subjects'].append(rebind_keys([second],self.cfg['subjects'])[0])
        apply_access(self.path,expanded,self.path.read_bytes())
        store=Store(self.cfg['store']);self.assertEqual(len(store.db.execute('SELECT key FROM subjects WHERE enabled=1').fetchall()),2);store.close()
        reduced=copy.deepcopy(expanded);reduced['subjects'][0]['content']=False;reduced['subjects']=[reduced['subjects'][0]]
        apply_access(self.path,reduced,self.path.read_bytes())
        store=Store(self.cfg['store'])
        try:self.assertFalse(store.subject(principal,'old')['content']);self.assertFalse(store.db.execute('SELECT enabled FROM subjects WHERE key=?',(expanded['subjects'][1]['key'],)).fetchone()[0])
        finally:store.close()
        replaced=copy.deepcopy(reduced);replaced['subjects']=rebind_keys([dict(reduced['subjects'][0],terminal='replacement')],reduced['subjects'])
        apply_access(self.path,replaced,self.path.read_bytes())
        inactive=copy.deepcopy(replaced);inactive.update(subjects=[],session_users=[],inactive=True,access_accounts=['account'])
        apply_access(self.path,inactive,self.path.read_bytes())
        reenabled=copy.deepcopy(inactive);reenabled.pop('inactive');reenabled['subjects']=replaced['subjects']
        apply_access(self.path,reenabled,self.path.read_bytes())
        store=Store(self.cfg['store'])
        try:
            self.assertFalse(store.db.execute('SELECT active FROM subscriptions WHERE id=?',(watch,)).fetchone()[0])
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM events WHERE id=?',(event,)).fetchone()[0],1)
            self.assertEqual(store.begin_action(principal,'original-request',{'method':'agent.prompt'})['request_id'],'original-request')
            with self.assertRaisesRegex(Rejected,'forbidden_scope'):store.subject(principal,'old')
            self.assertTrue(store.subject(principal,replaced['subjects'][0]['key']))
        finally:store.close()
