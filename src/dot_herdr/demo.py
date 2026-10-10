"""Credential-free synthetic SDK demonstration, entirely in process and temporary."""
import base64
import hashlib
import hmac
import json
import tempfile
from pathlib import Path
import httpx2
from mcp.server.auth.provider import AccessToken
from .core import Store,NAMES
from .endpoint import build,principal_key
from .webhooks import deliver_one

ISSUER='https://auth.example.invalid'
RESOURCE='https://connector.example.invalid/mcp'
SECRET='whsec_'+base64.b64encode(b's'*32).decode()

class SyntheticVerifier:
    async def verify_token(self,token):
        if token!='synthetic-demo-token':return None
        return AccessToken(token=token,client_id='demo-client',subject='demo-user',resource=RESOURCE,
                           scopes=['herdr:observe','herdr:control'],claims={'iss':ISSUER})

class SyntheticSource:
    current={'terminal_id':'demo-terminal','pane_id':'demo-pane','agent':'codex','agent_status':'working','revision':1,'state_change_seq':1,'completion_seq':0}
    def __init__(self):self.actions=[]
    async def agent(self,pane):return dict(self.current)
    async def visible(self,pane,lines):
        return {'text':'Synthetic review needed: choose A or B.','revision':0,'source':'visible','truncated':False}
    async def request(self,method,params):
        if method not in ('pane.send_input','agent.prompt'):raise AssertionError('demo_unexpected_action')
        self.actions.append((method,params))
        self.current={**self.current,'agent_status':'idle' if method=='pane.send_input' else 'working',
                      'revision':self.current['revision']+1,'state_change_seq':self.current['state_change_seq']+1}
        return {'type':'input_submitted','agent':dict(self.current)}

class InProcessCallback:
    def __init__(self):self.application=[]
    async def post(self,url,body,hs):
        # No HTTP client, DNS lookup, socket or external endpoint exists in this transport.
        prefix=(hs['webhook-id']+'.'+hs['webhook-timestamp']+'.').encode()
        signature='v1,'+base64.b64encode(hmac.new(b's'*32,prefix+body,hashlib.sha256).digest()).decode()
        if not hmac.compare_digest(hs['webhook-signature'],signature):raise AssertionError('demo_signature_failure')
        value=json.loads(body)
        if value.get('type')=='verification':return 200,json.dumps({'challenge':value['challenge']}).encode()
        if value['eventId']!=hs['webhook-id']:raise AssertionError('demo_id_failure')
        self.application.append(value);return 202,b'{}'

async def demo():
    with tempfile.TemporaryDirectory(prefix='dot-herdr-demo-') as directory:
        clock=lambda:2000000000
        store=Store(Path(directory).resolve()/'journal.sqlite',clock)
        try:
            who=principal_key(ISSUER,'demo-user')
            store.enroll('demo-parent',who,'demo-owner','demo-pane','demo-terminal',content=True)
            source=SyntheticSource();callback=InProcessCallback()
            server=build(store,source,callback,SyntheticVerifier(),ISSUER,RESOURCE,controls={'demo-parent'})
            app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
            async with app.router.lifespan_context(app):
                async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000',trust_env=False) as client:
                    async def rpc(method,params):
                        meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}
                        hs={'Authorization':'Bearer synthetic-demo-token','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method}
                        if method=='tools/call':hs['Mcp-Name']=params['name']
                        response=await client.post('/mcp',headers=hs,json={'jsonrpc':'2.0','id':1,'method':method,'params':{**params,'_meta':meta}})
                        response.raise_for_status();value=response.json()
                        if 'error' in value or value.get('result',{}).get('isError'):raise AssertionError('demo_rpc_failure')
                        return value['result']
                    discovery=await rpc('server/discover',{})
                    if 'events' not in discovery['capabilities']:raise AssertionError('demo_discovery_failure')
                    catalog=await rpc('events/list',{})
                    delivery={'mode':'webhook','url':'https://callback.example.invalid/demo','secret':SECRET}
                    sub=await rpc('events/subscribe',{'name':NAMES[0],'arguments':{'subject_key':'demo-parent'},'delivery':delivery})
                    store.observe('demo-parent',source.current)
                    source.current={**source.current,'agent_status':'blocked','revision':2,'state_change_seq':2}
                    store.observe('demo-parent',source.current)
                    await deliver_one(store,callback)
                    if len(callback.application)!=1:raise AssertionError('demo_wake_failure')
                    event=callback.application[0]
                    state=await rpc('tools/call',{'name':'get_agent_state','arguments':{'subject_key':'demo-parent'}})
                    context=await rpc('tools/call',{'name':'read_visible_context','arguments':{'subject_key':'demo-parent','expected_generation':1}})
                    reply_params={'name':'send_agent_input','arguments':{'subject_key':'demo-parent','expected_generation':1,'request_id':'demo-reply','text':'A','keys':['enter']}}
                    reply=await rpc('tools/call',reply_params)
                    duplicate=await rpc('tools/call',reply_params)
                    if duplicate!=reply or len(source.actions)!=1:raise AssertionError('demo_duplicate_input')
                    live=await rpc('tools/call',{'name':'get_live_agent_state','arguments':{'subject_key':'demo-parent','expected_generation':1}})
                    message=await rpc('tools/call',{'name':'send_agent_message','arguments':{'subject_key':'demo-parent','expected_generation':1,'request_id':'demo-follow-up','text':'Report the result of the selected option.'}})
                    receipt=await rpc('tools/call',{'name':'record_triage_receipt','arguments':{'event_id':event['eventId'],'subscription_key':sub['id'],'phase':'finished','disposition':'detail_reviewed'}})
                    await rpc('events/unsubscribe',{'name':NAMES[0],'arguments':{'subject_key':'demo-parent'},'delivery':{'mode':'webhook','url':delivery['url']}})
                    return {'demo':'passed','mode':'synthetic_in_process','events_advertised':len(catalog['events']),
                            'signed_application_callbacks':len(callback.application),'state':state['structuredContent']['state']['agent_status'],
                            'context':context['structuredContent']['text'],'receipt':receipt['structuredContent']['disposition'],
                            'interactive_reply':reply['structuredContent']['outcome'],'follow_up_message':message['structuredContent']['outcome'],
                            'duplicate_reply':'not_resubmitted','source_actions':len(source.actions),'state_after_reply':live['structuredContent']['state']['agent_status'],
                            'goal_status':event['data']['goal_status'],'unsubscribe':'processed','temporary_store':'removed_on_exit',
                            'not_proven':['real OAuth','Herdr source/socket','public DNS/TLS callbacks','ChatGPT/dot delivery','live reliability']}
        finally:store.close()
