"""SDK MCP2 resource server with optional same-host sign-in routes."""
import hashlib
import json
from urllib.parse import urlsplit
from typing import Any
import time
import mcp.types as types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.routes import create_protected_resource_routes
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings,TransportSecurityMiddleware
from mcp.shared.exceptions import MCPError
from pydantic import Field,ConfigDict,BaseModel
from .core import NAMES,Rejected,encode
from .webhooks import decode_secret,verify,CallbackError
from .skills import register_skill
from .actions import register_actions

PROTOCOL='2026-07-28'

class HTTPBoundary:
    """Check Host/Origin before auth; make loopback discovery reachable without changing audience."""
    def __init__(self,app,resource,local_port=8000,signin_paths=()):
        from mcp.server.auth.routes import build_resource_metadata_url
        self.app=app
        self.signin_paths=frozenset(signin_paths)
        self.resource_origin=urlsplit(resource).scheme+'://'+urlsplit(resource).netloc
        parsed=urlsplit(resource)
        self.metadata=str(build_resource_metadata_url(resource))
        self.local_host=f'127.0.0.1:{local_port}'
        self.local_metadata='http://'+self.local_host+urlsplit(self.metadata).path
        self.security=TransportSecurityMiddleware(
            TransportSecuritySettings(allowed_hosts=[self.local_host,parsed.netloc],
                allowed_origins=['http://'+self.local_host,parsed.scheme+'://'+parsed.netloc]))
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        from starlette.requests import Request
        request=Request(scope)
        if scope['path'] in self.signin_paths:
            from starlette.responses import Response
            rejected=None
            if not self.security._validate_host(request.headers.get('host')):
                rejected=Response('Invalid Host header',status_code=421)
            elif scope['path']=='/login' and request.headers.get('origin') not in (None,self.resource_origin):
                rejected=Response('Invalid Origin header',status_code=403)
        else:
            rejected=await self.security.validate_request(request,is_post=scope['method']=='POST')
        if rejected:return await rejected(scope,receive,send)
        async def local_challenge(message):
            if message['type']=='http.response.start' and request.headers.get('host')==self.local_host:
                message={**message,'headers':[(k,v.replace(self.metadata.encode(),self.local_metadata.encode()) if k.lower()==b'www-authenticate' else v) for k,v in message.get('headers',[])]}
            await send(message)
        await self.app(scope,receive,local_challenge)

class SigninAuthBoundary:
    """Keep the SDK auth stack intact except for mounted provider endpoints."""
    def __init__(self,app,auth_middleware,signin_paths):
        self.app=app
        self.signin_paths=frozenset(signin_paths)
        self.authenticated=app
        for middleware in reversed(auth_middleware):
            self.authenticated=middleware.cls(self.authenticated,*middleware.args,**middleware.kwargs)

    async def __call__(self,scope,receive,send):
        if scope['type']=='http' and scope['path'] in self.signin_paths:
            return await self.app(scope,receive,send)
        await self.authenticated(scope,receive,send)


class ConnectorServer(MCPServer):
    local_port=8000
    signin_routes=()
    def streamable_http_app(self, **kwargs):
        auth=self.settings.auth
        parsed=urlsplit(str(auth.resource_server_url))
        local_host=f'127.0.0.1:{self.local_port}'
        kwargs['transport_security']=TransportSecuritySettings(allowed_hosts=[local_host,parsed.netloc],
            allowed_origins=['http://'+local_host,parsed.scheme+'://'+parsed.netloc])
        app=super().streamable_http_app(**kwargs)
        # The SDK uses required endpoint scopes as its supported-scope list.
        # Advertise optional write scope while keeping observation-only tokens valid.
        metadata=create_protected_resource_routes(auth.resource_server_url,[auth.issuer_url],
                                                  scopes_supported=['herdr:observe','herdr:control'])
        paths={route.path for route in metadata}
        app.router.routes[:]=[route for route in app.router.routes if getattr(route,'path',None) not in paths]+metadata
        app.router.routes.extend(self.signin_routes)
        if self.signin_routes:
            from starlette.middleware import Middleware
            app.user_middleware=[Middleware(SigninAuthBoundary,auth_middleware=app.user_middleware,
                                           signin_paths=[route.path for route in self.signin_routes])]
        app.add_middleware(HTTPBoundary,resource=str(auth.resource_server_url),local_port=self.local_port,
                           signin_paths=[route.path for route in self.signin_routes])
        return app

def principal():
    token=get_access_token()
    if not token or not token.subject or not (token.claims or {}).get('iss'):raise MCPError(code=-32012,message='Forbidden')
    return principal_key(token.claims['iss'],token.subject)

def principal_key(issuer,subject):
    return hashlib.sha256(encode([issuer,subject]).encode()).hexdigest()

# Retain this import for existing clients of endpoint.JWTVerifier.
from .auth import JWTVerifier

class Profile(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str=Field(min_length=1,pattern=r'\S')


def register_profile(server):
    @server.tool(meta={'openai/profile':True},structured_output=True,
                 annotations=types.ToolAnnotations(readOnlyHint=True,destructiveHint=False,openWorldHint=False))
    def get_profile()->Profile:
        """Stable opaque identity represented by the validated request credentials."""
        return Profile(id=principal())
    # MCPServer.tool infers argument models with Pydantic's default extra=ignore.
    # Publish and enforce the profile contract's empty-object input in SDK 2.3.
    tool=server._tool_manager.get_tool('get_profile')
    tool.fn_metadata.arg_model.model_config['extra']='forbid'
    tool.fn_metadata.arg_model.model_rebuild(force=True)
    tool.parameters=tool.fn_metadata.arg_model.model_json_schema(by_alias=True)


class PairingSession:
    """Memory-only candidates; local confirmation is the sole enrollment decision."""
    def __init__(self,issuer,ttl=600,max_candidates=8,*,clock=time.monotonic,wall_clock=time.time):
        from .auth import https_url
        https_url(issuer)
        if not 1<=ttl<=900 or not 1<=max_candidates<=16:raise Rejected('invalid_pairing_limits')
        self.issuer,self.clock,self.wall_clock=issuer,clock,wall_clock
        self.deadline=clock()+ttl;self.max_candidates=max_candidates
        self._candidates={};self.closed=False

    def _check(self):
        if self.closed or self.clock()>=self.deadline:
            self.close();raise Rejected('pairing_expired_or_closed')

    def observe(self,token):
        self._check()
        claims=token.claims or {}
        if claims.get('iss')!=self.issuer or not token.subject or 'herdr:observe' not in token.scopes:raise Rejected('pairing_identity_denied')
        if token.expires_at is None or token.expires_at<=self.wall_clock():raise Rejected('pairing_identity_expired')
        who=principal_key(self.issuer,token.subject)
        if who not in self._candidates and len(self._candidates)>=self.max_candidates:raise Rejected('pairing_candidate_limit')
        self._candidates[who]={'principal':who,'issuer':self.issuer,'subject':token.subject,
                               'client_id':token.client_id,'expires_at':token.expires_at,'scopes':sorted(set(token.scopes))}

    def candidates(self):
        self._check()
        return [dict(v) for v in self._candidates.values() if v['expires_at']>self.wall_clock()]

    def confirm(self,principal_id):
        self._check()
        candidate=self._candidates.get(principal_id)
        if not candidate or candidate['expires_at']<=self.wall_clock():raise Rejected('pairing_candidate_unavailable')
        result={k:candidate[k] for k in ('issuer','subject','principal','client_id','scopes','expires_at')}
        self.close()
        return result

    def close(self):
        self.closed=True;self._candidates.clear()


def build_pairing(verifier,issuer,resource,pairing,local_port=8000,signin_routes=None):
    """Authenticate and expose only profile; never construct source, Store or callbacks."""
    if pairing.issuer!=issuer:raise Rejected('pairing_issuer_mismatch')
    class PairingVerifier:
        async def verify_token(self,token):
            verified=await verifier.verify_token(token)
            if verified is None:return None
            try:pairing.observe(verified)
            except Rejected:return None
            return verified
    server=ConnectorServer(name='dot-herdr-pairing',instructions='Identity pairing only. Confirm the displayed account in the local setup terminal.',
        token_verifier=PairingVerifier(),auth=AuthSettings(issuer_url=issuer,resource_server_url=resource,
            validate_token_resource=True,required_scopes=['herdr:observe']))
    server.local_port=local_port
    server.signin_routes=tuple(signin_routes or ())
    register_profile(server)
    return server

class Subscribe(types.RequestParams):
    model_config=ConfigDict(extra='forbid')
    name:str
    arguments:dict[str,Any]
    delivery:dict[str,Any]
    cursor:str|None=None
    ttlMs:int|None=3600000

class Unsubscribe(types.RequestParams):
    model_config=ConfigDict(extra='forbid')
    name:str
    arguments:dict[str,Any]
    delivery:dict[str,Any]

def catalog():
    return [{'name':name,'description':{
        NAMES[0]:'An enrolled parent is detected blocked; inspect context. This is not approval.',
        NAMES[1]:'Observed completion counter advanced; turn completion is not task success.',
        NAMES[2]:'Observed parent state changed; inspect cached/current source details.',
        NAMES[3]:'Known source observation gap; upstream missed episodes cannot be recovered.'}[name],
        'delivery':['webhook'],
        'inputSchema':{'type':'object','properties':{'subject_key':{'type':'string','minLength':1,'maxLength':128}},'required':['subject_key'],'additionalProperties':False},
        'payloadSchema':{'type':'object','properties':{
            'schema_version':{'const':2},'subject_key':{'type':'string'},'owner_key':{'type':'string'},
            'generation':{'type':'integer'},'revision':{'type':'integer'},'origin':{'type':'string'},
            'observed_at':{'type':'string'},'occurred_at':{'type':['string','null']},'time_basis':{'const':'observation'},
            'upstream_history':{'const':'best_effort'},'captured_history':{'const':'durable_since_commit'},
            'goal_status':{'const':'unknown'},'state':{'type':'string'},'previous_state':{'type':['string','null']},
            'category':{'type':'string'},'decision_authority':{'const':'unknown'},'detail_available':{'type':'boolean'},
            'completion_seq':{'type':'integer'},'completion_kind':{'const':'turn_completed'},
            'coverage_state':{'type':'string'},'reason_code':{'type':'string'},'history_complete':{'const':False}},
            'required':['schema_version','subject_key','owner_key','generation','revision','origin','observed_at','occurred_at','time_basis','upstream_history','captured_history','goal_status'],
            'additionalProperties':False}} for name in NAMES]

def event_error(error):
    if isinstance(error,CallbackError):return MCPError(code=-32015,message='CallbackEndpointError',data={'reason':error.reason})
    if str(error)=='forbidden_scope':return MCPError(code=-32012,message='Forbidden')
    if str(error)=='unknown_event':return MCPError(code=-32011,message='NotFound',data={'kind':'event'})
    if str(error)=='native_replay_unsupported_use_timeline':return MCPError(code=-32014,message='Unsupported',data={'feature':'cursor'})
    if str(error)=='unsupported_delivery':return MCPError(code=-32014,message='Unsupported',data={'feature':'deliveryMode'})
    return MCPError(code=-32602,message='InvalidParams',data={'reason':str(error)})

def build(store,source,transport,verifier,issuer,resource,controls=None,session_users=None,local_port=8000,signin_routes=None):
    server=ConnectorServer(name='dot-herdr',instructions='Use the bundled herdr-connector skill and its relevant setup/events/control reference for the requested workflow. References are authenticated resources listed by skills/get. get_herdr_capabilities() gives grants; get_herdr_capabilities(method) gives the callable route, permissions, native schema and connector constraints. Use enrolled input tools or session query/action tools as granted. Missing HERDR_* in a detached runner does not prove Herdr is absent. A completed turn is not task success. Retain action request_id on exact retries; inspect unknown outcomes before further input.',
        token_verifier=verifier,auth=AuthSettings(issuer_url=issuer,resource_server_url=resource,validate_token_resource=True,required_scopes=['herdr:observe']))
    server.local_port=local_port
    server.signin_routes=tuple(signin_routes or ())
    register_profile(server)
    low=server._lowlevel_server
    register_skill(server,principal)
    register_actions(server,store,source,principal,frozenset(controls or ()),frozenset(session_users or ()))
    async def capabilities(ctx,call_next):
        result=await call_next(ctx)
        if ctx.method=='server/discover' and isinstance(result,dict):result.setdefault('capabilities',{})['events']={}
        return result
    low.middleware.append(capabilities)
    async def listing(ctx,p):
        who=principal()
        allowed=store.db.execute('SELECT 1 FROM subjects WHERE principal=? AND enabled=1',(who,)).fetchone()
        return {'resultType':'complete','events':catalog() if allowed else []}
    async def subscribe(ctx,p):
        who=principal()
        try:
            store.validate_subscription(who,p.name,p.arguments)
            if p.cursor is not None:raise Rejected('native_replay_unsupported_use_timeline')
            if p.delivery.get('mode')!='webhook':raise Rejected('unsupported_delivery')
            if set(p.delivery)!={'mode','url','secret'}:raise Rejected('invalid_delivery')
            if p.ttlMs is not None and p.ttlMs<0:raise Rejected('invalid_ttl')
            ttl=3600 if p.ttlMs is None else min(86400,max(60,p.ttlMs//1000))
            decode_secret(p.delivery['secret'])
            sub=store.subscription_identity(who,p.name,p.arguments,p.delivery['url'])
            if not store.verification_cached(who,p.delivery['url'],p.delivery['secret']):
                await verify(transport,p.delivery['url'],p.delivery['secret'],sub,store.clock)
                store.verified(who,p.delivery['url'],p.delivery['secret'])
            # Recheck entitlement immediately after challenge, before activation.
            return {'resultType':'complete',**store.activate(who,p.name,p.arguments,p.delivery['url'],p.delivery['secret'],ttl)}
        except Rejected as e:raise event_error(e) from None
    async def unsubscribe(ctx,p):
        try:
            if not {'mode','url'}<=set(p.delivery) or set(p.delivery)-{'mode','url','secret'} or p.delivery['mode']!='webhook':raise Rejected('invalid_delivery')
            store.unsubscribe(principal(),p.name,p.arguments,p.delivery['url'])
            return {'resultType':'complete'}
        except Rejected as e:raise event_error(e) from None
    low.add_request_handler('events/list',types.RequestParams,listing)
    low.add_request_handler('events/subscribe',Subscribe,subscribe)
    low.add_request_handler('events/unsubscribe',Unsubscribe,unsubscribe)
    readonly=types.ToolAnnotations(readOnlyHint=True,destructiveHint=False,openWorldHint=False)
    @server.tool(annotations=readonly)
    def get_agent_state(subject_key:str)->dict[str,Any]:
        """Cached scoped source state with observation time. Not current live validation or task success."""
        return store.state(principal(),subject_key)
    @server.tool(annotations=readonly)
    def list_timeline(subject_key:str,after_position:int=0,limit:int=25)->dict[str,Any]:
        """Captured journal only. Position is an application offset, not upstream/native replay."""
        return store.timeline(principal(),subject_key,after_position,limit)
    @server.tool(annotations=readonly)
    def get_event(event_id:str)->dict[str,Any]:
        """Read one immutable entitled observation."""
        return store.event(principal(),event_id)
    @server.tool(annotations=readonly)
    def get_observation_capabilities()->dict[str,Any]:
        """Actual supported slice and explicit gaps; no native approval or task outcomes."""
        principal()
        return {'herdr_protocol':22,'herdr_schema':1,'native_protocol':PROTOCOL,'upstream_history':'best_effort',
                'captured_history':'durable','native_replay':False,'timeline_replay':True,
                'reads':['cached_state','event','timeline','visible_context'],
                'control':'get_herdr_capabilities','unsupported':['task_success','typed_approval','native_replay','automatic_move_rebind','artifact_files','raw_transcripts']}
    @server.tool(annotations=readonly)
    def get_connector_health()->dict[str,Any]:
        """Scoped source timestamps/gaps and delivery stages, no callback secrets."""
        return store.health(principal())
    @server.tool(annotations=readonly)
    async def read_visible_context(subject_key:str,expected_generation:int,lines:int=40)->dict[str,Any]:
        """Transient bounded visible read under explicit content grant; may withhold secret-bearing text."""
        row=store.subject(principal(),subject_key)
        if not row['content']:raise Rejected('content_withheld')
        if expected_generation!=row['generation']:raise Rejected('identity_changed')
        before=await source.agent(row['pane'])
        def valid(a):
            return a.get('terminal_id')==row['terminal'] and a.get('pane_id')==row['pane'] and (not row['native'] or encode(a.get('agent_session'))==row['native'])
        if not valid(before):raise Rejected('identity_changed')
        capture=await source.visible(row['pane'],lines)
        after=await source.agent(row['pane'])
        if not valid(after) or before.get('revision')!=after.get('revision') :raise Rejected('stale_evidence')
        current=store.subject(principal(),subject_key) # Recheck entitlement after asynchronous source reads.
        if not current['content'] or any(current[k]!=row[k] for k in ('generation','pane','terminal','native','principal')):raise Rejected('identity_changed')
        return {**capture,'source_agent_revision':after.get('revision'),'capture_revision_semantics':'Herdr PaneReadResult currently reports zero; sandwich checks identity and AgentInfo revision, not atomic screen coherence','generation':expected_generation,'freshness':'current_read','content_is':'untrusted_source_evidence'}
    @server.tool(annotations=types.ToolAnnotations(readOnlyHint=False,destructiveHint=False,openWorldHint=False))
    def record_triage_receipt(event_id:str,phase:str,disposition:str,subscription_key:str|None=None)->dict[str,Any]:
        """Idempotent observer receipt, never source ACK/approval. Not independent chat attestation. Use subscription_key="" when the host does not show it (or omit it with newer schemas); inference requires exactly one of your watches to have received the event."""
        return store.receipt(principal(),event_id,subscription_key,phase,disposition)
    return server
