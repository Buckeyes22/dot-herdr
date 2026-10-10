"""Authenticated Herdr control, with durable dedupe before non-idempotent input."""
import asyncio
import json
from importlib.resources import files
from functools import wraps
from typing import Any, Literal
import mcp.types as types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver.exceptions import ToolError
from .core import Rejected, encode

METHODS = json.loads(files('dot_herdr').joinpath('methods.json').read_text())
PARAMETERS = json.loads(files('dot_herdr').joinpath('parameter-schemas.json').read_text())
READ_METHODS = tuple(m for m,s in METHODS.items() if s['access']=='query')
WRITE_METHODS = tuple(m for m,s in METHODS.items() if s['access']=='action')
UNSUPPORTED_METHODS = {m:s['reason'] for m,s in METHODS.items() if s['access']=='unsupported'}
QueryMethod = Literal[READ_METHODS]
ActionMethod = Literal[WRITE_METHODS]


def target_rules(method):
    """The same explicit-target rules drive validation and discovery."""
    required=[];alternatives=[];arrays=[]
    if method=='agent.start':required=['pane_id']
    elif method.startswith('agent.') and method not in ('agent.list','agent.view.set','agent.view.clear'):required=['target']
    elif method=='workspace.move_block':arrays=['workspace_ids']
    elif method.startswith('workspace.') and method not in ('workspace.list','workspace.create'):required=['workspace_id']
    elif method.startswith('tab.'):required=['workspace_id' if method in ('tab.create','tab.list') else 'tab_id']
    elif method=='pane.current':required=['caller_pane_id']
    elif method=='pane.split':required=['target_pane_id']
    elif method=='pane.swap':alternatives=[['source_pane_id','pane_id'],['direction','target_pane_id']]
    elif method.startswith('pane.') and method!='pane.list':required=['pane_id']
    elif method.startswith('layout.'):
        if method=='layout.apply':required=['workspace_id']
        else:alternatives=[['tab_id','pane_id']]
    elif method.startswith('worktree.'):alternatives=[['cwd','workspace_id']]
    elif method=='command.invoke':alternatives=[['pane_id','tab_id','workspace_id']]
    elif method=='plugin.action.invoke':alternatives=[['context.focused_pane_id','context.tab_id','context.workspace_id']]
    elif method=='plugin.pane.open':alternatives=[['target_pane_id','workspace_id']]
    elif method in ('plugin.pane.close','plugin.pane.focus'):required=['pane_id']
    elif method=='events.wait':required=['match_event.pane_id']
    return {'required':required,'one_of_each':alternatives,'nonempty_arrays':arrays}


def absolute_paths(method):
    if method=='plugin.link':return ['path']
    return ['cwd'] if method in ('workspace.create','tab.create','pane.split','plugin.pane.open') else []


def method_details(method):
    """Native shape plus actionable connector-specific routing and limits."""
    if method not in METHODS:raise Rejected('unsupported_method')
    access=METHODS[method]['access']
    tool={'query':'herdr_query','action':'herdr_action','events':'collect_native_events'}.get(access)
    constraints={'explicit_targets':target_rules(method),'absolute_paths':absolute_paths(method),
                 'unknown_parameter_fields':'rejected_at_top_level','max_parameter_bytes':32768}
    constraints['explicit_targets']['identifier_characters']={'minimum':1,'maximum':256,'cwd_is_path':True}
    if method in ('agent.wait','pane.wait_for_output','events.wait','agent.start'):
        constraints['timeout_ms']={'minimum':3001 if method=='agent.start' else 1,'maximum':30000,'default':30000 if method=='agent.start' else 10000,'null_allowed':False}
    if method=='events.wait':constraints['match_event.event']={'allowed':['pane_agent_status_changed']}
    if method=='plugin.log.list':constraints['limit']={'minimum':1,'maximum':100,'default':25,'null_allowed':False}
    if method in ('agent.prompt','pane.send_text','pane.send_input'):
        constraints['text']={'max_utf8_bytes':16384,'nonblank':True,'forbidden_codepoints':'U+0000-U+001F except tab/newline','when':'nonempty text for pane.send_input; always for prompt/send_text'}
    if method=='agent.prompt':constraints['wait']='omit_or_null; use agent.wait separately'
    if method in ('agent.send_keys','pane.send_keys','pane.send_input'):
        constraints['keys']={'minimum_items':1,'maximum_items':32,'minimum_key_characters':1,'maximum_key_characters':64,'forbidden_codepoints':'U+0000-U+001F','when':'keys supplied'}
    if method=='pane.send_input':constraints['input']='nonblank text or nonempty keys required'
    if access=='action':constraints['request_id']={'minimum_characters':1,'maximum_characters':128,'exact_retry':'durable_dedupe','unknown_outcome':'inspect_before_any_new_submission'}
    if access=='events':
        constraints.update({'subscriptions':{'minimum_items':1,'maximum_items':32},
                            'timeout_ms':{'minimum':1,'maximum':30000,'default':10000},
                            'limit':{'minimum':1,'maximum':100,'default':25},'max_event_bytes':131072,'socket_open_timeout_ms':10000,'history':'best_effort; no reconnect or replay'})
    return {'method':method,**METHODS[method],'tool':tool,
            'permissions':{'session_access_required':True,'oauth_scopes':['herdr:observe']+(['herdr:control'] if access=='action' else [])},
            'connector_constraints':constraints,'inputSchema':method_schema(method)}


def method_schema(method):
    """Return the native parameter shape and only its reachable definitions."""
    if method not in METHODS:raise Rejected('unsupported_method')
    schema=PARAMETERS['methods'][method]
    definitions={}
    def visit(value):
        if isinstance(value,dict):
            ref=value.get('$ref','')
            if ref.startswith('#/$defs/'):
                name=ref.split('/')[-1]
                if name not in definitions:
                    definitions[name]=PARAMETERS['$defs'][name]
                    visit(definitions[name])
            for v in value.values():visit(v)
        elif isinstance(value,list):
            for v in value:visit(v)
    visit(schema)
    return {**schema,**({'$defs':definitions} if definitions else {})}



def safe_tool(fn):
    """Return categorized expected failures without source messages or tracebacks."""
    @wraps(fn)
    async def wrapped(*args,**kwargs):
        try:return await fn(*args,**kwargs)
        except Rejected as error:raise ToolError(str(error)) from None
        except (OSError,TimeoutError):raise ToolError('source_unavailable') from None
    return wrapped


def prepare(method, params):
    """No focus fallback; Herdr validates the remaining native parameter values."""
    if method not in METHODS or method in UNSUPPORTED_METHODS or not isinstance(params,dict):raise Rejected('unsupported_method')
    spec=METHODS[method]
    if set(params)-set(spec['fields']) or not set(spec['required'])<=set(params):raise Rejected('invalid_source_params')
    p=dict(params)
    # A remote caller must never depend on the foreground client's focus.
    def value(path):
        obj=p
        for key in path.split('.'):
            if not isinstance(obj,dict):return None
            obj=obj.get(key)
        return obj
    rules=target_rules(method)
    for path in rules['required']:require_target({'target':value(path)},'target')
    for group in rules['one_of_each']:
        path=next((path for path in group if value(path)),None)
        if path=='cwd':
            if not isinstance(value(path),str):raise Rejected('explicit_target_required')
        else:require_target({'target':value(path) if path else None},'target')
    for path in rules['nonempty_arrays']:
        targets=value(path)
        if not isinstance(targets,list) or not targets:raise Rejected('explicit_target_required')
        for target in targets:require_target({'target':target},'target')
    for path in absolute_paths(method):
        if not isinstance(p.get(path),str) or not p[path].startswith('/'):
            raise Rejected('absolute_plugin_path_required' if path=='path' else 'absolute_cwd_required')
    if method in ('agent.wait','pane.wait_for_output','events.wait'):
        p['timeout_ms']=bounded_timeout(p.get('timeout_ms',10000))
    if method=='events.wait':
        match=p.get('match_event')
        if not isinstance(match,dict) or match.get('event')!='pane_agent_status_changed':raise Rejected('unsupported_event_wait_match')
        require_target(match,'pane_id')
    if method=='plugin.log.list':
        limit=p.get('limit',25)
        if type(limit)!=int or not 1<=limit<=100:raise Rejected('invalid_limit')
        p['limit']=limit
    if method=='agent.start':
        p['timeout_ms']=bounded_timeout(p.get('timeout_ms',30000))
        if p['timeout_ms']<=3000:raise Rejected('invalid_timeout')
    if method=='agent.prompt':
        validate_text(p.get('text'))
        # Submit and inspect afterwards. Native prompt waits can confuse completion
        # of an already-active turn with the submitted instruction's completion.
        if p.get('wait') is not None:raise Rejected('use_agent_wait_separately')
    if method=='pane.send_text' or (method=='pane.send_input' and p.get('text')):validate_text(p.get('text'))
    if method in ('agent.send_keys','pane.send_keys','pane.send_input') and 'keys' in p:
        validate_keys(p['keys'])
    if method=='pane.send_input' and not p.get('text') and not p.get('keys'):raise Rejected('invalid_message')
    if len(encode(p).encode())>32768:raise Rejected('source_params_too_large')
    return p


def require_target(params, key):
    if not isinstance(params.get(key),str) or not 1<=len(params[key])<=256:raise Rejected('explicit_target_required')


def bounded_timeout(value):
    if type(value)!=int or not 1<=value<=30000:raise Rejected('invalid_timeout')
    return value


def validate_text(text):
    if not isinstance(text,str) or not text.strip() or len(text.encode())>16384 or any(ord(c)<32 and c not in '\n\t' for c in text):raise Rejected('invalid_message')


def validate_keys(keys):
    if not isinstance(keys,list) or not 1<=len(keys)<=32 or any(not isinstance(k,str) or not 1<=len(k)<=64 or any(ord(c)<32 for c in k) for k in keys):raise Rejected('invalid_keys')


def register_actions(server, store, source, authenticate, controls, session_users):
    lock=asyncio.Lock()  # One submission at a time across scoped and session tools.
    readonly=types.ToolAnnotations(readOnlyHint=True,destructiveHint=False,openWorldHint=False)
    write=types.ToolAnnotations(readOnlyHint=False,destructiveHint=True,idempotentHint=True,openWorldHint=True)

    def control_principal():
        who=authenticate()
        token=get_access_token()
        if not token or 'herdr:control' not in token.scopes:
            from .auth import CONTROL_SCOPE_REMEDY
            raise Rejected('control_scope_required: '+CONTROL_SCOPE_REMEDY)
        return who

    def enrolled(who,key,generation,control=False):
        row=store.subject(who,key)
        if control and key not in controls:raise Rejected('control_withheld')
        if generation!=row['generation']:raise Rejected('identity_changed')
        return row

    async def live(who,key,generation,control=False):
        row=enrolled(who,key,generation,control)
        agent=await source.agent(row['pane'])
        current=enrolled(who,key,generation,control)
        if any(current[k]!=row[k] for k in ('pane','terminal','native','principal')) or agent.get('pane_id')!=row['pane'] or agent.get('terminal_id')!=row['terminal'] or (row['native'] and encode(agent.get('agent_session'))!=row['native']):raise Rejected('identity_changed')
        return row,agent

    async def dispatch(who,request_id,operation,method,params,scoped=False):
        previous=store.begin_action(who,request_id,operation)
        if previous is not None:return previous
        try:
            result=await source.request(method,params)
            if scoped:
                # Agent action responses can include title/cwd/token metadata.
                a=result.get('agent',{})
                result={'type':result.get('type'),'agent_status':a.get('agent_status'),'revision':a.get('revision')}
            reply={'request_id':request_id,'outcome':'submitted','result':result,'task_success':'unknown'}
        except Rejected as error:
            reason=str(error)
            # Only an explicit native error is known; partial writes may still
            # have happened even when the native server returned an error.
            reply={'request_id':request_id,'outcome':'unknown','reason':reason,'retry':'inspect_source_do_not_resubmit'}
        except (OSError,TimeoutError,ValueError,KeyError):
            reply={'request_id':request_id,'outcome':'unknown','reason':'source_unavailable','retry':'inspect_source_do_not_resubmit'}
        return store.finish_action(who,request_id,reply)

    async def agent_action(key,generation,request_id,method,args):
        who=control_principal()
        async with lock:
            row=enrolled(who,key,generation,True)
            params=prepare(method,{'pane_id' if method.startswith('pane.') else 'target':row['pane'],**args})
            operation={'subject_key':key,'generation':generation,'method':method,'params':params}
            # Return a recorded outcome without touching source on exact retry.
            old=store.db.execute('SELECT 1 FROM actions WHERE principal=? AND request_id=?',(who,request_id)).fetchone()
            if old:return store.begin_action(who,request_id,operation)
            row,agent=await live(who,key,generation,True)
            if method in ('agent.prompt','agent.send_keys','pane.send_input') and not agent.get('agent'):raise Rejected('agent_not_ready')
            if method=='agent.prompt' and agent.get('agent_status')=='blocked':raise Rejected('agent_blocked_use_interactive_keys')
            return await dispatch(who,request_id,operation,method,params,True)

    @server.tool(annotations=write)
    @safe_tool
    async def send_agent_message(subject_key:str,expected_generation:int,request_id:str,text:str)->dict[str,Any]:
        """Submit a prompt to an enrolled agent. Requires control grant and herdr:control. Reuse request_id only for the same action; unknown delivery must be inspected, never blindly resubmitted."""
        return await agent_action(subject_key,expected_generation,request_id,'agent.prompt',{'text':text})

    @server.tool(annotations=write)
    @safe_tool
    async def send_agent_keys(subject_key:str,expected_generation:int,request_id:str,keys:list[str])->dict[str,Any]:
        """Send logical UI keys (enter, esc, ctrl+c, y) to an enrolled agent, including blocked dialogs. Inspect UI first and follow user's decision authority. Not a typed approval API."""
        return await agent_action(subject_key,expected_generation,request_id,'agent.send_keys',{'keys':keys})

    @server.tool(annotations=write)
    @safe_tool
    async def send_agent_input(subject_key:str,expected_generation:int,request_id:str,text:str,keys:list[str]|None=None)->dict[str,Any]:
        """Type a text reply and optional logical keys into the enrolled agent UI, including blocked questions. Pass keys=['enter'] to submit. Inspect current UI and follow user's authority; this can answer approvals and is not a typed approval protocol."""
        args={'text':text}
        if keys is not None:args['keys']=keys
        return await agent_action(subject_key,expected_generation,request_id,'pane.send_input',args)

    @server.tool(annotations=write)
    @safe_tool
    async def rename_agent(subject_key:str,expected_generation:int,request_id:str,name:str|None=None)->dict[str,Any]:
        """Set or clear enrolled agent's display name. Does not change enrollment identity."""
        return await agent_action(subject_key,expected_generation,request_id,'agent.rename',{'name':name})

    @server.tool(annotations=write)
    @safe_tool
    async def focus_agent(subject_key:str,expected_generation:int,request_id:str)->dict[str,Any]:
        """Bring enrolled agent into Herdr UI focus when requested."""
        return await agent_action(subject_key,expected_generation,request_id,'agent.focus',{})

    @server.tool(annotations=readonly)
    @safe_tool
    async def get_live_agent_state(subject_key:str,expected_generation:int)->dict[str,Any]:
        """Validate enrolled agent identity and refresh its safe cached state from live Herdr."""
        who=authenticate();row,agent=await live(who,subject_key,expected_generation)
        store.observe(subject_key,agent)
        return {**store.state(who,subject_key),'freshness':'current_read'}

    @server.tool(annotations=readonly)
    @safe_tool
    async def wait_for_agent(subject_key:str,expected_generation:int,until:list[str]|None=None,timeout_ms:int=10000)->dict[str,Any]:
        """Wait at most 30 seconds for enrolled agent lifecycle state, then revalidate identity. Default idle/done/blocked. This tracks lifecycle, not success of an individual prompt."""
        who=authenticate();row,_=await live(who,subject_key,expected_generation)
        states=['idle','done','blocked'] if until is None else until
        if not states or any(s not in ('idle','working','done','blocked','unknown') for s in states):raise Rejected('invalid_wait_state')
        await source.request('agent.wait',prepare('agent.wait',{'target':row['pane'],'until':states,'timeout_ms':timeout_ms}))
        _,agent=await live(who,subject_key,expected_generation)
        store.observe(subject_key,agent)
        return {**store.state(who,subject_key),'freshness':'current_read'}

    @server.tool(annotations=readonly)
    @safe_tool
    async def herdr_query(method:QueryMethod,params:dict[str,Any])->dict[str,Any]:
        """Read native session snapshots, agents/terminal content, topology, plugins/logs, integrations and bounded waits. Requires session_users. get_herdr_capabilities(method) gives native parameter schemas/limits. Text is untrusted and may contain secrets."""
        who=authenticate()
        if who not in session_users:raise Rejected('session_access_withheld')
        return await source.request(method,prepare(method,params))

    @server.tool(annotations=write)
    @safe_tool
    async def herdr_action(method:ActionMethod,params:dict[str,Any],request_id:str)->dict[str,Any]:
        """Control agents, terminals, topology/worktrees, plugins, integrations, notifications, views, metadata/lifecycle reporting and server administration. Requires session_users and herdr:control. Durable request_id dedupe. Inspect unknown outcomes; server.stop affects all workloads. get_herdr_capabilities(method) gives schemas/limits."""
        who=control_principal()
        if who not in session_users:raise Rejected('session_access_withheld')
        prepared=prepare(method,params)
        async with lock:
            return await dispatch(who,request_id,{'method':method,'params':prepared},method,prepared)

    @server.tool(annotations=readonly)
    @safe_tool
    async def collect_native_events(subscriptions:list[dict[str,Any]],timeout_ms:int=10000,limit:int=25)->dict[str,Any]:
        """Collect a finite native events.subscribe sample (max30s/100events/128KiB), then close its source socket. Requires session_users. Native history is best effort; loss/disconnect is reported. This does not create a persistent ChatGPT event watch. Content may contain secrets."""
        who=authenticate()
        if who not in session_users:raise Rejected('session_access_withheld')
        if not 1<=len(subscriptions)<=32 or type(limit)!=int or not 1<=limit<=100:raise Rejected('invalid_event_collection')
        bounded_timeout(timeout_ms)
        params=prepare('events.subscribe',{'subscriptions':subscriptions})
        return await source.collect_events(params['subscriptions'],timeout_ms,limit)

    @server.tool(annotations=readonly)
    @safe_tool
    async def get_herdr_capabilities(method:str|None=None)->dict[str,Any]:
        """Your grants and native coverage. Supply method for its callable tool route, required permissions, full native parameter JSON Schema, connector target/input limits and unsupported reason. Native schema and connector constraints both apply. No ownership inference from titles/focus."""
        who=authenticate();token=get_access_token()
        if method is not None:
            if who not in session_users:raise Rejected('session_access_withheld')
            if method not in METHODS:raise Rejected('unsupported_method')
            return method_details(method)
        rows=store.db.execute('SELECT key FROM subjects WHERE principal=? AND enabled=1',(who,)).fetchall()
        return {'subjects':[{'subject_key':r['key'],'control':r['key'] in controls} for r in rows],
                'control_scope':bool(token and 'herdr:control' in token.scopes),
                'session_access':who in session_users,
                'session_queries':{m:METHODS[m] for m in READ_METHODS} if who in session_users else {},
                'session_actions':{m:METHODS[m] for m in WRITE_METHODS} if who in session_users else {},
                'native_event_collection':who in session_users,
                'native_coverage':{'catalog_methods':len(METHODS),'queries':len(READ_METHODS),'actions':len(WRITE_METHODS),'bounded_event_streams':1,'unsupported':UNSUPPORTED_METHODS},
                'identity_fence':'preflight_check_not_atomic_with_Herdr_write',
                'action_retries':'durable_dedupe_unknown_never_automatically_resubmitted'}
