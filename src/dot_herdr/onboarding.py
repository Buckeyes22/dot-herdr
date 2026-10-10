"""Guided setup: read existing Herdr metadata and save private configuration."""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from .core import Rejected
from .herdr import HerdrClient
from .setup import TEMPLATE,doctor,load_config,placeholders,public_key,validate_config


def clear_pending_input(stream=None):
    stream=stream or sys.stdin
    try:
        if not stream.isatty():return
        import termios
        termios.tcflush(stream.fileno(),termios.TCIFLUSH)
    except (ImportError,AttributeError,OSError,ValueError):pass


def ask_clean(ask,prompt):
    clear_pending_input()
    return ask(prompt)


async def confirm_candidate(candidates,issuer,ask,say,deadline=float('inf'),clock=time.monotonic,control_selected=False,client_app='chatgpt-web'):
    import asyncio
    if len(candidates)==1:
        candidate=candidates[0];principal=candidate['principal']
        say('Verified account '+json.dumps(candidate['subject'])+' at '+issuer+' (profile '+principal+', OAuth client '+json.dumps(candidate.get('client_id','unknown'))+').')
        short=principal if len(principal)<=16 else principal[:8]+'…'+principal[-4:]
        prompt='Approve account '+json.dumps(candidate['subject'])+' at '+issuer+' (profile '+short+', OAuth client '+json.dumps(candidate.get('client_id','unknown'))+')? It gets only the access you chose. [y/N]: '
    else:
        for index,candidate in enumerate(candidates,1):say(str(index)+'. Verified account '+json.dumps(candidate['subject'])+' at '+issuer+' (profile '+candidate['principal']+', OAuth client '+json.dumps(candidate.get('client_id','unknown'))+')')
        prompt='Approve account number for only the access you chose (Enter or n refuses): '
    while clock()<deadline:
        answer=ask(prompt)
        if asyncio.iscoroutine(answer):answer=await answer
        if clock()>=deadline:return None
        choice=answer.strip().lower()
        if choice in ('','n','no'):return None
        selected=candidates[0] if len(candidates)==1 and choice in ('y','yes') else candidates[int(choice)-1] if len(candidates)>1 and choice.isascii() and choice.isdecimal() and 1<=int(choice)<=len(candidates) else None
        if selected:
            if control_selected and 'herdr:control' not in selected.get('scopes',[]):
                from .auth import CONTROL_SCOPE_REMEDY
                say('This sign-in allows observation only. In the ChatGPT/Codex desktop app, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page. Observation works now.' if client_app=='desktop' else CONTROL_SCOPE_REMEDY)
            return selected['principal']
        say('Please enter '+('y to approve, or Enter/n to refuse.' if len(candidates)==1 else 'a listed number, or Enter/n to refuse.')+' Try again before the window closes.')
    return None


async def answer_before_deadline(prompt,ask,say,deadline,clock):
    import asyncio
    remaining=deadline-clock()
    if remaining<=0:return ''
    if ask is not input:return ask_clean(ask,prompt)
    loop=asyncio.get_running_loop();future=loop.create_future()
    clear_pending_input()
    say(prompt)
    def readable():
        if not future.done():future.set_result(sys.stdin.readline())
    loop.add_reader(sys.stdin.fileno(),readable)
    try:return await asyncio.wait_for(future,remaining)
    except asyncio.TimeoutError:return ''
    finally:loop.remove_reader(sys.stdin.fileno())


def missing(value):
    return not value or value.startswith('/path/to/') or value.startswith('replace-with-') or '.invalid' in value


def private_directory(path):
    from .connections import safe_path
    safe_path(path)
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o077:raise Rejected('private_output_parent_required')


def running_sessions():
    binary=shutil.which('herdr')
    if not binary:raise Rejected('herdr_cli_not_found_use_setup_socket')
    try:
        response=subprocess.run([binary,'session','list','--json'],capture_output=True,timeout=10,check=True)
        if len(response.stdout)>262144:raise ValueError
        sessions=json.loads(response.stdout)['sessions']
        if not isinstance(sessions,list):raise ValueError
        return [s for s in sessions if isinstance(s,dict) and s.get('running') is True and isinstance(s.get('socket_path'),str)]
    except (subprocess.SubprocessError,KeyError,ValueError,TypeError):raise Rejected('session_discovery_failed_use_setup_socket') from None


def choose_socket(explicit,ask,say):
    if explicit:return explicit
    sessions=running_sessions()
    if not sessions:raise Rejected('no_running_herdr_session')
    if len(sessions)==1:
        say('Using the only running Herdr session: '+json.dumps(sessions[0].get('name','unnamed')))
        return sessions[0]['socket_path']
    for index,session in enumerate(sessions,1):
        say(f"{index}. "+json.dumps(session.get('name','unnamed'))+' — '+json.dumps(session['socket_path']))
    choice=ask('Herdr session number: ').strip()
    if not choice.isdigit() or not 1<=int(choice)<=len(sessions):raise Rejected('invalid_session_selection')
    return sessions[int(choice)-1]['socket_path']


async def choose_agents(source,full,control,user,ask,say):
    agents=(await source.request('agent.list',{})).get('agents')
    if not isinstance(agents,list):raise Rejected('malformed_source')
    agents=[a for a in agents if isinstance(a,dict) and a.get('agent') and isinstance(a.get('pane_id'),str)]
    if not agents:
        if full:return []
        raise Rejected('no_agents_for_scoped_setup')
    say('Choose agents to monitor'+(' (optional with whole-session access).' if full else '.'))
    for i,a in enumerate(agents,1):
        # Never print titles, cwd, transcripts or arbitrary source metadata.
        say(f"{i}. "+json.dumps(a['pane_id'])+' — '+json.dumps(a['agent'])+' — '+json.dumps(a.get('agent_status','unknown')))
    choice=ask('Agent numbers separated by commas'+('; Enter for none' if full else '')+': ').strip()
    if not choice and full:return []
    selected=choice.split(',')
    if len(selected)>32 or any(not v.strip().isdigit() or not 1<=int(v)<=len(agents) for v in selected):raise Rejected('invalid_agent_selection')
    indexes=[int(v) for v in selected]
    if len(indexes)!=len(set(indexes)):raise Rejected('invalid_agent_selection')
    content=ask('Allow bounded visible context for these monitored agents? [y/N]: ').strip().lower() in ('y','yes')
    roster=[]
    for index in indexes:
        listed=agents[index-1];current=await source.agent(listed['pane_id'])
        if current.get('pane_id')!=listed['pane_id'] or current.get('terminal_id')!=listed.get('terminal_id') or current.get('agent_session')!=listed.get('agent_session'):raise Rejected('identity_changed_run_setup_again')
        if not current.get('agent') or not isinstance(current.get('terminal_id'),str):raise Rejected('agent_not_ready')
        identity=hashlib.sha256((current['pane_id']+'\0'+current['terminal_id']).encode()).hexdigest()[:16]
        roster.append({'key':'agent-'+identity,'user_subject':user,'owner':'operator','pane':current['pane_id'],
                       'terminal':current['terminal_id'],'native':current.get('agent_session'),'content':content,'control':control})
    return roster


def complete_auth(cfg,ask,say):
    say('OAuth/HTTPS settings come from your provider. Enter known values; Enter leaves missing settings for later. No tokens or private keys are requested.')
    for field,label in [('issuer','OAuth issuer HTTPS URL'),('resource','Canonical HTTPS resource/audience ending /mcp (also used with a private tunnel)'),('public_key','Issuer RSA PUBLIC-key file (PEM)')]:
        if missing(cfg[field]) or (field=='public_key' and not Path(cfg[field]).is_file()):
            answer=ask(label+': ').strip()
            if answer:cfg[field]=str(Path(answer).expanduser().absolute()) if field=='public_key' else answer
    users=cfg.get('session_users',[])+[s['user_subject'] for s in cfg['subjects']]
    if any(missing(u) for u in users):
        answer=ask('Your OAuth user subject (sub); Enter to finish later: ').strip()
        if answer:
            cfg['session_users']=[answer if missing(u) else u for u in cfg.get('session_users',[])]
            for s in cfg['subjects']:
                if missing(s['user_subject']):s['user_subject']=answer
    if not missing(cfg['public_key']) and Path(cfg['public_key']).exists():public_key(cfg['public_key'])
    validate_config(cfg)


def save_config(path,cfg,previous=None):
    body=json.dumps(cfg,indent=2)+'\n'
    if len(body.encode())>65536:raise Rejected('configuration_too_large')
    private_directory(path.parent);private_directory(Path(cfg['store']).parent)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.setup-',dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write(body);stream.flush();os.fsync(stream.fileno())
        if previous is None:os.link(temporary,path)  # Atomic, refuses overwrite.
        else:
            if Path(cfg['store']).exists():raise Rejected('initialized_configuration_use_explicit_operator_edit')
            if path.is_symlink() or path.read_bytes()!=previous:raise Rejected('configuration_changed_run_setup_again')
            os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:temporary.unlink(missing_ok=True)


async def configure(path,socket_path=None,ask=input,say=print,client_factory=HerdrClient):
    raw_ask=ask
    ask=lambda prompt:ask_clean(raw_ask,prompt)
    path=Path(path).expanduser().absolute()
    say('dot-herdr setup — reads existing Herdr metadata and saves private config. It does not start agents, the connector or external services.')
    previous=None
    if path.exists() or path.is_symlink():
        cfg=load_config(path);previous=path.read_bytes()
        if socket_path and socket_path!=cfg['socket']:raise Rejected('existing_setup_socket_mismatch')
        if Path(cfg['store']).exists():
            say('Existing initialized configuration retained: '+str(path));return report(path,say)
        if not placeholders(cfg) and all(c['status']!='blocked' for c in doctor(path)['checks']):return report(path,say)
        say('Continuing pending setup; selected identities and access grants are retained.')
    else:
        selected=Path(choose_socket(socket_path,ask,say))
        if not selected.is_absolute() or selected.is_symlink() or not selected.exists() or not stat.S_ISSOCK(selected.stat().st_mode):raise Rejected('source_socket_required')
        source=client_factory(str(selected));pong=await source.request('ping',{})
        if pong.get('version')!='0.9.3' or pong.get('protocol')!=22:raise Rejected('unsupported_source_version')
        say('Access: 1) monitor selected agents; 2) monitor and control selected agents; 3) whole-session reads/control (commands, plugins and administration).')
        mode=ask('Access choice [1/2/3]: ').strip()
        if mode not in ('1','2','3'):raise Rejected('invalid_access_selection')
        full=mode=='3';user='replace-with-approved-issuer-subject'
        cfg={'store':str(path.parent/'state'/'connector.sqlite'),'socket':str(selected),
             'issuer':TEMPLATE['issuer'],'resource':TEMPLATE['resource'],'public_key':TEMPLATE['public_key'],
             'subjects':await choose_agents(source,full,mode in ('2','3'),user,ask,say),'session_users':[user] if full else []}
    complete_auth(cfg,ask,say);save_config(path,cfg,previous)
    return report(path,say)


def report(path,say):
    checks=doctor(path);blocked=[c['name'] for c in checks['checks'] if c['status']=='blocked']
    say('Configuration: '+str(path))
    if blocked:
        say('Local setup saved; still needed: '+', '.join(blocked)+'.')
        if Path(load_config(path)['store']).exists():
            say('Restore the missing prerequisites or explicitly edit this initialized configuration with the connector stopped; setup retained its grants.')
        else:say('Obtain missing OAuth/HTTPS settings and the RSA public key, then run dot-herdr setup again (use --config for a custom location).')
    else:
        cfg=load_config(path);control=bool(cfg.get('session_users')) or any(s.get('control') for s in cfg['subjects'])
        say('Local checks passed. Required OAuth scopes: herdr:observe'+(' and herdr:control' if control else '')+'.')
        say('When OAuth/HTTPS is configured, start with dot-herdr run (use --config for a custom location), then connect the endpoint to your dot.')
    say('OAuth, network connectivity, callback delivery and dot/skill import are not validated by local setup. Desktop/tunnel preparation uses dot-herdr connect.')
    return checks


def draft_path(config):
    return Path(config).with_name(Path(config).name+'.draft.json')


def pending_auth_path(config):
    return Path(config).with_name(Path(config).name+'.pending-auth.json')


def pending_auth(config,socket,resource=None,issuer=None,confirmed_same_origin=False):
    from .auth import https_url
    from .connections import read_file,write_file,encoded
    path=pending_auth_path(config);raw=read_file(path,8192)
    if raw is not None:
        if path.stat().st_mode & 0o077:raise Rejected('private_pending_auth_required')
        try:value=json.loads(raw)
        except (ValueError,TypeError):raise Rejected('invalid_pending_auth') from None
        if not isinstance(value,dict) or set(value)-{'socket','resource','issuer','confirmed_same_origin'} or value.get('socket')!=socket:raise Rejected('pending_auth_source_changed')
        for field in ('resource','issuer'):
            if field in value:https_url(value[field])
        if 'confirmed_same_origin' in value and value['confirmed_same_origin']!=value.get('issuer'):raise Rejected('invalid_pending_auth')
    else:value={'socket':socket}
    if resource is not None:
        https_url(resource)
        if resource!=value.get('resource'):value.pop('issuer',None);value.pop('confirmed_same_origin',None)
        value['resource']=resource
    if issuer is not None:
        https_url(issuer)
        if issuer!=value.get('issuer'):value.pop('confirmed_same_origin',None)
        value['issuer']=issuer
    if confirmed_same_origin:
        if issuer is None or value.get('issuer')!=issuer:raise Rejected('invalid_pending_auth')
        value['confirmed_same_origin']=issuer
    if resource is not None or issuer is not None or confirmed_same_origin:
        write_file(path,encoded(value),raw,backup=False);path.chmod(0o600)
    return value


def _setup_choices(config, **updates):
    """Persist only non-secret choices needed before exposure/provider completion."""
    from .connections import read_file,write_file,encoded
    path=Path(config).with_name(Path(config).name+'.setup-choices.json')
    raw=read_file(path,8192)
    if raw is not None:
        if path.stat().st_mode & 0o077:raise Rejected('private_setup_choices_required')
        try:value=json.loads(raw)
        except (ValueError,TypeError):raise Rejected('invalid_setup_choices') from None
        if not isinstance(value,dict) or set(value)-{'cloudflare','hostname','mode','builtin','offer_builtin'}:raise Rejected('invalid_setup_choices')
        if any(value.get(k) not in (None,True,False) for k in ('cloudflare','builtin','offer_builtin')):raise Rejected('invalid_setup_choices')
        if value.get('mode') not in (None,'api','login'):raise Rejected('invalid_setup_choices')
        if 'hostname' in value:
            from .cloudflare import ingress_rules
            ingress_rules(value['hostname'],8000)
    else:value={}
    if updates:
        value.update(updates);write_file(path,encoded(value),raw,backup=False);path.chmod(0o600)
    return value


def _cloudflare_note(hostname,say):
    say("Cloudflare's bot protection blocks ChatGPT's calls. Turn it off for "+hostname+", or add a rule that skips it for this hostname, before adding the plugin. dot-herdr never changes zone security settings.")


async def _public_signin_fetch(url):
    """Use the auth fetch bounds, retaining only safe Cloudflare failure categories."""
    import asyncio
    import httpx2
    from .auth import https_url,MAX_DOCUMENT
    https_url(url)
    try:
        async with asyncio.timeout(8):
            async with httpx2.AsyncClient(trust_env=False,follow_redirects=False,timeout=5) as client:
                async with client.stream('GET',url,headers={'Accept':'application/json','Accept-Encoding':'identity'}) as response:
                    reason=_public_signin_failure(response.status_code,response.headers,b'',url)
                    if reason:raise Rejected(reason)
                    if response.headers.get('content-encoding','identity').lower()!='identity':raise Rejected('auth_encoded_document_not_allowed')
                    data=bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data)>MAX_DOCUMENT:raise Rejected('auth_document_too_large')
                    reason=_public_signin_failure(response.status_code,response.headers,bytes(data),url)
                    if reason:raise Rejected(reason)
                    if response.status_code!=200:raise Rejected('auth_discovery_unavailable')
        try:value=json.loads(data)
        except (ValueError,UnicodeDecodeError):raise Rejected('invalid_auth_document') from None
        if not isinstance(value,dict):raise Rejected('invalid_auth_document')
        return value
    except (httpx2.TimeoutException,TimeoutError):raise Rejected('cloudflare_timeout') from None
    except httpx2.HTTPError:raise Rejected('cloudflare_tunnel_down') from None


_PUBLIC_SIGNIN_FAILURES=(
    ('cloudflare_bot_protection',403,{'cf-mitigated':'challenge'},b''),
    ('cloudflare_tunnel_down',530,{},b''),
    ('cloudflare_timeout',524,{},b''),
)


def _public_signin_failure(code,headers,body,resource):
    from .login import _cloudflare_advice
    advice=_cloudflare_advice(code,headers,body,resource)
    if advice:
        for reason,status,signals,sample in _PUBLIC_SIGNIN_FAILURES:
            if advice==_cloudflare_advice(status,signals,sample,resource):return reason
    return None


def _public_signin_advice(reason,resource):
    from .login import _cloudflare_advice
    for category,code,headers,body in _PUBLIC_SIGNIN_FAILURES:
        if reason==category:return _cloudflare_advice(code,headers,body,resource)
    return 'Public sign-in confirmation failed ('+reason+').'


async def _confirm_public_signin_once(cfg,fetch=None):
    from .auth import discover_provider
    fetch=fetch or _public_signin_fetch
    failures=[]
    async def checked_fetch(url):
        try:return await fetch(url)
        except Rejected as error:
            failures.append(str(error));raise
    try:recipe=await discover_provider(cfg['issuer'],cfg['resource'],cfg.get('oauth_client_id'),fetch=checked_fetch,allow_oidc=False)
    except Rejected:
        if failures:raise Rejected(failures[-1]) from None
        raise
    if recipe['issuer']!=cfg['issuer'] or recipe['jwks_url']!=cfg['jwks_url']:raise Rejected('provider_key_origin_changed')
    keys=await fetch(cfg['jwks_url'])
    if not isinstance(keys,dict) or not isinstance(keys.get('keys'),list) or not 1<=len(keys['keys'])<=128:raise Rejected('invalid_provider_jwks')
    from jwt import PyJWK,PyJWTError
    try:
        for key in keys['keys']:
            if not isinstance(key,dict) or key.get('kty')!='RSA':raise ValueError
            PyJWK.from_dict(key,algorithm='RS256')
    except (ValueError,TypeError,KeyError,PyJWTError):raise Rejected('invalid_provider_jwks') from None


async def _confirm_public_signin(cfg,fetch=None,*,child=None,deadline=float('inf'),clock=time.monotonic,sleep=None):
    """Allow tunnel propagation, bounded by both startup and pairing windows."""
    import asyncio
    sleep=sleep or asyncio.sleep
    end=min(clock()+60,deadline)
    delay=1
    last=None
    while clock()<end:
        if child is not None and child.returncode is not None:break
        try:
            async with asyncio.timeout(end-clock()):
                await _confirm_public_signin_once(cfg,fetch)
            return
        except TimeoutError:
            last=Rejected('cloudflare_timeout')
        except Rejected as error:
            if str(error) not in ('cloudflare_tunnel_down','cloudflare_timeout'):raise
            last=error
        # Poll during backoff so a stopped child cannot consume the whole window.
        until=min(clock()+delay,end)
        while clock()<until:
            if child is not None and child.returncode is not None:raise last
            await sleep(min(.2,until-clock()))
        delay=min(delay*2,8)
    raise last or Rejected('cloudflare_tunnel_down')


async def _pairing_identity(path,cfg,record,*,ask=input,say=print,browser=True,timeout=600,public_fetch=None):
    """Own an auth-only listener until a locally selected verified account is confirmed."""
    import asyncio
    import time
    import uvicorn
    from .auth import verifier_from_config
    from .endpoint import PairingSession,build_pairing
    from .connections import save_connection
    from .status import port_in_use
    if port_in_use(cfg.get('local_port',8000)):raise Rejected('pairing_port_occupied_stop_listener_explicitly')
    from .runtime import builtin_signin_routes,tunnel_provider,launch_tunnel,reap_tunnel
    signin_routes=builtin_signin_routes(path,cfg)
    provider=tunnel_provider(path,cfg,tunnel=record['route']=='tunnel',exposure=record.get('exposure'))
    pairing=PairingSession(cfg['issuer'],ttl=timeout)
    verifier=verifier_from_config(cfg)
    class DiagnosticVerifier:
        async def verify_token(self,token):
            verified=await verifier.verify_token(token)
            if verified is None:say('Authenticated pairing request rejected: token_verification_failed.')
            return verified
    observe=pairing.observe
    def diagnostic_observe(token):
        try:return observe(token)
        except Rejected as error:
            reason=str(error)
            if reason not in ('pairing_expired_or_closed','pairing_identity_denied','pairing_identity_expired','pairing_candidate_limit'):
                reason='pairing_request_rejected'
            say('Authenticated pairing request rejected: '+reason+'.')
            raise
    pairing.observe=diagnostic_observe
    server=build_pairing(DiagnosticVerifier(),cfg['issuer'],cfg['resource'],pairing,local_port=cfg.get('local_port',8000),
                         **({'signin_routes':signin_routes} if signin_routes is not None else {}))
    app=server.streamable_http_app(json_response=True,stateless_http=True,max_request_body_size=65536,host='127.0.0.1')
    http=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=cfg.get('local_port',8000),log_level='warning',access_log=False,proxy_headers=False))
    async def serve():
        try:await http.serve()
        except SystemExit:raise Rejected('pairing_listener_failed') from None
    serving=asyncio.create_task(serve());child=None;watcher=None
    try:
        deadline=time.monotonic()+min(10,timeout)
        while not http.started:
            if serving.done():await serving;raise Rejected('pairing_listener_failed')
            if time.monotonic()>deadline:raise Rejected('pairing_listener_timeout')
            await asyncio.sleep(.05)
        if provider:
            child=await launch_tunnel(provider)
            watcher=asyncio.create_task(child.wait())
        if cfg.get('signin')=='builtin' and public_fetch is not None:
            try:await _confirm_public_signin(cfg,public_fetch,child=child,deadline=pairing.deadline,clock=pairing.clock)
            except Rejected as error:
                record['stage']='public-provider';record['pending']=_public_signin_advice(str(error),cfg['resource'])+' Resume setup here after repairing public reachability.'
                save_connection(path,record);say(record['pending']);raise Rejected('public_signin_confirmation_pending') from None
            say('Built-in sign-in metadata and public signing keys confirmed through the public URL.')
        if record.get('exposure',{}).get('provider')=='cloudflare':_cloudflare_note(record['exposure']['hostname'],say)
        already_added=bool(record.get('identity') or record.get('last_authentication'))
        record['stage']='identity';save_connection(path,record)
        if record['wiring']=='registered-plugin':
            if record.get('client_app')=='desktop':
                say('Your Herdr plugin is already connected in the ChatGPT/Codex desktop app. Ask it to run get_profile; your account will appear here.' if already_added else 'In the ChatGPT/Codex desktop app, open the Plugins Directory and install the Herdr plugin connected to '+record['endpoint']+'. Complete provider sign-in if prompted'+(' and tick "Also allow Herdr control" on the password page. In the Herdr plugin settings, switch tool access from low-risk only to allow all tools; control actions are marked as write actions, so the low-risk setting blocks them' if cfg.get('session_users') or any(s.get('control') for s in cfg['subjects']) else '')+'. Then ask the plugin to run get_profile. Your account will appear here within ten minutes.')
            else:
                say('Your Herdr plugin is already added in ChatGPT in a web browser (chatgpt.com). In that ChatGPT conversation, ask the Herdr plugin to run get_profile. Your account will appear here; do not type anything in this terminal until it does.' if already_added else 'If the plugin is not added yet, open ChatGPT in a web browser (chatgpt.com): Settings → Plugins → + → Add custom MCP server → enter '+record['endpoint']+' → Create as a plugin → password page'+(' (tick "Also allow Herdr control" if you selected control). In the Herdr plugin settings, switch tool access from low-risk only to allow all tools; control actions are marked as write actions, so the low-risk setting blocks them' if cfg.get('session_users') or any(s.get('control') for s in cfg['subjects']) else '')+'. Return to Settings, then use the Herdr plugin once in the same ChatGPT web UI (for example, ask it to run get_profile). Your account will appear here within ten minutes; do not type anything in this terminal until it does.')
        if record['wiring']=='standalone' and browser:
            from .login import login_mcp
            # Draft identities remain placeholders; login needs only approved auth
            # settings and selected scopes, never an inferred subject.
            result=await login_mcp(cfg,endpoint=record['endpoint'],allow_pairing=True)
            if result.get('status')=='authenticated':
                from .login import request_authenticated_discovery
                await request_authenticated_discovery(timeout=max(1,min(30,pairing.deadline-pairing.clock())))
        if record['wiring']=='standalone':say('Finish sign-in in the browser page opened by this terminal. The verified account will appear here for approval; no input is needed in this terminal while waiting. This window lasts ten minutes.')
        deadline=pairing.deadline
        while True:
            if pairing.clock()>=deadline:return None
            if pairing.candidates():break
            if watcher and watcher.done():
                raise Rejected(provider.failed if watcher.result() else provider.stopped)
            if serving.done():raise Rejected('pairing_transport_stopped')
            await asyncio.sleep(.2)
        # Keep HTTP responsive while local consent is read. Default stdin has a
        # bounded reader so expiration does not leave an executor input thread.
        candidates=pairing.candidates();verified_at=time.time()
        selected=await confirm_candidate(candidates,cfg['issuer'],lambda prompt:answer_before_deadline(prompt,ask,say,pairing.deadline,pairing.clock),say,pairing.deadline,pairing.clock,control_selected=bool(cfg.get('session_users') or any(s.get('control') for s in cfg['subjects'])),client_app=record.get('client_app','chatgpt-web'))
        if not selected:return None
        identity=pairing.confirm(selected)
        approved=next(c for c in candidates if c['principal']==selected)
        if identity.get('client_id')!=approved['client_id'] or identity.get('scopes')!=approved['scopes']:raise Rejected('pairing_candidate_changed_retry')
        identity['verified_at']=verified_at
        return identity
    finally:
        pairing.close();http.should_exit=True
        try:await asyncio.wait_for(asyncio.shield(serving),5)
        except (asyncio.TimeoutError,asyncio.CancelledError):
            serving.cancel();await asyncio.gather(serving,return_exceptions=True)
        except Exception:
            pass  # Preserve the stage failure and still reap the owned tunnel.
        if watcher:watcher.cancel();await asyncio.gather(watcher,return_exceptions=True)
        await reap_tunnel(child,provider)


async def _guided_setup(path,socket_path=None,*,ask=input,say=print,client_factory=HerdrClient,interactive=True,
                       endpoint=None,app_id=None,tunnel_id=None,wiring=None,route=None,launch=True,login=True,
                       prepare=True,download=True,oauth_client_id=None,client_app=None,public_fetch=None,hidden_prompt=None):
    from .auth import CONTROL_SCOPE_REMEDY as _remedy
    check_say=lambda message:None if message.startswith('This sign-in allows observation only.') else say(message)
    """Resume private drafts and choices; persisted stages never substitute for live facts."""
    import asyncio
    from .connections import connection_record,save_connection,read_file,write_file,encoded,prepare_connections,LOCAL_URL,local_url
    from .auth import discover_provider,discover_resource
    from .status import account_access,runtime_observation,port_in_use
    raw_ask=ask
    ask=lambda prompt:ask_clean(raw_ask,prompt)
    path=Path(path).expanduser().absolute();draft=draft_path(path)
    private_directory(path.parent)
    record=connection_record(path)
    def finish_setup(check,background):
        Path(path).with_name(Path(path).name+'.setup-choices.json').unlink(missing_ok=True)
        access=account_access(cfg,record)
        say('Connector running in background: '+('yes' if background else 'no'))
        say('Account approved: '+('yes' if record.get('identity') else 'no'))
        say('Account access: '+access)
        if not background:step='Run dot-herdr run in a separate terminal when you need the connection.'
        elif check.get('phase')=='control_scope':step=('In the ChatGPT/Codex desktop app, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page.' if record.get('client_app')=='desktop' else 'In ChatGPT in a web browser (chatgpt.com), open Settings → Plugins, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page.')+' In the Herdr plugin settings, switch tool access from low-risk only to allow all tools; control actions are marked as write actions, so the low-risk setting blocks them.'
        elif check.get('phase')=='test_target':step='Run dot-herdr access to add a disposable agent with control, then run dot-herdr check-connection.'
        elif check.get('status')=='complete':step='Use the Herdr plugin in '+('the ChatGPT/Codex desktop app.' if record.get('client_app')=='desktop' else 'ChatGPT in a web browser (chatgpt.com).')
        else:step='Run dot-herdr check-connection to continue the saved test.'
        say('Next: '+step)
    def pending(stage,message):
        record['stage']=stage;record['pending']=message;save_connection(path,record);say(message)
        return {'status':'pending','stage':stage,'next_action':message}
    previous=None;reselect=None
    if path.exists():
        cfg=load_config(path);previous=path.read_bytes()
        if socket_path and socket_path!=cfg['socket']:raise Rejected('existing_setup_socket_mismatch')
        if cfg.get('inactive'):return pending('access','In this terminal, run dot-herdr access to select grants.')
        if placeholders(cfg) and Path(cfg['store']).exists():return pending('configuration','In this terminal, restore the initialized configuration prerequisites before resuming setup.')
    elif draft.exists():
        cfg=load_config(draft)
        if record.get('stage')=='source' and interactive:
            reselect=cfg;cfg=None
            say('Select the source and access again; replacement identities require fresh local approval.')
        else:
            if socket_path and socket_path!=cfg['socket']:raise Rejected('existing_setup_socket_mismatch')
            say('Resuming the saved source identities and selected access.')
    else:
        cfg=None
    if cfg is None:
        say('Choose Cloudflare with your domain, or use an existing HTTPS MCP URL and sign-in service.')
        if not interactive:return pending('access','In this terminal, run interactive setup to select the Herdr session and access.')
        selected=Path(choose_socket(socket_path,ask,say))
        if not selected.is_absolute() or selected.is_symlink() or not selected.exists() or not stat.S_ISSOCK(selected.stat().st_mode):raise Rejected('source_socket_required')
        source=client_factory(str(selected));pong=await source.request('ping',{})
        if pong.get('version')!='0.9.3' or pong.get('protocol')!=22:raise Rejected('unsupported_source_version')
        say('Access: 1) monitor selected agents; 2) monitor/control selected agents; 3) whole-session reads/control.')
        mode=ask('Access choice [1/2/3]: ').strip()
        if mode not in ('1','2','3'):raise Rejected('invalid_access_selection')
        user='replace-with-approved-issuer-subject'
        cfg={'store':str(path.parent/'state'/'connector.sqlite'),'socket':str(selected),'issuer':TEMPLATE['issuer'],'resource':TEMPLATE['resource'],'public_key':TEMPLATE['public_key'],
             'subjects':await choose_agents(source,mode=='3',mode in ('2','3'),user,ask,say),'session_users':[user] if mode=='3' else []}
        if reselect is None:save_config(draft,cfg)
        else:
            choices=pending_auth(path,reselect['socket'])
            cfg={**reselect,**{key:cfg[key] for key in ('socket','subjects','session_users')}}
            old=read_file(draft);write_file(draft,encoded(cfg),old,backup=False)
            if read_file(pending_auth_path(path)) is not None:
                choices['socket']=cfg['socket']
                old=read_file(pending_auth_path(path));write_file(pending_auth_path(path),encoded(choices),old,backup=False)
            for key in ('identity','approved_client_id','verified_client_scopes','last_verified_scopes','check'):
                record.pop(key,None)
            record['stage']='route';save_connection(path,record)
    if oauth_client_id:
        if cfg.get('oauth_client_id') not in (None,oauth_client_id):raise Rejected('existing_oauth_client_id_mismatch')
        if previous is not None and 'oauth_client_id' not in cfg:raise Rejected('initialized_client_selection_requires_explicit_migration')
        cfg['oauth_client_id']=oauth_client_id
        validate_config(cfg)
        if previous is None:
            old=read_file(draft);write_file(draft,encoded(cfg),old,backup=False)
    # Verify source readiness and exact identity again even on resumed setup.
    source=client_factory(cfg['socket'])
    try:
        pong=await source.request('ping',{})
        if pong.get('version')!='0.9.3' or pong.get('protocol')!=22:raise Rejected('unsupported_source_version')
        for subject in cfg['subjects']:
            current=await source.agent(subject['pane'])
            if current.get('pane_id')!=subject['pane'] or current.get('terminal_id')!=subject['terminal'] or current.get('agent_session')!=subject.get('native'):raise Rejected('identity_changed_use_access')
    except (Rejected,OSError) as error:
        command='dot-herdr access to review the selected source' if previous is not None else 'dot-herdr setup to reselect the source and access with fresh local approval'
        return pending('source','Selected source is unavailable or changed ('+str(error)+'). In this terminal, run '+command+'.')
    if client_app and client_app not in ('chatgpt-web','desktop'):raise Rejected('invalid_client_app')
    if record.get('client_app') and client_app and client_app!=record['client_app']:raise Rejected('existing_client_app_change_requires_explicit_migration (run dot-herdr migrate-route --client-app)')
    if not record.get('client_app'):
        if client_app:selected_app=client_app
        elif record.get('route') or not interactive:selected_app='chatgpt-web'
        else:
            selected_app={'1':'chatgpt-web','2':'desktop'}.get(ask('Where will you use Herdr? 1) ChatGPT in a web browser (chatgpt.com) 2) ChatGPT/Codex desktop app [1/2]: ').strip())
            if not selected_app:raise Rejected('invalid_client_app_selection')
        record['client_app']=selected_app;save_connection(path,record)
    if app_id and record['client_app']!='desktop':raise Rejected('app_id_requires_desktop_client_app')
    if not record.get('route'):
        if not interactive and not route:return pending('route','In this terminal, run interactive setup to choose the connection route.')
        choice=route or {'1':'tunnel','2':'https','3':'loopback','4':'cloudflare','cloudflare':'cloudflare'}.get(ask('Route: 4) Cloudflare (I have a domain on Cloudflare); 2) I already have an HTTPS URL; 1) eligible Secure MCP Tunnel; 3) advanced loopback [4/2/1/3]: ').strip())
        if choice=='cloudflare' and route is None:
            _setup_choices(path,cloudflare=True);choice='https'
        if choice not in ('tunnel','https','loopback'):raise Rejected('invalid_connection_route')
        record.update(route=choice,wiring=wiring or 'registered-plugin')
        save_connection(path,record)
    if route and route!=record['route'] or wiring and wiring!=record['wiring']:raise Rejected('existing_route_change_requires_explicit_migration (run dot-herdr migrate-route)')
    choices_setup=_setup_choices(path)
    if choices_setup.get('cloudflare') and not record.get('exposure'):
        from . import cloudflare
        from .cli import cloudflare_token
        hostname=choices_setup.get('hostname')
        if not hostname:
            if not interactive:return pending('cloudflare-hostname','Resume interactive setup to enter the Cloudflare hostname.')
            hostname=ask('Cloudflare hostname (DNS name, e.g. herdr.example.com; Enter to pause): ').strip().lower()
            if not hostname:return pending('cloudflare-hostname','Resume setup to enter the Cloudflare hostname.')
            cloudflare.ingress_rules(hostname,cfg.get('local_port',8000))
            choices_setup=_setup_choices(path,hostname=hostname)
        if endpoint and endpoint!='https://'+hostname+'/mcp':raise Rejected('connection_endpoint_selection_mismatch')
        detected=cloudflare.detect_cloudflared()
        if not detected:return pending('cloudflare-install','Install cloudflared, then resume setup. '+cloudflare.INSTALL_DOCS)
        say('cloudflared: '+detected['path']+'; '+detected['version'])
        mode=choices_setup.get('mode')
        if not mode:
            if not interactive:return pending('cloudflare-credentials','Resume interactive setup to choose API token or --login fallback.')
            answer=ask('Cloudflare: 1) API token (recommended); 2) --login browser fallback (Enter to pause) [1/2]: ').strip()
            if not answer:return pending('cloudflare-credentials','Resume setup to choose API token or --login fallback.')
            mode={'1':'api','2':'login'}.get(answer)
            if not mode:raise Rejected('invalid_cloudflare_mode')
            choices_setup=_setup_choices(path,mode=mode)
        if not interactive:return pending('cloudflare-credentials','Resume interactive setup to authorize Cloudflare exposure.')
        try:
            if mode=='login':
                exposure=cloudflare.expose_login(path,hostname,cfg.get('local_port',8000),cloudflared=detected['path'],say=say)
            else:
                token=cloudflare_token()
                try:exposure=await cloudflare.expose_api(path,hostname,cfg.get('local_port',8000),token,cloudflared=detected['path'],say=say)
                finally:token=None
        except (Rejected,OSError,EOFError):return pending('cloudflare-exposure','Cloudflare exposure is pending. Resume setup after checking credentials, ownership and cloudflared prerequisites.')
        record['exposure']=exposure;save_connection(path,record)
    if choices_setup.get('cloudflare') and missing(cfg['resource']):
        pending_auth(path,cfg['socket'],resource='https://'+choices_setup['hostname']+'/mcp')
    if missing(cfg['issuer']) and choices_setup.get('cloudflare') and 'builtin' not in choices_setup:
        say("Use the built-in sign-in service (recommended if you don't already run one), or discover an existing sign-in service.")
        if not interactive:return pending('provider-choice','Resume interactive setup to choose the sign-in service.')
        answer=ask('Sign-in service: 1) built-in (recommended); 2) existing discovery [1/2, Enter=1]: ').strip()
        if answer not in ('','1','2'):raise Rejected('invalid_sign_in_service_selection')
        choices_setup=_setup_choices(path,builtin=answer!='2')
    if (missing(cfg['issuer']) or missing(cfg['resource'])) and not choices_setup.get('builtin'):
        entered_url=False;resource_advertised=False
        choices=pending_auth(path,cfg['socket'],resource=endpoint)
        selected=endpoint or choices.get('resource')
        if not selected:
            if not interactive:return pending('provider','In this setup terminal, run interactive setup and enter the existing MCP URL.')
            selected=ask('Existing HTTPS MCP URL (Enter to pause setup): ').strip()
            if not selected:return pending('provider','In this setup terminal, resume setup and enter the existing MCP URL.')
            choices=pending_auth(path,cfg['socket'],resource=selected)
            entered_url=True
        try:
            discovered=await discover_resource(selected,client_id=cfg['oauth_client_id']) if cfg.get('oauth_client_id') else await discover_resource(selected)
            resource_advertised=True
            issuers=discovered['issuers']
            issuer=choices.get('issuer') if choices.get('issuer') in issuers else None
            if issuer is None and len(issuers)==1:issuer=issuers[0]
            if issuer is None:
                if not interactive:return pending('provider','In this setup terminal, choose the sign-in service for the saved MCP URL.')
                for index,value in enumerate(issuers,1):say(str(index)+'. Sign-in service: '+value)
                choice=ask('Sign-in service number (Enter to pause setup): ').strip()
                if not choice:return pending('provider','In this setup terminal, resume setup and choose the sign-in service.')
                if not choice.isdigit() or not 1<=int(choice)<=len(issuers):raise Rejected('invalid_sign_in_service_selection')
                issuer=issuers[int(choice)-1]
            fallback=discovered.get('source')=='same_origin_authorization_server'
            if fallback and choices.get('confirmed_same_origin')!=issuer:
                say("This URL's resource details are not available yet — it appears to forward to this computer, where the connector starts later in setup. Found the sign-in service at the same address: "+issuer+'.')
                if not interactive:return pending('provider','In this setup terminal, resume interactive setup and confirm using the sign-in service at '+issuer+'.')
                if ask('Use this same-address sign-in service for this URL? [y/N]: ').strip().lower() not in ('y','yes'):
                    return pending('provider','In this setup terminal, resume setup to confirm the same-address sign-in service at '+issuer+'.')
            pending_auth(path,cfg['socket'],issuer=issuer,confirmed_same_origin=fallback)
            recipe=await discover_provider(issuer,selected,cfg.get('oauth_client_id'))
        except Rejected as error:
            reason=str(error)
            problem={'auth_discovery_unavailable':"Could not reach this URL's resource details.",
                     'provider_discovery_unavailable':"Could not reach this URL's resource details or the same-address sign-in service.",
                     'provider_jwks_uri_and_scopes_supported_missing':'The sign-in service does not advertise its public signing keys (jwks_uri) or supported access permissions (scopes_supported).',
                     'provider_jwks_uri_missing':'The sign-in service does not advertise its public signing keys (jwks_uri).',
                     'provider_scopes_supported_missing':'The sign-in service does not advertise supported access permissions (scopes_supported).',
                     'protected_resource_mismatch':'The MCP server advertises a different URL than the one entered.'}.get(reason,('The sign-in service is incompatible' if reason.startswith('provider_') else 'Published discovery details are invalid')+' ('+reason+').')
            action=('In this setup terminal, resume when the URL or sign-in service answers.' if reason in ('auth_discovery_unavailable','provider_discovery_unavailable') else
                    'In this setup terminal, resume after the sign-in service metadata is corrected.' if reason.startswith('provider_') else
                    "In this setup terminal, resume after the URL's resource details are corrected.")
            message=problem+' '+action
            if (record['route']!='https' or choices_setup.get('cloudflare') or not interactive or resource_advertised or
                    not (entered_url or choices_setup.get('offer_builtin'))):return pending('provider',message)
            choices_setup=_setup_choices(path,offer_builtin=True)
            say("1) Use the built-in sign-in service (recommended if you don't already run one); 2) Stop and fix the advertised sign-in service")
            try:answer=ask('Sign-in service [1/2, Enter to pause]: ').strip()
            except EOFError:return pending('provider',message)
            if answer in ('','2'):return pending('provider',message)
            if answer!='1':raise Rejected('invalid_sign_in_service_selection')
            choices_setup=_setup_choices(path,builtin=True)
        else:
            if not choices_setup.get('cloudflare'):
                say('This URL already advertises a sign-in service; using it. (The built-in sign-in service is for URLs without one.)')
            cfg['issuer']=issuer;cfg['resource']=selected;cfg.pop('public_key',None)
            cfg['jwks_url']=recipe['jwks_url'];validate_config(cfg)
            old=read_file(draft);write_file(draft,encoded(cfg),old,backup=False)
            pending_auth_path(path).unlink(missing_ok=True)
            say(('The same-address sign-in service is compatible. The URL\'s resource details will need verification when the connector is serving.' if fallback else 'The MCP URL matches its published server identity. Its sign-in service advertises compatible keys, permissions and public-client login.')+' A real account still needs approval in this terminal.')
    elif 'jwks_url' in cfg and cfg.get('signin')!='builtin':
        try:
            recipe=await discover_provider(cfg['issuer'],cfg['resource'],cfg.get('oauth_client_id'))
            if recipe['jwks_url']!=cfg['jwks_url']:raise Rejected('provider_key_origin_changed')
        except Rejected as error:return pending('provider','Provider recheck failed ('+str(error)+'). In this setup terminal, resume after the sign-in service metadata is repaired.')
    if missing(cfg['issuer']) and choices_setup.get('builtin'):
        from . import signin
        selected=endpoint or pending_auth(path,cfg['socket']).get('resource')
        if not selected:return pending('provider','Resume setup to enter the HTTPS MCP URL for built-in sign-in.')
        if not signin.has_password(signin.signin_root(path)):
            if not interactive:return pending('signin-password','Resume interactive setup to set the built-in sign-in password.')
            try:
                import getpass
                secret=signin.ask_new_password(getpass=hidden_prompt or getpass.getpass,say=say)
                try:signin.set_password(signin.signin_root(path),secret)
                finally:secret=None
            except (Rejected,EOFError):return pending('signin-password','Resume setup to set the built-in sign-in password using hidden input.')
        cfg.update(resource=selected,issuer=signin.issuer_for(selected),jwks_url=signin.jwks_url(signin.issuer_for(selected)),signin='builtin')
        cfg.pop('public_key',None);validate_config(cfg)
        old=read_file(draft);write_file(draft,encoded(cfg),old,backup=False)
        pending_auth_path(path).unlink(missing_ok=True)
    record['endpoint']=local_url(cfg) if record['route']=='loopback' else cfg['resource'];save_connection(path,record)
    if endpoint and endpoint!=record['endpoint']:raise Rejected('connection_endpoint_selection_mismatch')
    if record['route']=='loopback':return pending('route','Codex CLI (advanced): Codex 0.160.1 rejects this loopback discovery. In this terminal, review the saved route with dot-herdr status before migration.')
    if record['route']=='tunnel':
        from .tunnel import prepare_tunnel,profile_settings
        try:profile_settings(path)
        except (Rejected,OSError):
            selected=tunnel_id or (ask('Existing tunnel ID (Enter to resume later): ').strip() if interactive else '')
            if not selected:return pending('tunnel','In this setup terminal, resume with a tunnel ID authorized for the selected workspace.')
            try:prepare_tunnel(path,selected,download=download,say=say)
            except (Rejected,OSError) as error:return pending('tunnel','Tunnel preparation is pending ('+str(error)+'). In this setup terminal, resume after repairing the tunnel.')
        if not os.environ.get('CONTROL_PLANE_API_KEY'):return pending('tunnel','In this setup terminal, resume with the tunnel runtime key in CONTROL_PLANE_API_KEY.')
    if not prepare:return pending('wiring','In this setup terminal, resume setup to prepare the selected connection.')
    if record['wiring']=='standalone' and shutil.which('codex') is None:
        return pending('client','Codex CLI (advanced): the selected standalone connection requires Codex CLI. In this terminal, install Codex CLI before resuming setup.')
    if record['wiring']!='registered-plugin':
        result=prepare_connections(cfg,endpoint=record['endpoint'],app_id=app_id,wiring=record['wiring'],launch=launch,say=say,client_app=record['client_app'])
        if result['registration']['status'].startswith('pending'):return pending('wiring','In this setup terminal, resume after the MCP URL is reachable.')
        record['owned']={**record.get('owned',{}),**result.get('owned',{})};save_connection(path,record)
    elif app_id:
        if record.get('app_id') not in (None,app_id):raise Rejected('existing_registered_server_id_mismatch')
        record['app_id']=app_id;save_connection(path,record)
    users=cfg.get('session_users',[])+[s['user_subject'] for s in cfg['subjects']]
    if any(missing(u) for u in users):
        handoff='advanced Codex CLI browser sign-in' if record['wiring']=='standalone' else 'ChatGPT web Settings sign-in'
        if not interactive or not login or not launch:return pending('identity','In this setup terminal, resume interactive setup to open the ten-minute '+handoff+' and account approval window.')
        try:identity=await pairing_identity(path,cfg,record,ask=raw_ask,say=say,browser=login,**({'public_fetch':public_fetch or _public_signin_fetch} if cfg.get('signin')=='builtin' else {}))
        except (Rejected,EOFError):
            latest=connection_record(path)
            if latest.get('stage')=='public-provider':return {'status':'pending','stage':'public-provider','next_action':latest['pending']}
            return pending('identity','Sign-in stopped before account approval. Run dot-herdr setup here to open a new ten-minute '+handoff+' window.')
        if not identity:return pending('identity','No account was approved. Run dot-herdr setup here to open a new ten-minute '+handoff+' window.')
        cfg['session_users']=[identity['subject'] if missing(u) else u for u in cfg.get('session_users',[])]
        for subject in cfg['subjects']:
            if missing(subject['user_subject']):subject['user_subject']=identity['subject']
        # Pairing may take minutes; a replaced source never inherits the draft grants.
        for subject in cfg['subjects']:
            current=await source.agent(subject['pane'])
            if current.get('pane_id')!=subject['pane'] or current.get('terminal_id')!=subject['terminal'] or current.get('agent_session')!=subject.get('native'):
                raise Rejected('identity_changed_use_access')
        # Compare active config/draft and activate once, without changing grants.
        save_config(path,cfg,previous)
        record.update(identity=identity['principal'],last_authentication=__import__('time').time(),stage='runtime')
        record.pop('last_verified_scopes',None)
        if identity.get('client_id'):
            record['approved_client_id']=identity['client_id']
            record['verified_client_scopes']={identity['client_id']:{'scopes':identity.get('scopes',[]),'verified_at':identity['verified_at'],'expires_at':identity['expires_at']}}
        else:
            record.pop('approved_client_id',None);record.pop('verified_client_scopes',None)
        save_connection(path,record)
        old=read_file(draft)
        if old is not None:
            if json.loads(old).get('subjects') and not path.exists():raise Rejected('activation_incomplete')
            draft.unlink()
    elif not path.exists():save_config(path,cfg)
    if record['wiring']=='registered-plugin':
        try:result=prepare_connections(cfg,endpoint=record['endpoint'],app_id=app_id,wiring=record['wiring'],launch=launch,say=(lambda _:None) if not app_id else say,client_app=record['client_app'])
        except (Rejected,OSError) as error:return pending('wiring','Plugin preparation paused ('+str(error)+'). In this setup terminal, resume after repairing the plugin mapping.')
        record['owned']={**record.get('owned',{}),**result.get('owned',{})}
        if result.get('local_package'):record['local_package']=result['local_package']
        save_connection(path,record)
    # Associate custom data paths only with an existing connector-owned installer.
    try:
        from .maintenance import refresh_inventory
        refresh_inventory(Path.home()/'.local/share/dot-herdr',path,associate_data=True)
    except (Rejected,ValueError,OSError):pass
    # An initialized configuration proceeds through wiring/runtime/check stages.
    from .service import install,manage,service_status
    if 'background' not in record:
        if not interactive:return pending('runtime','In this setup terminal, run interactive setup to choose foreground or user-service operation.')
        background=ask('Keep the connector running in the background after setup? [y/N]: ').strip().lower() in ('y','yes')
        record['background']=background
        record['login_start']=background and ask('Start at user login? [y/N]: ').strip().lower() in ('y','yes')
        save_connection(path,record)
    if record['background']:
        credential=None
        if record['route']=='tunnel':
            if not interactive:return pending('runtime','In this setup terminal, resume interactively with a private tunnel credential file.')
            from .service import service_record
            try:credential=service_record(path).get('credential_file')
            except (Rejected,OSError):credential=None
            if not credential:credential=ask('Absolute private tunnel runtime-key file path (never paste its value): ').strip()
            if not credential:return pending('runtime','In this setup terminal, resume with the absolute path to a private tunnel credential file.')
        try:
            install(path,tunnel=record['route']=='tunnel',credential_file=credential,login_start=record.get('login_start',False))
            manage(path,'start')
        except (Rejected,OSError) as error:return pending('runtime','User service is pending ('+str(error)+'). In this setup terminal, resume after repairing its prerequisites.')
        for _ in range(100):
            manager=service_status(path);current=runtime_observation(path)
            if manager.get('state') in ('active','running') and manager.get('pid',0)>0 and manager['pid']==current.get('pid') and current.get('state')=='running' and current.get('runtime_prefix')==str(Path(sys.prefix).resolve()) and all(current.get('workers',{}).get(name)=='running' for name in ('observer','delivery')):break
            await asyncio.sleep(.1)
        else:return pending('runtime','In this setup terminal, inspect the owned service status and resume setup after its manager process and workers are ready.')
        record['stage']='check';save_connection(path,record)
        from .connection_check import check_connection
        check=await check_connection(path,interactive=interactive,ask=raw_ask,say=check_say)
        finish_setup(check,True)
        return check
    current=runtime_observation(path)
    if current['state']=='running':
        from .connection_check import check_connection
        check=await check_connection(path,interactive=interactive,ask=raw_ask,say=check_say)
        finish_setup(check,bool(record.get('background')))
        return check
    port=cfg.get('local_port',8000)
    if port_in_use(port):return pending('runtime',f'Port {port} has an unverified listener. In this terminal, identify and stop that listener before resuming setup.')
    from .runtime import run
    task=asyncio.create_task(run(path,cfg=cfg,tunnel=record['route']=='tunnel'))
    try:
        for _ in range(100):
            if task.done():await task;raise Rejected('setup_runtime_stopped')
            if runtime_observation(path)['state']=='running':break
            await asyncio.sleep(.1)
        else:return pending('runtime','The owned runtime did not become ready. In this terminal, inspect dot-herdr status before resuming setup.')
        record['stage']='check';save_connection(path,record)
        from .connection_check import check_connection
        check=await check_connection(path,interactive=interactive,ask=raw_ask,say=check_say)
        finish_setup(check,False)
        return check
    finally:
        task.cancel();await asyncio.gather(task,return_exceptions=True)


async def pairing_identity(path,cfg,record,*,ask=input,say=print,browser=True,timeout=600,public_fetch=None):
    """Bound the entire stage, including provider login and local confirmation."""
    import asyncio
    try:
        async with asyncio.timeout(timeout):
            return await _pairing_identity(path,cfg,record,ask=ask,say=say,browser=browser,timeout=timeout,public_fetch=public_fetch)
    except TimeoutError:
        return None


async def guided_setup(path,*args,**kwargs):
    from .connections import SetupLock
    with SetupLock(Path(path).expanduser().absolute()):
        return await _guided_setup(path,*args,**kwargs)
