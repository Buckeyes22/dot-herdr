"""Read-only operator observations. A receipt does not attest to a chat destination."""
import asyncio
import json
import os
import socket
import sqlite3
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from .core import Rejected
from .connections import LOCAL_URL, connection_record, read_file, local_url
from .setup import doctor, load_config, placeholders


def observation(state, next_action='', at=None, **facts):
    return {'state':state,'observed_at':at,'next_action':next_action,**facts}


def account_access(cfg,record):
    from .auth import approved_scope_evidence
    evidence=approved_scope_evidence(record)
    if evidence is None:return 'unknown'
    scopes=evidence['scopes']
    if 'herdr:observe' not in scopes:return 'unknown'
    if 'herdr:control' in scopes:return 'observe+control'
    return 'observe only (control selected but not granted at sign-in)' if cfg.get('session_users') or any(s.get('control') for s in cfg['subjects']) else 'observe only'


def runtime_observation(config, now=None):
    from .runtime import status_path, process_identity
    now=time.time() if now is None else now
    path=status_path(config)
    raw=read_file(path,65536)
    if raw is None:return observation('stopped','Start the connector or its owned user service.')
    try:
        if path.stat().st_mode & 0o077:raise ValueError
        value=json.loads(raw)
        updated=value['updated_at'];pid=value['pid']
        if value.get('config')!=str(Path(config).expanduser().absolute()) or not isinstance(updated,(int,float)) or isinstance(pid,bool) or not isinstance(pid,int):raise ValueError
        identity=process_identity(pid)
        current=identity is not None and identity==value.get('process_start') and -2<=now-updated<=10
        if value.get('state')=='stopped':return observation('stopped','Start the connector or its owned user service.',updated,last_verified_authentication=value.get('last_verified_authentication'))
        if value.get('state')=='failed':return observation('failed','Inspect the redacted runtime error, then repair and restart.',updated,error=value.get('error','runtime_failed'))
        if not current:return observation('stale','The saved runtime record is not evidence of a running connector.',updated)
        workers=value.get('workers',{})
        ready=value.get('http_started') and all(workers.get(k)=='running' for k in ('observer','delivery'))
        return observation('running' if ready else 'starting','' if ready else 'Wait for readiness or inspect service status.',updated,pid=pid,runtime_prefix=value.get('runtime_prefix'),workers=workers,tunnel=value.get('tunnel','unknown'),cloudflared=value.get('cloudflared','unknown'),last_verified_authentication=value.get('last_verified_authentication'))
    except (ValueError,KeyError,TypeError,OSError):return observation('invalid_record','Inspect the private runtime record; it could not be verified.')


def database_summary(path, now=None):
    """Do not construct Store, migrate, recover sends or acquire its owner lock."""
    now=time.time() if now is None else now
    path=Path(path)
    if not path.exists():return observation('not_initialized','Start only after identity confirmation.')
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:return observation('unsafe','Restore private database permissions.')
    db=None
    try:
        db=sqlite3.connect('file:'+quote(str(path),safe='/')+'?mode=ro',uri=True,timeout=0.5)
        db.execute('PRAGMA query_only=ON');db.row_factory=sqlite3.Row
        db.execute('BEGIN')
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'subscriptions','deliveries','receipts','subjects'}<=tables:return observation('unsupported_schema','Use the matching connector version; do not migrate during status.')
        live=db.execute('SELECT COUNT(*) FROM subscriptions s JOIN subjects p ON p.key=s.subject WHERE s.active=1 AND s.expires>? AND p.enabled=1',(now,)).fetchone()[0]
        expired=db.execute('SELECT COUNT(*) FROM subscriptions WHERE active=1 AND expires<=?',(now,)).fetchone()[0]
        accepted=db.execute("SELECT MAX(e.at) FROM deliveries d JOIN events e ON e.id=d.event WHERE d.state='accepted'").fetchone()[0]
        triage=db.execute('SELECT MAX(at) FROM receipts').fetchone()[0]
        return observation('observed',now=now,active_unexpired=live,expired=expired,last_transport_acceptance_event_at=accepted,last_authenticated_triage_report_at=triage,correct_dot='unknown',next_action='Renew an expired watch explicitly.' if expired and not live else '')
    except sqlite3.Error:return observation('unavailable','Retry after the database transaction finishes; no state was changed.')
    finally:
        if db is not None:db.close()


def port_in_use(port=8000):
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=0.2):return True
    except OSError:return False


def cloudflared_observation(config, record, runtime):
    from .connections import exposure_for
    from . import cloudflare
    exposure=exposure_for(record)
    if exposure is None:return observation('not_applicable')
    root=Path(config).expanduser().absolute().parent/'cloudflare'
    try:
        journal=cloudflare.Journal(config).read()
    except Rejected:
        return observation('journal_invalid','Repair or remove the private Cloudflare journal, then run dot-herdr status again.',
            binary='unknown',binary_path=None,credential='unknown',credential_files={},child=runtime.get('cloudflared','unknown') if isinstance(runtime,dict) else 'unknown',mode=exposure['mode'])
    try:recorded=cloudflare.recorded_cloudflared(config)
    except Rejected:
        return observation('journal_invalid','Repair or remove the private Cloudflare journal, then run dot-herdr status again.',
            binary='unknown',binary_path=None,credential='unknown',credential_files={},child=runtime.get('cloudflared','unknown') if isinstance(runtime,dict) else 'unknown',mode=exposure['mode'])
    binary=Path(recorded) if recorded else None
    if not recorded:
        from shutil import which
        found=which('cloudflared')
        binary=Path(found) if found else None
    binary_state='found' if binary and binary.is_file() and os.access(binary,os.X_OK) else 'missing'
    paths=({'token_file':journal['token_file']} if journal and exposure['mode']=='api' else
           {'config':journal['config'],'credentials':journal['credentials']} if journal and exposure['mode']=='login' else {})
    credential_files={}
    for name,path in paths.items():
        candidate=Path(path)
        try:
            st=candidate.stat(follow_symlinks=False)
            safe=(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not st.st_mode&0o077 and not candidate.is_symlink())
        except OSError:safe=False
        credential_files[name]={'path':str(candidate),'state':'present_private' if safe else 'missing_or_not_private'}
    credential_state='present_private' if credential_files and all(x['state']=='present_private' for x in credential_files.values()) else 'missing_or_not_private'
    child=runtime.get('cloudflared','unknown') if isinstance(runtime,dict) else 'unknown'
    action=''
    if binary_state=='missing':action='Install cloudflared from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/, then run dot-herdr service restart or dot-herdr run.'
    elif credential_state!='present_private':action='Restore the private Cloudflare file(s) named by the Cloudflare journal, then run dot-herdr status again.'
    elif child not in ('running','starting'):action='Start the connector with dot-herdr service start or dot-herdr run and inspect the cloudflared child.'
    return observation('ready' if binary_state=='found' and credential_state=='present_private' and child=='running' else 'observed',action,
        binary=binary_state,binary_path=str(binary) if binary else None,credential=credential_state,credential_files=credential_files,child=child,mode=exposure['mode'])


def overall(checks,cfg=None,live=False):
    if checks['configuration']['state']=='missing_or_invalid' or cfg and (cfg.get('inactive') or placeholders(cfg)):
        return {'verdict':'setup needs attention','next_action':checks['configuration'].get('next_action') or 'Run guided setup or restore private configuration permissions.'}
    runtime=checks['runtime']['state'];listener=checks['listener']['state']
    if runtime not in ('running','starting') and listener!='occupied':
        action='In this terminal, run dot-herdr service start' if checks['service'].get('installed') else 'In this terminal, run dot-herdr run in a normal terminal and keep it open'
        return {'verdict':'the connector is not running','next_action':action}
    if listener=='occupied':return {'verdict':'the local port is occupied','next_action':checks['listener']['next_action']}
    if live and checks['source']['state']=='unavailable':return {'verdict':'the Herdr session is not reachable','next_action':'Start the selected Herdr session ('+cfg['socket']+') or inspect its socket.'}
    if live and checks['source']['state']=='unsupported':return {'verdict':'the Herdr version/protocol is unsupported','next_action':checks['source']['next_action']}
    reach=checks['route']['public_reachability'];url=checks['route'].get('url')
    if live and runtime=='running' and reach.startswith('unreachable') and url:
        if checks['route'].get('cloudflare_advice'):
            return {'verdict':f'the connector runs on this computer, but {url} does not reach it ({reach.removeprefix("unreachable ")})','next_action':checks['route']['cloudflare_advice']}
        reason=reach.removeprefix('unreachable ')
        return {'verdict':f'the connector runs on this computer, but {url} does not reach it {reason}','next_action':f"Check the route that forwards that URL to this computer's port {cfg.get('local_port',8000)}."}
    if live and checks['discovery']['state']=='unavailable':
        return {'verdict':'the public metadata does not match','next_action':checks['discovery']['next_action']}
    if checks['authentication']['account_access']=='observe only (control selected but not granted at sign-in)':
        return {'verdict':'Herdr control needs account approval','next_action':'In ChatGPT Settings → Plugins, remove and add the selected Herdr plugin again with the same URL; tick Also allow Herdr control on the password page.'}
    if live:return {'verdict':'working','next_action':''}
    return {'verdict':'no problems found in local checks; run status --live to test the public URL','next_action':''}


async def status(config, *, live=False, client_factory=None):
    config=Path(config).expanduser().absolute();now=time.time()
    report={'version':1,'mode':'live_read_only' if live else 'offline_read_only','observed_at':now,'config':str(config),'observations':{},'correct_dot_delivery':'unknown'}
    checks=report['observations']
    try:cfg=load_config(config)
    except (Rejected,ValueError,OSError):
        checks['configuration']=observation('missing_or_invalid','Run guided setup or restore private configuration permissions.',now)
        report['overall']=overall(checks)
        return report
    offline=doctor(config)
    checks['configuration']=observation('inactive' if cfg.get('inactive') else 'valid_shape',at=now,checks=offline['checks'])
    checks['runtime']=runtime_observation(config,now)
    port=cfg.get('local_port',8000)
    if checks['runtime']['state'] not in ('running','starting') and port_in_use(port):checks['listener']=observation('occupied',f'Another listener owns port {port}. Stop it explicitly; setup will not replace it.',now)
    else:checks['listener']=observation('managed' if checks['runtime']['state']=='running' else 'not_observed',at=now)
    from .service import service_status
    try:checks['service']=service_status(config)
    except (Rejected,OSError):checks['service']=observation('unavailable','Use foreground operation or repair the user service manager.',now)
    socket_path=Path(cfg['socket'])
    present=socket_path.exists() and not socket_path.is_symlink() and stat.S_ISSOCK(socket_path.stat().st_mode)
    checks['source']=observation('present_unprobed' if present else 'missing','' if present else 'Start Herdr, then run dot-herdr access to select a running session and approve its agents.',now)
    record=connection_record(config)
    route=record.get('route');wiring=record.get('wiring');endpoint=record.get('endpoint') or (local_url(cfg) if route=='loopback' else cfg['resource'])
    local_package=record.get('local_package') if isinstance(record.get('local_package'),dict) else {}
    settings_plugin=wiring=='registered-plugin' and local_package.get('status')!='prepared'
    local_preparation='not_prepared' if settings_plugin else 'observed' if record.get('owned') else 'pending'
    checks['route']=observation('selected' if route else 'unselected','Select a connection route with setup.' if not route else '',now,url=endpoint if route else None,wiring=wiring,local_preparation=local_preparation,local_package_reason=local_package.get('reason') or ('plugin_created_in_chatgpt_settings' if settings_plugin else None),public_reachability='unknown',account_connection='unknown')
    client_app=record.get('client_app') or 'chatgpt-web'
    checks['wiring']=observation('settings_plugin' if settings_plugin else 'prepared' if record.get('owned') else 'pending',('Complete the Codex CLI (advanced) handoff.' if wiring=='standalone' else 'Complete the ChatGPT/Codex desktop app plugin connection.' if client_app=='desktop' else 'Complete the ChatGPT web plugin connection.') if not settings_plugin and not record.get('owned') else '',now,route=route,wiring=wiring,client_app=client_app)
    check=record.get('check') if isinstance(record.get('check'),dict) else {}
    phases=check.get('phases') if isinstance(check.get('phases'),dict) else {}
    destination=phases.get('destination_confirmation','pending')
    next_test_action={'pending':'Run check-connection to continue the saved test.','expired':'Run check-recovery --recovery inspect, then finish or abandon the expired test.','incomplete':'Inspect saved evidence; use check-recovery --recovery start-new with a fresh request ID for another test.','abandoned':'Use check-recovery --recovery start-new with a fresh request ID for another test.'}.get(check.get('status'),'')
    checks['guided_connection_test']=observation(check.get('status','not_started'),next_test_action,check.get('checked_at') or check.get('started_at'),phase=check.get('phase'),phases=phases,destination_confirmation=destination,destination_confirmed_at=check.get('destination_confirmed_at'),target=check.get('target'),request_id=check.get('request_id'),nonce=check.get('nonce'),subscription_id=check.get('subscription_id'),subscription_epoch=check.get('subscription_epoch'),watch_expires_at=check.get('watch_expires_at'),watch_capture=check.get('watch_capture'),prior_watch_ids=check.get('prior_watch_ids',[]),instruction_shown=check.get('instruction_shown'),action_inspection=check.get('action_inspection'),fence_result=check.get('fence_result'),history=check.get('history',[]),evidence='saved_guided_test_user_report_and_local_observations' if check else 'none')
    auth=checks['runtime'].get('last_verified_authentication') or record.get('last_authentication')
    from .auth import approved_scope_evidence
    scope_evidence=approved_scope_evidence(record,now)
    if check.get('status')=='complete' and scope_evidence and isinstance(check.get('checked_at'),(int,float)):
        checks['route']['account_connection']='verified by the connection test on '+datetime.fromtimestamp(check['checked_at'],timezone.utc).date().isoformat()
    checks['authentication']=observation('historically_verified' if auth else 'unknown','Sign in and perform an authenticated profile/read request.' if not auth else '',auth,token_currently_usable='unknown',approved_client_id=record.get('approved_client_id'),verified_scopes=scope_evidence['scopes'] if scope_evidence else 'unknown',scope_client_id=scope_evidence['client_id'] if scope_evidence else None,scope_clients=scope_evidence['clients'] if scope_evidence else [],scope_verified_at=scope_evidence['verified_at'] if scope_evidence else None,scope_expires_at=scope_evidence['expires_at'] if scope_evidence else None,account_access=account_access(cfg,record))
    checks['cloud_connection']=observation('unknown','Confirm the Herdr plugin connection and account consent in the ChatGPT/Codex desktop app.' if client_app=='desktop' else 'Confirm the custom plugin connection and account consent in ChatGPT in a web browser (chatgpt.com): Settings → Plugins.',now)
    if route!='tunnel':checks['tunnel']=observation('not_applicable',at=now)
    else:
        from .tunnel import profile_settings
        try:
            profile_settings(config)
            available=bool(os.environ.get('CONTROL_PLANE_API_KEY'))
            # A service credential is checked for availability without reading its value.
            try:
                from .service import service_record
                credential=service_record(config).get('credential_file')
                if credential:
                    p=Path(credential);available=available or (p.is_file() and not p.is_symlink() and p.stat().st_uid==os.getuid() and not p.stat().st_mode & 0o077 and 0<p.stat().st_size<=16384)
            except (Rejected,OSError):pass
            checks['tunnel']=observation('prepared_key_available' if available else 'missing_runtime_key','Configure a private runtime credential source for the selected tunnel.' if not available else 'Live readiness and account OAuth remain separate.',now)
        except (Rejected,OSError):checks['tunnel']=observation('not_prepared','Prepare a tunnel only if your organization/workspace is eligible.',now)
    checks['cloudflared']=cloudflared_observation(config,record,checks['runtime'])
    checks['monitoring']=database_summary(cfg['store'],now)
    if live:
        from .herdr import HerdrClient
        try:
            source=(client_factory or HerdrClient)(cfg['socket']);pong=await asyncio.wait_for(source.request('ping',{}),5)
            compatible=pong.get('version')=='0.9.3' and pong.get('protocol')==22
            checks['source']=observation('compatible' if compatible else 'unsupported','' if compatible else 'Use supported Herdr 0.9.3 protocol 22.',time.time(),version=pong.get('version'),protocol=pong.get('protocol'))
        except (Rejected,OSError,asyncio.TimeoutError):checks['source']=observation('unavailable','Start the selected Herdr session or inspect its socket.',time.time())
        from .login import public_metadata_status
        endpoint=record.get('endpoint') or cfg['resource']
        result=await asyncio.to_thread(public_metadata_status,cfg,endpoint,details=True)
        reach,ready,*advice=result
        if advice and advice[0]:checks['route']['cloudflare_advice']=advice[0]
        checks['route']['public_reachability']=reach
        unavailable=checks['runtime']['state'] not in ('running','starting') and checks['listener']['state']!='occupied'
        action='because the connector is not running' if unavailable else '' if ready else 'Check the selected route/forwarder to this computer.' if reach.startswith('unreachable') else 'Repair the selected route and approved issuer/resource metadata.'
        checks['discovery']=observation('unavailable' if unavailable else 'matched' if ready else 'unavailable',action,time.time())
    report['overall']=overall(checks,cfg,live)
    return report


def render(report):
    lines=[f"Connection status ({report['mode']}):"]
    verdict=report.get('overall',{})
    if verdict:lines.append('Overall: '+verdict['verdict']+'.'+(' '+verdict['next_action'] if verdict.get('next_action') else ''))
    app=report.get('observations',{}).get('wiring',{}).get('client_app')
    if app:lines.append('Chosen app: '+('ChatGPT/Codex desktop app' if app=='desktop' else 'ChatGPT in a web browser (chatgpt.com)'))
    for name,value in report['observations'].items():
        state=value.get('state',value.get('status','unknown'))
        if name=='cloudflared' and state=='not_applicable':continue
        details=''
        if name=='route' and value.get('url'):details=' URL='+str(value['url'])+'; wiring='+str(value.get('wiring'))+'; local preparation='+str(value.get('local_preparation'))+'; public reachability='+str(value.get('public_reachability'))+'; account connection='+str(value.get('account_connection'))
        if name=='guided_connection_test':details=' phases='+json.dumps(value.get('phases',{}),sort_keys=True)+'; destination confirmation='+str(value.get('destination_confirmation'))+'; test watch identity='+str(value.get('watch_capture'))+'; test watch fence='+str(value.get('fence_result'))+'; prior tests='+str(len(value.get('history',[])))
        if name=='authentication':
            clients=value.get('scope_clients',[])
            scopes=', '.join(', '.join(entry['scopes'])+' (client '+entry['client_id'][:8]+'…)' for entry in clients) if clients else 'unknown'
            details='; account access: '+value.get('account_access','unknown')+'; approved client scopes: '+scopes
        if name=='cloudflared':
            files=value.get('credential_files',{})
            file_details='; '.join(key+'='+item.get('state','unknown')+' ('+item.get('path','')+')' for key,item in files.items())
            details=' binary='+str(value.get('binary','unknown'))+'; credential='+str(value.get('credential','unknown'))+('; '+file_details if file_details else '')+'; child='+str(value.get('child','unknown'))
        separator=' ' if name=='discovery' and value.get('next_action','').startswith('because ') else '. '
        lines.append(name+': '+str(state)+details+(separator+value['next_action'] if value.get('next_action') else ''))
    lines.append('Correct-dot delivery: unknown unless separately confirmed in the intended destination.')
    return '\n'.join(lines)
