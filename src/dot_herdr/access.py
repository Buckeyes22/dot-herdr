"""Explicit operator access changes; no model tool and no arbitrary process kills."""
import copy
import fcntl
import hashlib
import json
import os
import secrets
import stat
import time
from pathlib import Path
from .core import Rejected, Store, encode
from .herdr import HerdrClient
from .onboarding import ask_clean, choose_agents, choose_socket, private_directory
from .setup import load_config, validate_config


def roster(cfg):
    from .endpoint import principal_key
    return [dict(key=s['key'],principal=principal_key(cfg['issuer'],s['user_subject']),
                 owner=s['owner'],pane=s['pane'],terminal=s['terminal'],
                 native=s.get('native'),content=s.get('content',False)) for s in cfg['subjects']]


def grants(cfg):
    return {'subjects':[{'key':s['key'],'control':s.get('control',False),'content':s.get('content',False)} for s in cfg['subjects']],
            'session_control':bool(cfg.get('session_users')),'inactive':not cfg['subjects'] and not cfg.get('session_users')}


def describe_change(old,new):
    before={s['key']:s for s in old['subjects']};after={s['key']:s for s in new['subjects']};changes=[]
    if old['socket']!=new['socket']:changes.append('Herdr session changed')
    added=len(after.keys()-before.keys());removed=len(before.keys()-after.keys())
    if added:changes.append(f'{added} agent grant'+('s' if added!=1 else '')+' added')
    if removed:changes.append(f'{removed} agent grant'+('s' if removed!=1 else '')+' removed')
    for key in before.keys()&after.keys():
        for field,label in (('control','agent control'),('content','visible context')):
            if bool(before[key].get(field))!=bool(after[key].get(field)):changes.append(label+(' enabled' if after[key].get(field) else ' revoked')+' for '+key)
    if set(old.get('session_users',[]))!=set(new.get('session_users',[])):changes.append('whole-session access changed')
    return '; '.join(changes) if changes else 'No grant changes'


def binding(subject):
    return [subject[k] for k in ('user_subject','owner','pane','terminal')]+[subject.get('native')]


def control_accounts(cfg):
    return set(cfg.get('session_users',[]))|{s['user_subject'] for s in cfg['subjects'] if s.get('control')}


def service_adapter(config):
    """Return only an installed owned service; no service means foreground rules."""
    from .service import manage,service_status
    state=service_status(config)
    if state['state']=='interrupted_install':raise Rejected('owned_service_state_unavailable_recover_service_install')
    if not state.get('installed'):return None
    class OwnedService:
        def status(self):
            current=service_status(config)
            if current['state'] in ('manager_unavailable','unknown','interrupted_install'):raise Rejected('owned_service_state_unavailable')
            return {'owned':current.get('installed',False),'active':current['state'] in ('active','running','activating','deactivating','waiting')}
        def stop(self):
            current=manage(config,'stop')
            if current['state'] not in ('inactive','stopped','failed'):raise Rejected('owned_service_stop_not_confirmed')
        def start(self):
            current=manage(config,'start')
            if current['state'] not in ('active','running','activating','waiting'):raise Rejected('owned_service_start_not_confirmed')
        def verify(self,expected_release=None):
            from .runtime import status_path
            from .status import runtime_observation
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                current=service_status(config);observed=runtime_observation(config)
                if observed['state']=='failed':raise Rejected('owned_service_runtime_failed')
                try:
                    path=status_path(config)
                    if path.is_symlink() or path.stat().st_mode&0o077 or path.stat().st_size>65536:raise ValueError
                    raw=json.loads(path.read_text())
                    matched=bool(current.get('pid')) and current.get('pid')==raw.get('pid')
                    release=expected_release is None or raw.get('runtime_prefix')==str(Path(expected_release).resolve())
                    if observed['state']=='running' and matched and release:return {'status':'verified','pid':raw['pid']}
                except (OSError,ValueError):pass
                time.sleep(0.1)
            raise Rejected('owned_service_runtime_readiness_unverified')
        def remove(self):return manage(config,'remove')
    return OwnedService()


def rebind_keys(subjects,old,force_new=False):
    """Retain exact bindings; replacements receive independent identities and grants."""
    result=[];existing={} if force_new else {encode(binding(s)):s['key'] for s in old}
    used={s['key'] for s in old}
    for subject in subjects:
        identity=encode(binding(subject));subject=dict(subject)
        if force_new:
            key='agent-'+secrets.token_hex(16)
            while key in used:key='agent-'+secrets.token_hex(16)
        else:key=existing.get(identity,'agent-'+hashlib.sha256(identity.encode()).hexdigest()[:32])
        subject['key']=key;used.add(key)
        result.append(subject)
    return result


def apply_access(path,cfg,previous,service=None):
    """Commit complete stopped config and fence the roster. Failure leaves grants stopped."""
    path=Path(path).expanduser().absolute();cfg=validate_config(copy.deepcopy(cfg))
    old=load_config(path)
    if cfg['store']!=old['store'] or cfg['issuer']!=old['issuer']:
        raise Rejected('access_cannot_change_store_or_issuer')
    body=(json.dumps(cfg,indent=2)+'\n').encode()
    if len(body)>65536:raise Rejected('configuration_too_large')
    if path.is_symlink() or path.read_bytes()!=previous:raise Rejected('configuration_changed_run_access_again')
    private_directory(path.parent);private_directory(Path(cfg['store']).parent)
    active=False
    if service is not None:
        state=service.status()
        if not state.get('owned'):raise Rejected('connector_owned_service_required')
        active=bool(state.get('active'))
        if active:service.stop()
    store_path=Path(cfg['store']);store=None;lockfd=None;temporary=None
    backup=path.with_name(path.name+'.access-previous-'+secrets.token_hex(6))
    committed=False;failure=None
    try:
        # Store() alone would reset delivery uncertainty before discovering bad bindings.
        # Lock first and validate through a read-only connection before opening the writer.
        lockpath=Path(str(store_path)+'.owner.lock')
        if store_path.exists():
            if lockpath.is_symlink() or not lockpath.is_file() or lockpath.stat().st_mode&0o077:raise Rejected('private_store_required')
            lockfd=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW)
            try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected('stop_foreground_owner_before_access') from None
            import sqlite3
            from urllib.parse import quote
            db=sqlite3.connect('file:'+quote(str(store_path),safe='/')+'?mode=ro',uri=True)
            db.row_factory=sqlite3.Row
            try:
                for entry in roster(cfg):
                    row=db.execute('SELECT * FROM subjects WHERE key=?',(entry['key'],)).fetchone()
                    expected=tuple(entry[k] for k in ('principal','owner','pane','terminal'))+(encode(entry['native']) if entry['native'] else None,)
                    if row and tuple(row[k] for k in ('principal','owner','pane','terminal','native'))!=expected:raise Rejected('enrollment_changed_rebind_required')
            finally:db.close()
            # Transfer ownership without an unlocked window during activation.
            store=Store(store_path,owner_fd=lockfd);lockfd=None
        fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(previous);stream.flush();os.fsync(stream.fileno())
        temporary=path.with_name(path.name+'.access-new-'+secrets.token_hex(6))
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        if path.is_symlink() or path.read_bytes()!=previous:raise Rejected('configuration_changed_run_access_again')
        os.replace(temporary,path);committed=True
        directory=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
        if store is not None:
            store.apply_roster(roster(cfg));store.close();store=None
    except BaseException as error:
        # A committed revocation must never be silently restored after a failed start.
        failure=error
    finally:
        if store is not None:store.close()
        if lockfd is not None:
            try:os.close(lockfd)
            except OSError:pass  # A rejected Store constructor may already close it.
        if temporary is not None:temporary.unlink(missing_ok=True)
    if failure is not None:
        if active and not committed:service.start()
        raise failure
    inactive=not cfg['subjects'] and not cfg.get('session_users')
    # Revoke-all stopped the owned service; explicitly re-enabling access starts it again.
    if service is not None and not active and not inactive and not old['subjects'] and not old.get('session_users'):active=True
    if active and not inactive:
        try:
            service.start()
            if hasattr(service,'verify'):service.verify()
        except Exception:
            try:service.stop()
            except Exception:raise Rejected('access_saved_restart_failed_owned_service_state_unknown_no_grants_restored') from None
            raise Rejected('access_saved_restart_failed_service_stopped_no_grants_restored') from None
    return {'status':'inactive' if inactive else 'saved','backup':str(backup),'service_restarted':active and not inactive,
            'consent':'pending_herdr_control_scope' if control_accounts(cfg)-control_accounts(old) else 'unchanged'}


async def configure_access(path,*,revoke_all=False,user_subject=None,socket_path=None,mode=None,agent_numbers=None,content=None,approve=False,reselect_session=False,interactive=True,ask=input,say=print,client_factory=HerdrClient,service=None):
    raw_ask=ask;ask=lambda prompt:ask_clean(raw_ask,prompt)
    path=Path(path).expanduser().absolute();cfg=load_config(path);previous=path.read_bytes();changed=copy.deepcopy(cfg)
    accounts=list(dict.fromkeys(cfg.get('access_accounts',[])+cfg.get('session_users',[])+[s['user_subject'] for s in cfg['subjects']]))
    say('Current access on '+cfg['socket']+': '+json.dumps(grants(cfg),sort_keys=True))
    if not interactive and not revoke_all and (not socket_path or user_subject is None or mode is None or not approve or (mode in ('1','2','3') and (agent_numbers is None or content is None))):
        raise Rejected('noninteractive_access_requires_socket_account_mode_agents_content_and_apply_flags')
    if revoke_all:
        changed['subjects']=[];changed['session_users']=[];changed['inactive']=True
        changed['access_accounts']=accounts
    else:
        users=accounts
        if user_subject is None:
            if len(users)==1:user_subject=users[0]
            elif users:
                for index,user in enumerate(users,1):say(f'{index}. '+json.dumps(user))
                selected=ask('Approved account number: ').strip()
                if not selected.isdigit() or not 1<=int(selected)<=len(users):raise Rejected('invalid_account_selection')
                user_subject=users[int(selected)-1]
            else:raise Rejected('inactive_access_requires_verified_enrollment')
        if user_subject not in users:raise Rejected('access_account_requires_verified_enrollment')
        def valid_socket(value):
            selected=Path(value)
            if not selected.is_absolute() or selected.is_symlink() or not selected.exists() or not stat.S_ISSOCK(selected.stat().st_mode):raise Rejected('source_socket_required')
            return str(selected)
        def running_socket():
            try:return valid_socket(choose_socket(None,ask,say))
            except Rejected as error:
                if str(error) in ('herdr_cli_not_found_use_setup_socket','session_discovery_failed_use_setup_socket'):
                    raise Rejected('session_discovery_unavailable_use_access_socket') from None
                raise
        switched=bool(reselect_session)
        if socket_path:
            selected=valid_socket(socket_path);switched=switched or selected!=cfg['socket']
        elif not interactive:raise Rejected('noninteractive_access_requires_socket')
        elif not Path(cfg['socket']).exists() or Path(cfg['socket']).is_symlink() or not stat.S_ISSOCK(Path(cfg['socket']).stat().st_mode):
            say('The saved Herdr session is gone. Next: choose a running session in this terminal; its agents need fresh approval.')
            selected=running_socket();switched=True
        else:
            choice=ask('Herdr session: 1) keep saved; 2) choose a running session [1/2]: ').strip()
            if choice not in ('1','2'):raise Rejected('invalid_session_selection')
            switched=choice=='2';selected=running_socket() if switched else valid_socket(cfg['socket'])
        source=client_factory(selected)
        try:pong=await source.request('ping',{})
        except (Rejected,OSError):
            if not interactive or switched:raise
            say('The saved Herdr session is unavailable. Next: choose a running session in this terminal; its agents need fresh approval.')
            selected=running_socket();switched=True;source=client_factory(selected);pong=await source.request('ping',{})
        if pong.get('version')!='0.9.3' or pong.get('protocol')!=22:raise Rejected('unsupported_source_version')
        if switched:say('Selected '+selected+'. Previous session grants will be revoked and its watches fenced. Next: select new grants in this terminal.')
        changed['socket']=selected
        say('Choose access: 1) monitor selected agents; 2) monitor and control selected agents; 3) whole-session reads/control; 4) revoke all.')
        if mode is None:mode=ask('Access choice [1/2/3/4]: ').strip()
        if mode not in ('1','2','3','4'):raise Rejected('invalid_access_selection')
        if mode=='4' and agent_numbers is not None:raise Rejected('invalid_agent_selection')
        if mode=='4':selected_agents=[]
        elif interactive and agent_numbers is None and content is None:selected_agents=await choose_agents(source,mode=='3',mode in ('2','3'),user_subject,ask,say)
        else:
            if not isinstance(agent_numbers,str) or not isinstance(content,bool):raise Rejected('invalid_agent_selection')
            values=iter((agent_numbers,'y' if content else 'n'))
            selected_agents=await choose_agents(source,mode=='3',mode in ('2','3'),user_subject,lambda _:next(values),say)
        changed['subjects']=rebind_keys(selected_agents,cfg['subjects'],force_new=switched)
        changed['session_users']=[user_subject] if mode=='3' else []
        changed['access_accounts']=accounts
        if mode=='4':changed['inactive']=True
        else:changed.pop('inactive',None)
    validate_config(changed)
    say('Change summary: '+describe_change(cfg,changed)+'.')
    say('Requested access on '+changed['socket']+': '+json.dumps(grants(changed),sort_keys=True))
    if not revoke_all and not approve and ask('Approve this complete access selection in this terminal? [y/N]: ').strip().lower() not in ('y','yes'):
        return {'status':'cancelled'}
    result=apply_access(path,changed,previous,service)
    say(('All access revoked.' if result['status']=='inactive' else 'Access saved.')+' Previous private configuration: '+result['backup'])
    if result['consent']!='unchanged':
        from .connections import connection_record
        say(control_growth_note(connection_record(path)))
    if result['status']=='inactive':say('The connector is stopped while no access is granted. Run dot-herdr access again to re-enable access; that starts it again.')
    return result


def control_growth_note(record):
    app=record.get('client_app')
    entries=[e for e in record.get('verified_client_scopes',{}).values() if isinstance(e,dict) and isinstance(e.get('verified_at'),(int,float))]
    newest=max(entries,key=lambda e:e['verified_at'],default=None)
    if newest and 'herdr:control' in newest.get('scopes',[]):
        return 'Control access grew. Your ChatGPT sign-in already allowed control when last checked; the next control request from the dot confirms it. No plugin change is needed.'
    return 'Control access grew; herdr:control consent is pending until a protected control request verifies it. Next: '+('in the ChatGPT/Codex desktop app, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page.' if app=='desktop' else 'in ChatGPT in a web browser (chatgpt.com), open Settings → Plugins, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page.')
