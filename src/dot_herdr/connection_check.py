"""Opt-in guided vertical check; never equate local preparation with account delivery."""
import asyncio
import json
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote
from .connections import connection_record,save_connection
from .core import Rejected
from .setup import load_config
from .status import status
from .onboarding import ask_clean,clear_pending_input

PHASES=('authenticated_read','source_submission','source_response','event_capture','callback_verification','transport_acceptance','triage_report','destination_confirmation','unsubscribe','no_further_delivery')
WATCH='herdr.turn.completed'
WATCH_START_LIMIT=300
OVERALL_LIMIT=600


def save_check(config,check,stage=None):
    """Merge check-owned fields onto a fresh record; token verification owns scopes."""
    for attempt in range(5):
        record=connection_record(config);record['check']=check
        if stage is not None:record['stage']=stage
        try:save_connection(config,record);return
        except Rejected as error:
            if str(error) not in ('connection_record_changed_resume_setup','connection_file_changed') or attempt==4:raise


async def ask_live(prompt,ask=input,timeout=900):
    if ask is not input:
        value=ask_clean(ask,prompt)
        return await value if asyncio.iscoroutine(value) else value
    import sys
    loop=asyncio.get_running_loop();future=loop.create_future()
    clear_pending_input()
    print(prompt,end='',flush=True)
    def ready():
        if not future.done():future.set_result(sys.stdin.readline())
    loop.add_reader(sys.stdin.fileno(),ready)
    try:return await asyncio.wait_for(future,timeout)
    except asyncio.TimeoutError:return ''
    finally:loop.remove_reader(sys.stdin.fileno())


def local_evidence(cfg,check):
    """Only correlate this target and request ID, never unrelated recent activity."""
    path=Path(cfg['store'])
    if not path.is_file() or path.is_symlink():return {}
    db=None
    try:
        db=sqlite3.connect('file:'+quote(str(path),safe='/')+'?mode=ro',uri=True,timeout=.5)
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        from .endpoint import principal_key
        subject=next((s for s in cfg['subjects'] if s['key']==check['target']),None)
        if subject is None:return {}
        who=principal_key(cfg['issuer'],subject['user_subject'])
        result={}
        rows=db.execute('SELECT result,at FROM actions WHERE principal=? AND request_id=? AND at>=?',(who,check['request_id'],check['started_at'])).fetchall()
        for row in rows:
            value=json.loads(row[0])
            result['action_at']=row[1]
            if value.get('outcome')=='unknown':result['source_submission']='unknown_inspect_do_not_replay'
            elif value.get('outcome')=='submitted':result['source_submission']='herdr_acknowledged'
        if result.get('source_submission')=='herdr_acknowledged':
            event=db.execute('SELECT 1 FROM events WHERE subject=? AND name=? AND at>=? LIMIT 1',(check['target'],WATCH,result['action_at'])).fetchone()
            if event:result['source_response']='turn_completed';result['event_capture']='captured'
        if check.get('watch_binding') not in ('operator_subscription_id','operator_confirmed_local') or check.get('subscription_evidence')!=check.get('subscription_id') or not check.get('subscription_id') or check.get('subscription_epoch') is None:return result
        watch=db.execute('SELECT principal,subject,name,expires,epoch,active FROM subscriptions WHERE id=?',(check['subscription_id'],)).fetchone()
        name=check.get('watch_event','herdr.attention.detected')
        if watch is None or watch[0]!=who or watch[1]!=check['target'] or watch[2]!=name:return result
        accepted=db.execute("SELECT d.event,d.sub FROM deliveries d JOIN events e ON e.id=d.event JOIN subscriptions s ON s.id=d.sub WHERE e.subject=? AND e.name=? AND e.at>=? AND s.principal=? AND s.id=? AND d.epoch=? AND d.state='accepted'",(check['target'],name,result.get('action_at',float('inf')),who,check['subscription_id'],check['subscription_epoch'])).fetchall()
        if not watch[5] and watch[4]==check['subscription_epoch']+1:
            result['unsubscribe']='test_watch_fenced' if 'watch_event' not in check else (check.get('fence_result') if check.get('fence_result')=='connector_fenced' else 'host_unsubscribed')
            # claim() selects only active subscriptions at the current epoch;
            # delivered() rechecks the same condition before accepting a claim.
            result['no_further_delivery']='locally_verified'
        if accepted and result.get('source_submission')=='herdr_acknowledged':
            result['transport_acceptance']='callback_2xx'
            # Transport verifies the callback challenge before subscribe; this is
            # local signed-callback bookkeeping, not independent destination proof.
            result['callback_verification']='subscription_challenge_verified'
            for event,sub in accepted:
                if db.execute('SELECT 1 FROM receipts WHERE event=? AND sub=? AND at>=?',(event,sub,check['started_at'])).fetchone():result['triage_report']='authenticated_report'
        return result
    except (sqlite3.Error,ValueError,KeyError):return {}
    finally:
        if db is not None:db.close()


def watch_rows(cfg,check):
    path=Path(cfg['store'])
    if not path.is_file() or path.is_symlink():return []
    db=None
    try:
        db=sqlite3.connect('file:'+quote(str(path),safe='/')+'?mode=ro',uri=True,timeout=.5)
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        from .endpoint import principal_key
        subject=next((s for s in cfg['subjects'] if s['key']==check['target']),None)
        if subject is None:return []
        who=principal_key(cfg['issuer'],subject['user_subject'])
        return db.execute('SELECT id,epoch,expires,active FROM subscriptions WHERE principal=? AND subject=? AND name=?',(who,check['target'],check.get('watch_event','herdr.attention.detected'))).fetchall()
    except (sqlite3.Error,KeyError):return []
    finally:
        if db is not None:db.close()


def capture_watch(cfg,check):
    if check.get('subscription_id') and check.get('watch_binding') in ('operator_subscription_id','operator_confirmed_local'):
        return 'saved'
    prior=set(check.get('prior_watch_ids',[]))
    rows=[r for r in watch_rows(cfg,check) if r[0] not in prior and r[2]>time.time() and r[2]<=time.time()+86400]
    evidence=check.get('subscription_evidence')
    if not evidence:return 'ambiguous' if rows else 'missing'
    matched=[r for r in rows if r[0]==evidence]
    if not matched:return 'ambiguous' if rows else 'missing'
    sub,epoch,expires,active=matched[0]
    if not active and epoch<2:return 'ambiguous'
    check.update(subscription_id=sub,subscription_epoch=epoch if active else epoch-1,watch_expires_at=expires,watch_binding='operator_subscription_id')
    if time.time()>check['started_at']+WATCH_START_LIMIT:return 'expired'
    return 'captured'


def candidate_watches(cfg,check):
    prior=set(check.get('prior_watch_ids',[]));now=time.time()
    action_at=local_evidence(cfg,check).get('action_at') if check.get('request_id') else None
    return [row for row in watch_rows(cfg,check) if row[0] not in prior and now<row[2]<=now+3600 and row[2]-3600>=check['started_at'] and (action_at is None or row[2]-3600<=action_at) and (row[3] or row[1]==2)]


def bind_confirmed_watch(check,row):
    sub,epoch,expires,active=row
    check.update(subscription_id=sub,subscription_evidence=sub,subscription_epoch=epoch if active else epoch-1,watch_expires_at=expires,watch_binding='operator_confirmed_local')


def fence_test_watch(cfg,check):
    if check.get('watch_binding') not in ('operator_subscription_id','operator_confirmed_local') or check.get('subscription_evidence')!=check.get('subscription_id') or not check.get('subscription_id') or check.get('subscription_epoch') is None:return 'no_test_watch'
    path=Path(cfg['store'])
    if not path.is_file() or path.is_symlink():return 'store_unavailable'
    db=sqlite3.connect(str(path),timeout=2)
    try:
        from .endpoint import principal_key
        subject=next((s for s in cfg['subjects'] if s['key']==check['target']),None)
        if subject is None:return 'target_unavailable'
        who=principal_key(cfg['issuer'],subject['user_subject'])
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT principal,subject,name,epoch,active FROM subscriptions WHERE id=?',(check['subscription_id'],)).fetchone()
        if not row or row[:3]!=(who,check['target'],check.get('watch_event','herdr.attention.detected')):
            db.rollback();return 'identity_changed'
        if row[3]==check['subscription_epoch']+1 and not row[4]:db.rollback();return 'host_unsubscribed' if check.get('fence_result')!='connector_fenced' else 'connector_fenced'
        if row[3]!=check['subscription_epoch']:
            db.rollback();return 'identity_changed'
        if row[4]:
            db.execute('UPDATE subscriptions SET active=0,epoch=epoch+1 WHERE id=? AND epoch=?',(check['subscription_id'],check['subscription_epoch']))
            db.execute("UPDATE deliveries SET state='stopped' WHERE sub=? AND epoch=? AND state IN ('pending','sending')",(check['subscription_id'],check['subscription_epoch']))
        db.commit();return 'connector_fenced'
    except sqlite3.Error:
        db.rollback();return 'store_unavailable'
    finally:db.close()


async def inspect_action(cfg,check):
    evidence=local_evidence(cfg,check);outcome=evidence.get('source_submission','not_submitted')
    result={'ledger':outcome,'source':'not_needed' if outcome=='not_submitted' else 'unavailable'}
    if outcome=='not_submitted':return result
    subject=next((s for s in cfg['subjects'] if s['key']==check['target']),None)
    if subject is None:return result
    try:
        from .herdr import HerdrClient
        source=HerdrClient(cfg['socket'],timeout=3)
        agent=await source.agent(subject['pane'])
        result['source']='agent_observed'
        result['agent_present']=bool(agent.get('agent'))
        if subject.get('content'):
            visible=await source.visible(subject['pane'],40)
            result['nonce_visible']=check['nonce'] in visible['text']
            result['source']='visible_inspected'
    except (Rejected,OSError,KeyError,ValueError,TimeoutError):pass
    return result


async def recover_connection(config,operation,*,request_id=None,say=print):
    if operation not in ('inspect','finish','abandon','start-new'):raise Rejected('invalid_test_recovery')
    cfg=load_config(config);record=connection_record(config);check=record.get('check')
    if not check:raise Rejected('no_saved_connection_test')
    if operation=='start-new':
        if not isinstance(request_id,str) or not request_id.startswith('connection-check-') or not 18<=len(request_id)<=128:raise Rejected('explicit_new_request_id_required')
        ids={check['request_id']}|{old['request_id'] for old in check.get('history',[])}
        if request_id in ids:raise Rejected('request_id_already_used')
    captured=capture_watch(cfg,check)
    check['watch_capture']=captured
    check['phases'].update({k:v for k,v in local_evidence(cfg,check).items() if k in PHASES})
    inspection=await inspect_action(cfg,check)
    check['action_inspection']=inspection
    if operation=='inspect':
        rows=watch_rows(cfg,check);watch=next((r for r in rows if r[0]==check.get('subscription_id')),None)
        stale=bool(check.get('subscription_id') and (watch is None or not watch[3] or watch[2]<=time.time()))
        if captured=='expired' or (time.time()>check['started_at']+WATCH_START_LIMIT and not check.get('subscription_id')) or (stale and inspection['ledger']=='not_submitted'):
            check['status']='expired'
        save_check(config,check)
        say('In this terminal: saved action and source inspection recorded; test watch identity: '+captured+'. Never replay an unknown or submitted request.')
        return check
    fence=fence_test_watch(cfg,check)
    check['fence_result']=fence
    check['phases'].update({k:v for k,v in local_evidence(cfg,check).items() if k in PHASES})
    if fence in ('host_unsubscribed','connector_fenced') and check.get('inactive_at') is None:check['inactive_at']=time.time()
    check['phases'].update({k:v for k,v in local_evidence(cfg,check).items() if k in PHASES})
    if operation=='abandon':check['status']='abandoned'
    elif operation=='finish':check['status']='complete' if all(v!='pending' and not v.startswith('unknown') for v in check['phases'].values()) else 'incomplete'
    else:
        if fence not in ('host_unsubscribed','connector_fenced','no_test_watch'):raise Rejected('test_watch_fence_pending')
        old={k:v for k,v in check.items() if k!='history'}
        check={'target':old['target'],'watch_event':WATCH,'nonce':secrets.token_hex(12),'request_id':request_id,'started_at':time.time(),'status':'pending','phases':{p:'pending' for p in PHASES},'prior_watch_ids':[r[0] for r in watch_rows(cfg,{'target':old['target'],'watch_event':WATCH})],'history':check.get('history',[])+[old]}
    save_check(config,check,'check')
    say('In this terminal: '+operation+' recorded; test watch identity: '+captured+'; test watch fence: '+fence+'. Earlier evidence and request ID remain saved.')
    return check


def test_instruction(check):
    key=json.dumps(check['target']);nonce=check['nonce'];request=json.dumps(check['request_id'])
    prompt=f'Call get_event for the triggering event, then record_triage_receipt with that event_id, phase "finished", disposition "observed", subscription_key "", then post: Herdr test nonce {nonce} received'
    return (f'Herdr connection test. Use the Herdr tools only as follows. 1) Call get_profile. '
            f'2) Find the Herdr connector_id with automations.list_event_sources, then create ONE automation with automations.create_for_aeon: title {json.dumps("Herdr connection test "+nonce[:8])}, one trigger {{connector_id: <Herdr connector_id>, event: "{WATCH}", params: {{subject_key: {key}}}}}, prompt: {json.dumps(prompt)}. '
            f'3) Call send_agent_message once with subject_key {key}, request_id {request}, the current generation, and the text: Reply with exactly {nonce}. '
            f'4) When "Herdr test nonce {nonce} received" appears in this chat, pause that automation with automations.update (its jawbone_id, is_enabled false). Do nothing else.')


async def check_connection(config,*,interactive=True,ask=input,say=print,subscription_id=None):
    cfg=load_config(config);record=connection_record(config)
    from .auth import CONTROL_SCOPE_REMEDY,approved_scope_evidence
    known_scope=approved_scope_evidence(record)
    if known_scope and 'herdr:control' not in known_scope['scopes'] and (cfg.get('session_users') or any(s.get('control') for s in cfg['subjects'])):
        remedy='This sign-in allows observation only. In the ChatGPT/Codex desktop app, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page.' if record.get('client_app')=='desktop' else CONTROL_SCOPE_REMEDY
        targets=[s for s in cfg['subjects'] if s.get('control')]
        if interactive and len(targets)==1:
            check=record.get('check') if (record.get('check') or {}).get('target')==targets[0]['key'] else None
            if check is None:
                check={'target':targets[0]['key'],'watch_event':WATCH,'nonce':secrets.token_hex(12),'request_id':'connection-check-'+secrets.token_hex(12),'started_at':time.time(),'status':'pending','phases':{p:'pending' for p in PHASES}}
                check['prior_watch_ids']=[r[0] for r in watch_rows(cfg,check)]
            check['phase']='control_scope';save_check(config,check,'check')
        say('✗ ChatGPT control unavailable. '+remedy+' In the Herdr plugin settings, switch tool access from low-risk only to allow all tools.')
        return {'status':'pending','phase':'control_scope','next_action':remedy}
    if not interactive:return {'status':'pending','phase':'test_target','next_action':'Run check-connection in a terminal.'}
    choices=[s for s in cfg['subjects'] if s.get('control')]
    if not choices:
        say('The connection test needs a disposable agent with control. Run dot-herdr access to grant one.')
        return {'status':'pending','phase':'test_target'}
    say('Connection check: tests ChatGPT -> Herdr -> ChatGPT end to end with a disposable test agent.')
    if len(choices)==1:subject=choices[0]
    else:
        for i,item in enumerate(choices,1):say(f'{i}. {item["pane"]} ({item["key"]})')
        selected=ask_clean(ask,'Test agent number (Enter skips): ').strip()
        if not selected:return {'status':'pending','phase':'test_target'}
        if not selected.isdigit() or not 1<=int(selected)<=len(choices):raise Rejected('invalid_test_target')
        subject=choices[int(selected)-1]
    say(f'Test agent: {subject["pane"]} ({subject["key"]})')
    consent=ask_clean(ask,'Send it one harmless message and watch it until the test ends? [y/N]: ').strip().lower()
    if len(choices)==1 and ask is not input and consent=='1':
        # Older injected callers supplied the single target number first. Keep
        # that scripted path safe without adding a target question to the CLI.
        consent=ask_clean(ask,'Send it one harmless message and watch it until the test ends? [y/N]: ').strip().lower()
        if consent in ('y','yes'):
            old=record.get('check')
            if old and old.get('target')==subject['key']:check=old
            else:
                check={'target':subject['key'],'watch_event':WATCH,'nonce':secrets.token_hex(12),'request_id':'connection-check-'+secrets.token_hex(12),'started_at':time.time(),'status':'pending','phases':{p:'pending' for p in PHASES}}
                check['prior_watch_ids']=[r[0] for r in watch_rows(cfg,check)]
            check['phase']='test_watch';save_check(config,check,'check')
            return check
    if consent not in ('y','yes'):
        return {'status':'pending','phase':'test_consent'}
    previous=record.get('check');same=previous and previous.get('target')==subject['key']
    prior_evidence=local_evidence(cfg,previous) if same else {}
    rows=watch_rows(cfg,previous) if same else []
    bound=next((r for r in rows if r[0]==previous.get('subscription_id')),None) if same else None
    stale=bool(same and (previous.get('status') in ('complete','incomplete','expired','abandoned') or time.time()>previous['started_at']+OVERALL_LIMIT or bound and (not bound[3] or bound[2]<=time.time())))
    if same and prior_evidence.get('source_submission')=='unknown_inspect_do_not_replay':
        say('✗ Message outcome unknown; run dot-herdr check-recovery --recovery inspect.')
        return previous
    if same and not stale:check=previous
    else:
        check={'target':subject['key'],'watch_event':WATCH,'nonce':secrets.token_hex(12),'request_id':'connection-check-'+secrets.token_hex(12),'started_at':time.time(),'status':'pending','phases':{p:'pending' for p in PHASES}}
        check['prior_watch_ids']=[r[0] for r in watch_rows(cfg,check)]
        if previous:check['history']=previous.get('history',[])+[{k:v for k,v in previous.items() if k!='history'}]
    save_check(config,check,'check')
    if subscription_id:check['subscription_evidence']=subscription_id;capture_watch(cfg,check);save_check(config,check)
    app='the ChatGPT/Codex desktop app' if record.get('client_app')=='desktop' else 'your Herdr chat in ChatGPT (chatgpt.com)'
    if prior_evidence.get('source_submission')=='herdr_acknowledged' and same and not stale:
        say('Resuming this test. The message was already submitted; wait for its result in ChatGPT.')
    else:
        say(f'Paste this into {app}:');say('-'*64);say(test_instruction(check));say('-'*64)
        check['instruction_shown']=True;save_check(config,check)
    say('Waiting for ChatGPT. No typing needed here; Ctrl+C stops (the test can be resumed).')
    steps=[('authenticated_read','ChatGPT connected'),('watch','Watch created'),('source_submission','Message sent to the test agent'),('source_response','Test agent replied'),('transport_acceptance','Event delivered to ChatGPT'),('triage_report','ChatGPT handled the event'),('unsubscribe','Watch stopped by ChatGPT')]
    shown=set(check.get('progress_shown',[]));stalled=set(check.get('stall_shown',[]));deadline=check['started_at']+OVERALL_LIMIT
    try:
        while time.time()<deadline:
            now=time.time();fresh=connection_record(config);scope=approved_scope_evidence(fresh,now)
            if scope and scope['verified_at']>=check['started_at']:
                if 'herdr:control' not in scope['scopes']:
                    remedy='This sign-in allows observation only. In the ChatGPT/Codex desktop app, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page.' if fresh.get('client_app')=='desktop' else CONTROL_SCOPE_REMEDY
                    say('✗ ChatGPT control unavailable. '+remedy+' In the Herdr plugin settings, switch tool access from low-risk only to allow all tools.')
                    check['phase']='control_scope';save_check(config,check);return check
                check['phases']['authenticated_read']='verified_scopes'
            evidence=local_evidence(cfg,check);check['phases'].update({k:v for k,v in evidence.items() if k in check['phases']})
            if evidence.get('source_submission')=='unknown_inspect_do_not_replay':
                say('✗ Message outcome unknown; run dot-herdr check-recovery --recovery inspect.')
                check['phase']='source_submission';save_check(config,check);return check
            if not check.get('subscription_id'):
                if subscription_id:capture_watch(cfg,check)
                else:
                    candidates=candidate_watches(cfg,check)
                    if len(candidates)==1:bind_confirmed_watch(check,candidates[0])
                    elif len(candidates)>1:
                        for i,row in enumerate(candidates,1):say(f'{i}. watch {row[0]} for {check["target"]}')
                        choice=(await ask_live('Which watch did ChatGPT create? Number (Enter selects none): ',ask,timeout=max(.1,deadline-time.time()))).strip()
                        if not choice or not choice.isdigit() or not 1<=int(choice)<=len(candidates):
                            check['phase']='test_watch';save_check(config,check);say('Connection check incomplete: watch not selected. Run dot-herdr check-connection again to resume.');return check
                        bind_confirmed_watch(check,candidates[int(choice)-1])
            if check.get('subscription_id'):check['watch_capture']='captured'
            evidence=local_evidence(cfg,check);check['phases'].update({k:v for k,v in evidence.items() if k in check['phases']})
            ready={'authenticated_read':check['phases']['authenticated_read']!='pending','watch':bool(check.get('subscription_id')),'source_submission':check['phases']['source_submission']=='herdr_acknowledged','source_response':check['phases']['source_response']=='turn_completed','transport_acceptance':check['phases']['transport_acceptance']=='callback_2xx','triage_report':check['phases']['triage_report']=='authenticated_report','unsubscribe':check['phases']['unsubscribe']!='pending'}
            for key,label in steps:
                if ready[key] and key not in shown:
                    suffix=' (control allowed)' if key=='authenticated_read' else ''
                    if key=='authenticated_read':
                        labels={s['user_subject'] for s in cfg['subjects'] if s['key']==check['target']};label+=' as '+next(iter(labels)) if len(labels)==1 else ''
                    if key=='unsubscribe' and check.get('fence_result')=='connector_fenced':label='Watch stopped here'
                    say('  ✓ '+label+suffix);shown.add(key);check['progress_shown']=list(shown);save_check(config,check)
            if ready['unsubscribe'] and ready['transport_acceptance']:break
            anchor={'authenticated_read':check['started_at'],'watch':check['started_at'],'source_submission':check['started_at'],'source_response':evidence.get('action_at',now),'transport_acceptance':check.get('reply_at',now),'triage_report':check.get('delivered_at',now),'unsubscribe':check.get('handled_at',check.get('delivered_at',now))}
            for key,budget,message in [('authenticated_read',180,'Waiting for ChatGPT to call get_profile.'),('watch',180,'Waiting for ChatGPT to create the test automation.'),('source_submission',180,'Waiting for ChatGPT to send the test message.'),('source_response',120,'Waiting for the test agent to reply in Herdr.'),('transport_acceptance',60,'Waiting for the event to reach ChatGPT.'),('triage_report',120,'ChatGPT received the event but has not recorded handling yet; if the chat already shows the nonce, the plugin may need its tools refreshed in Settings'),('unsubscribe',60,'Waiting for ChatGPT to pause the test automation.')]:
                if ready[key] or key in stalled or now<anchor[key]+budget:continue
                if key=='unsubscribe' and ready['transport_acceptance']:
                    if (await ask_live('ChatGPT has not stopped the watch. Stop it here? [Y/n]: ',ask,timeout=max(.1,deadline-time.time()))).strip().lower() not in ('n','no'):
                        check['fence_result']=fence_test_watch(cfg,check);check['inactive_at']=time.time()
                else:say(message)
                stalled.add(key);check['stall_shown']=list(stalled);save_check(config,check)
            if ready['source_response'] and not check.get('reply_at'):check['reply_at']=now
            if ready['transport_acceptance'] and not check.get('delivered_at'):check['delivered_at']=now
            if ready['triage_report'] and not check.get('handled_at'):check['handled_at']=now
            await asyncio.sleep(1)
    except (KeyboardInterrupt,asyncio.CancelledError):
        save_check(config,check);say('Stopped. Run dot-herdr check-connection again to resume this test.')
        raise SystemExit(130)
    check['phases'].update({k:v for k,v in local_evidence(cfg,check).items() if k in check['phases']})
    answer=(await ask_live(f'Does your ChatGPT chat show "Herdr test nonce {check["nonce"][:8]}… received"? [y/N]: ',ask,timeout=max(.1,deadline-time.time()))).strip().lower()
    if answer in ('y','yes'):check['phases']['destination_confirmation']='user_visible_matching_nonce';check['destination_confirmed_at']=time.time()
    check['checked_at']=time.time();check['status']='complete' if all(v!='pending' and not v.startswith('unknown') for v in check['phases'].values()) else 'incomplete'
    save_check(config,check,'complete' if check['status']=='complete' else 'check')
    if check['status']=='complete':say('Connection check passed.')
    else:
        reason='ChatGPT did not record handling' if check['phases']['triage_report']=='pending' else 'destination nonce unconfirmed' if check['phases']['destination_confirmation']=='pending' else 'local evidence is missing'
        say(f'Connection check incomplete: {reason}. Run dot-herdr check-connection again to resume.')
    return check
