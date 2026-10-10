"""Transactional observation core. SQLite owns captured history, never upstream truth."""
from __future__ import annotations
import base64
import hashlib
import fcntl
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, UTC
from pathlib import Path

NAMES = ('herdr.attention.detected', 'herdr.turn.completed', 'herdr.lifecycle.changed', 'herdr.coverage.changed')
STATUS = {'idle', 'working', 'blocked', 'done', 'unknown'}
MAX_EVENT = 4096

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)

def iso(ts):
    return datetime.fromtimestamp(ts, UTC).isoformat().replace('+00:00', 'Z')

class Rejected(ValueError):
    """Safe categorized error; do not carry source or callback details."""

class Store:
    def __init__(self, path: Path, clock=time.time, *, preflight=None, owner_fd=None):
        self.clock, self.lock = clock, threading.RLock()
        path = Path(path)
        if any(node.is_symlink() for node in (path,*path.parents)):raise Rejected('private_store_required')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Do not chmod unrelated parents. Require private dedicated store directory.
        if path.parent.is_symlink() or path.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise Rejected('private_store_required')
        if path.exists() and path.stat().st_mode & 0o077:
            raise Rejected('private_store_required')
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        lockpath=Path(str(path)+".owner.lock")
        if lockpath.is_symlink() or (lockpath.exists() and lockpath.stat().st_mode & 0o077):raise Rejected("private_store_required")
        if owner_fd is not None:
            expected=lockpath.stat();actual=os.fstat(owner_fd)
            if (expected.st_dev,expected.st_ino)!=(actual.st_dev,actual.st_ino) or actual.st_uid!=os.getuid() or actual.st_mode&0o077:
                raise Rejected('invalid_store_owner_lock')
            fd=owner_fd
        else:fd=os.open(lockpath,os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,0o600)
        self.owner_fd = fd
        try:fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd);raise Rejected('store_already_owned') from None
        try:
            if preflight is not None:preflight()
            self._initialize_database(path)
        except BaseException:
            if hasattr(self,'db'):self.db.close()
            os.close(self.owner_fd);raise

    def _initialize_database(self,path):
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        version=self.db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0,1,2):
            raise Rejected('unsupported_store_schema')
        self.db.executescript('''
PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS subjects(key TEXT PRIMARY KEY,principal TEXT NOT NULL,owner TEXT NOT NULL,pane TEXT NOT NULL,terminal TEXT NOT NULL,native TEXT,content INTEGER NOT NULL,generation INTEGER NOT NULL DEFAULT 1,state TEXT,completion INTEGER,source_revision INTEGER,revision INTEGER NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 1,gap_reason TEXT,current TEXT,observed REAL);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,subject TEXT NOT NULL,name TEXT NOT NULL,body TEXT NOT NULL,at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,principal TEXT NOT NULL,subject TEXT NOT NULL,name TEXT NOT NULL,args TEXT NOT NULL,url TEXT NOT NULL,secret TEXT NOT NULL,expires REAL NOT NULL,active INTEGER NOT NULL,epoch INTEGER NOT NULL DEFAULT 1,previous_secret TEXT,rotation_until REAL);
CREATE TABLE IF NOT EXISTS deliveries(event TEXT NOT NULL,sub TEXT NOT NULL,epoch INTEGER NOT NULL,state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_at REAL NOT NULL DEFAULT 0,status INTEGER,PRIMARY KEY(event,sub));
CREATE TABLE IF NOT EXISTS verifications(principal TEXT,url TEXT,fingerprint TEXT,at REAL,PRIMARY KEY(principal,url));
CREATE TABLE IF NOT EXISTS receipts(sub TEXT NOT NULL,event TEXT NOT NULL,phase TEXT NOT NULL,body TEXT NOT NULL,at REAL NOT NULL,PRIMARY KEY(sub,event,phase));
''')
        # Upgrade the first candidate schema without losing journal/outbox history.
        try:
            self.db.execute('BEGIN IMMEDIATE')
            columns={r['name'] for r in self.db.execute('PRAGMA table_info(subscriptions)')}
            for column,kind in (('previous_secret','TEXT'),('rotation_until','REAL')):
                if column not in columns:self.db.execute(f'ALTER TABLE subscriptions ADD COLUMN {column} {kind}')
            self.db.execute('CREATE TABLE IF NOT EXISTS actions(principal TEXT NOT NULL,request_id TEXT NOT NULL,fingerprint TEXT NOT NULL,result TEXT NOT NULL,at REAL NOT NULL,PRIMARY KEY(principal,request_id))')
            self.db.execute('PRAGMA user_version=2')
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        self.db.execute("UPDATE deliveries SET state='pending' WHERE state='sending'")
        for suffix in ('', '-wal', '-shm'):
            if Path(str(path)+suffix).exists(): os.chmod(str(path)+suffix, 0o600)

    def close(self):
        self.db.close()
        os.close(self.owner_fd)

    def enroll(self, key, principal, owner, pane, terminal, native=None, content=False):
        for v in (key, principal, owner, pane, terminal):
            if not isinstance(v, str) or not 1 <= len(v) <= 256: raise Rejected('invalid_enrollment')
        with self.lock, self.db:
            old = self.db.execute('SELECT * FROM subjects WHERE key=?', (key,)).fetchone()
            if not isinstance(content,bool):raise Rejected('invalid_content_grant')
            args = (principal, owner, pane, terminal, encode(native) if native else None)
            if old:
                if tuple(old[x] for x in ('principal','owner','pane','terminal','native')) != args:
                    raise Rejected('enrollment_changed_rebind_required')
                self.db.execute('UPDATE subjects SET content=? WHERE key=?',(int(content),key))
                return
            self.db.execute('INSERT INTO subjects(key,principal,owner,pane,terminal,native,content) VALUES (?,?,?,?,?,?,?)', (key,)+args+(int(content),))

    def apply_roster(self, enrollments):
        """Validate every immutable binding before atomically applying approved policy."""
        prepared=[];keys=set()
        for item in enrollments:
            values=tuple(item.get(k) for k in ('key','principal','owner','pane','terminal'))
            if any(not isinstance(v,str) or not 1<=len(v)<=256 for v in values):raise Rejected('invalid_enrollment')
            if values[0] in keys:raise Rejected('duplicate_subject')
            keys.add(values[0]);content=item.get('content',False)
            if not isinstance(content,bool):raise Rejected('invalid_content_grant')
            prepared.append(values+(encode(item['native']) if item.get('native') else None,int(content)))
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                for args in prepared:
                    old=self.db.execute('SELECT * FROM subjects WHERE key=?',(args[0],)).fetchone()
                    if old and tuple(old[k] for k in ('principal','owner','pane','terminal','native'))!=args[1:6]:
                        raise Rejected('enrollment_changed_rebind_required')
                for args in prepared:
                    self.db.execute('INSERT INTO subjects(key,principal,owner,pane,terminal,native,content) VALUES (?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET content=excluded.content,enabled=1',args)
                for row in self.db.execute('SELECT key,enabled FROM subjects').fetchall():
                    if row['key'] not in keys:
                        self.db.execute('UPDATE subjects SET enabled=0 WHERE key=?',(row['key'],))
                        if row['enabled']:
                            self.db.execute('UPDATE subscriptions SET active=0,epoch=epoch+1 WHERE subject=?',(row['key'],))
                            self.db.execute("UPDATE deliveries SET state='stopped' WHERE sub IN (SELECT id FROM subscriptions WHERE subject=?) AND state IN ('pending','sending')",(row['key'],))
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise

    def sync_roster(self, keys):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                for row in self.db.execute('SELECT key FROM subjects').fetchall():
                    active=int(row['key'] in keys)
                    self.db.execute('UPDATE subjects SET enabled=? WHERE key=?',(active,row['key']))
                    if not active:
                        self.db.execute('UPDATE subscriptions SET active=0,epoch=epoch+1 WHERE subject=?',(row['key'],))
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise

    def subject(self, principal, key):
        row = self.db.execute('SELECT * FROM subjects WHERE key=? AND principal=? AND enabled=1', (key, principal)).fetchone()
        if not row: raise Rejected('forbidden_scope')
        return row

    def begin_action(self, principal, request_id, operation):
        """Persist uncertainty before source input. Replays never submit again."""
        if not isinstance(request_id,str) or not 1<=len(request_id)<=128:raise Rejected('invalid_request_id')
        fingerprint=hashlib.sha256(encode(operation).encode()).hexdigest()
        with self.lock:
            row=self.db.execute('SELECT * FROM actions WHERE principal=? AND request_id=?',(principal,request_id)).fetchone()
            if row:
                if row['fingerprint']!=fingerprint:raise Rejected('request_id_conflict')
                return json.loads(row['result'])
            result={'request_id':request_id,'outcome':'unknown','retry':'inspect_source_do_not_resubmit'}
            self.db.execute('INSERT INTO actions VALUES (?,?,?,?,?)',(principal,request_id,fingerprint,encode(result),self.clock()))
            return None

    def finish_action(self, principal, request_id, result):
        result=json.loads(encode(result))
        with self.lock:
            self.db.execute('UPDATE actions SET result=? WHERE principal=? AND request_id=?',(encode(result),principal,request_id))
        return result

    def _event(self, row, name, revision, origin, extra):
        stamp = self.clock(); event_id = 'evt_' + secrets.token_hex(16)
        data = {'schema_version':2,'subject_key':row['key'],'owner_key':row['owner'],
                'generation':row['generation'],'revision':revision,'origin':origin,
                'observed_at':iso(stamp),'occurred_at':None,'time_basis':'observation',
                'upstream_history':'best_effort','captured_history':'durable_since_commit',
                'goal_status':'unknown',**extra}
        body = {'eventId':event_id,'name':name,'timestamp':iso(stamp),'cursor':None,'data':data}
        if len(encode(body).encode()) > MAX_EVENT: raise Rejected('payload_too_large')
        self.db.execute('INSERT INTO events(id,subject,name,body,at) VALUES (?,?,?,?,?)',(event_id,row['key'],name,encode(body),stamp))
        self.db.execute('''INSERT INTO deliveries(event,sub,epoch)
SELECT ?,id,epoch FROM subscriptions WHERE subject=? AND name=? AND active=1 AND expires>?''',
                        (event_id,row['key'],name,stamp))
        return event_id

    def observe(self, key, agent, origin='transition_observed'):
        if len(encode(agent).encode()) > 65536: raise Rejected('source_too_large')
        if origin not in ('transition_observed','baseline','reconciliation'): raise Rejected('invalid_origin')
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row=self.db.execute('SELECT * FROM subjects WHERE key=?',(key,)).fetchone()
                if not row or not row['enabled']: raise Rejected('unknown_subject')
                if agent.get('terminal_id') != row['terminal'] or agent.get('pane_id') != row['pane']:
                    raise Rejected('identity_changed')
                if row['native'] and encode(agent.get('agent_session')) != row['native']: raise Rejected('identity_changed')
                state=agent.get('agent_status'); seq=agent.get('completion_seq'); source_rev=agent.get('revision')
                if state not in STATUS or not isinstance(source_rev,int) or isinstance(source_rev,bool) or source_rev<0:
                    raise Rejected('malformed_source')
                if seq is not None and (not isinstance(seq,int) or isinstance(seq,bool) or seq<0): raise Rejected('malformed_source')
                if row['source_revision'] is not None and source_rev < row['source_revision']: raise Rejected('source_revision_regressed')
                if seq is not None and row['completion'] is not None and seq < row['completion']: raise Rejected('source_counter_regressed')
                revision=row['revision']; emitted=[]; baseline=row['state'] is None or row['gap_reason'] is not None
                actual_origin='baseline' if baseline else origin
                if not baseline and state!=row['state']:
                    revision+=1
                    emitted.append(self._event(row,'herdr.lifecycle.changed',revision,actual_origin,{'state':state,'previous_state':row['state']}))
                    if state=='blocked':
                        emitted.append(self._event(row,'herdr.attention.detected',revision,actual_origin,{'state':state,'category':'detected_blocked','decision_authority':'unknown','detail_available':bool(row['content'])}))
                if not baseline and seq is not None and row['completion'] is not None and seq>row['completion']:
                    revision+=1
                    emitted.append(self._event(row,'herdr.turn.completed',revision,actual_origin,{'completion_seq':seq,'completion_kind':'turn_completed'}))
                for field in ('screen_detection_skipped','interactive_ready','launch_pending'):
                    if field in agent and not isinstance(agent[field],bool):raise Rejected('malformed_source')
                counter=agent.get('state_change_seq')
                if 'state_change_seq' in agent and (not isinstance(counter,int) or isinstance(counter,bool) or counter<0):raise Rejected('malformed_source')
                safe={k:agent[k] for k in ('agent_status','revision','state_change_seq','completion_seq','screen_detection_skipped','interactive_ready','launch_pending') if k in agent}
                self.db.execute('UPDATE subjects SET gap_reason=NULL,state=?,completion=?,source_revision=?,revision=?,current=?,observed=? WHERE key=?',
                                (state, seq if seq is not None else row['completion'],source_rev,revision,encode(safe),self.clock(),key))
                self.db.execute('COMMIT'); return emitted
            except BaseException:
                self.db.execute('ROLLBACK'); raise

    def gap(self, key, reason):
        if reason not in ('disconnected','identity_changed','source_error','source_revision_regressed','source_counter_regressed'):
            reason='source_error'
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row=self.db.execute('SELECT * FROM subjects WHERE key=?',(key,)).fetchone()
                if not row or not row['enabled']: raise Rejected('unknown_subject')
                if row['gap_reason']==reason:
                    self.db.execute('COMMIT');return None
                event=self._event(row,'herdr.coverage.changed',row['revision']+1,'reconciliation',{'coverage_state':'gapped','reason_code':reason,'history_complete':False})
                self.db.execute('UPDATE subjects SET revision=revision+1,gap_reason=? WHERE key=?',(reason,key))
                self.db.execute('COMMIT');return event
            except BaseException:self.db.execute('ROLLBACK');raise

    def state(self, principal, key):
        with self.lock:
            row=self.subject(principal,key)
            return {'subject_key':key,'generation':row['generation'],'revision':row['revision'],
                    'state':json.loads(row['current']) if row['current'] else None,
                    'source_observed_at':iso(row['observed']) if row['observed'] else None,
                    'freshness':'cached','upstream_history':'best_effort','captured_history':'durable_since_commit','goal_status':'unknown','known_gap':row['gap_reason']}

    def timeline(self, principal, key, after=0, limit=25):
        if not isinstance(after,int) or after<0 or not isinstance(limit,int) or not 1<=limit<=100: raise Rejected('invalid_cursor')
        with self.lock:
            self.subject(principal,key)
            rows=self.db.execute('SELECT seq,body FROM events WHERE subject=? AND seq>? ORDER BY seq LIMIT ?', (key,after,limit)).fetchall()
            # Explicit subject is authorized on every read; integer is an application offset, not source/native replay.
            return {'events':[json.loads(r['body']) for r in rows],'next_position':rows[-1]['seq'] if rows else after,
                    'upstream_history':'best_effort','truncated':False}

    def health(self, principal):
        with self.lock:
            rows=self.db.execute('SELECT key,observed,gap_reason FROM subjects WHERE principal=? AND enabled=1',(principal,)).fetchall()
            counts=self.db.execute("SELECT d.state,COUNT(*) AS n FROM deliveries d JOIN subscriptions s ON s.id=d.sub WHERE s.principal=? GROUP BY d.state",(principal,)).fetchall()
            return {'subjects':[{'subject_key':r['key'],'last_source_observed_at':iso(r['observed']) if r['observed'] else None,'known_gap':r['gap_reason']} for r in rows],
                    'deliveries':{r['state']:r['n'] for r in counts},'upstream_history':'best_effort',
                    'triage_is_separate':True,'native_replay':False,'retention':'no_auto_prune_operator_capacity_required'}

    def event(self, principal, event):
        with self.lock:
            row=self.db.execute('SELECT e.body FROM events e JOIN subjects s ON s.key=e.subject WHERE e.id=? AND s.principal=? AND s.enabled=1',(event,principal)).fetchone()
            if not row:raise Rejected('forbidden_scope')
            return json.loads(row['body'])

    def subscription_identity(self, principal, name, arguments, url):
        return 'sub_'+hashlib.sha256(encode([principal,url,name,arguments]).encode()).hexdigest()[:32]

    def validate_subscription(self, principal, name, arguments):
        if name not in NAMES:raise Rejected('unknown_event')
        if not isinstance(arguments,dict) or set(arguments)!={'subject_key'} or not isinstance(arguments['subject_key'],str) or not 1<=len(arguments['subject_key'])<=128:raise Rejected('invalid_subscription')
        self.subject(principal,arguments['subject_key'])

    def verification_cached(self,principal,url,secret):
        row=self.db.execute('SELECT fingerprint,at FROM verifications WHERE principal=? AND url=?',(principal,url)).fetchone()
        return bool(row and row['fingerprint']==hashlib.sha256(secret.encode()).hexdigest() and 0<=self.clock()-row['at']<60)

    def verified(self,principal,url,secret):
        self.db.execute('INSERT OR REPLACE INTO verifications VALUES (?,?,?,?)',(principal,url,hashlib.sha256(secret.encode()).hexdigest(),self.clock()))

    def activate(self, principal, name, arguments, url, secret, ttl=3600):
        if not isinstance(ttl,int) or isinstance(ttl,bool) or not 60<=ttl<=86400:raise Rejected('invalid_ttl')
        with self.lock:
            self.validate_subscription(principal,name,arguments)
            now=self.clock();expires=now+ttl
            sub=self.subscription_identity(principal,name,arguments,url)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                old=self.db.execute('SELECT * FROM subscriptions WHERE id=?',(sub,)).fetchone()
                if old:
                    expired=not old['active'] or old['expires']<=now
                    if expired:
                        self.db.execute("UPDATE deliveries SET state='stopped' WHERE sub=? AND state IN ('pending','sending')",(sub,))
                    rotated=old['secret']!=secret and not expired
                    self.db.execute('UPDATE subscriptions SET active=1,expires=?,epoch=epoch+?,secret=?,previous_secret=?,rotation_until=? WHERE id=?',
                        (expires,int(expired),secret,old['secret'] if rotated else (old['previous_secret'] if not expired else None),
                         now+60 if rotated else (old['rotation_until'] if not expired else None),sub))
                else:
                    self.db.execute('INSERT INTO subscriptions(id,principal,subject,name,args,url,secret,expires,active) VALUES (?,?,?,?,?,?,?,?,1)',
                        (sub,principal,arguments['subject_key'],name,encode(arguments),url,secret,expires))
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
            return {'id':sub,'refreshBefore':iso(expires),'cursor':None,'truncated':False}

    def unsubscribe(self, principal, name, arguments, url):
        with self.lock:
            self.validate_subscription(principal,name,arguments)
            sub=self.subscription_identity(principal,name,arguments,url)
            self.db.execute('UPDATE subscriptions SET active=0,epoch=epoch+1 WHERE id=? AND principal=?',(sub,principal))
            self.db.execute("UPDATE deliveries SET state='stopped' WHERE sub=? AND state IN ('pending','sending')",(sub,))

    def claim(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row=self.db.execute('''SELECT d.*,s.url,s.secret,s.previous_secret,s.rotation_until,s.principal,s.expires,e.body FROM deliveries d
JOIN subscriptions s ON s.id=d.sub JOIN events e ON e.id=d.event JOIN subjects p ON p.key=s.subject
WHERE d.state='pending' AND d.next_at<=? AND s.active=1 AND s.expires>? AND s.epoch=d.epoch AND p.principal=s.principal AND p.enabled=1 ORDER BY e.seq LIMIT 1''',(self.clock(),self.clock())).fetchone()
                if row:self.db.execute("UPDATE deliveries SET state='sending',attempts=attempts+1 WHERE event=? AND sub=?",(row['event'],row['sub']))
                self.db.execute('COMMIT');return dict(row) if row else None
            except BaseException:self.db.execute('ROLLBACK');raise

    def active(self, item):
        with self.lock:
            row=self.db.execute('SELECT active,epoch,expires FROM subscriptions WHERE id=?',(item['sub'],)).fetchone()
            return bool(row and row['active'] and row['epoch']==item['epoch'] and row['expires']>self.clock())

    def delivered(self,item,status):
        with self.lock:
            if not self.active(item):state='stopped'
            elif 200<=status<300:state='accepted'
            elif status in (410,413,401,403) or item['attempts']+1>=6:state='dead_letter'
            else:state='pending'
            self.db.execute('UPDATE deliveries SET state=?,status=?,next_at=? WHERE event=? AND sub=? AND epoch=?',(state,status,self.clock()+min(60,2**(item['attempts']+1)),item['event'],item['sub'],item['epoch']))
            if status in (410,401,403):self.db.execute('UPDATE subscriptions SET active=0,epoch=epoch+1 WHERE id=? AND epoch=? AND secret=?',(item['sub'],item['epoch'],item['secret']))

    def receipt(self,principal,event,sub,phase,disposition):
        if phase not in ('started','finished') or disposition not in ('observed','detail_reviewed','no_action','paused','superseded','human_decision_needed','coverage_uncertain'):raise Rejected('invalid_receipt')
        body=encode({'disposition':disposition})
        with self.lock:
            if sub in (None,''):  # Older host schemas require a string; both forms infer only an unambiguous watch.
                subs=self.db.execute('SELECT DISTINCT d.sub FROM deliveries d JOIN subscriptions s ON s.id=d.sub WHERE d.event=? AND s.principal=?',(event,principal)).fetchall()
                if not subs:raise Rejected('forbidden_scope')
                if len(subs)>1:raise Rejected('subscription_key_required')
                sub=subs[0][0]
            row=self.db.execute('''SELECT 1 FROM deliveries d JOIN subscriptions s ON s.id=d.sub
JOIN events e ON e.id=d.event JOIN subjects p ON p.key=e.subject
WHERE d.event=? AND d.sub=? AND s.principal=? AND p.principal=? AND p.enabled=1''',(event,sub,principal,principal)).fetchone()
            if not row:raise Rejected('forbidden_scope')
            old=self.db.execute('SELECT body,at FROM receipts WHERE sub=? AND event=? AND phase=?',(sub,event,phase)).fetchone()
            if old and old['body']!=body:raise Rejected('receipt_conflict')
            stamp=old['at'] if old else self.clock()
            if not old:self.db.execute('INSERT INTO receipts VALUES (?,?,?,?,?)',(sub,event,phase,body,stamp))
            return {'event_id':event,'subscription_key':sub,'phase':phase,'recorded_at':iso(stamp),'disposition':disposition,'proves':'authenticated_triage_report_not_chat_attestation'}
