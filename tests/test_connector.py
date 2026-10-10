import asyncio
import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx2
import jsonschema
from mcp.server.auth.provider import AccessToken
from dot_herdr.core import Store,Rejected,NAMES
from dot_herdr.endpoint import build,principal_key,catalog
from dot_herdr.herdr import HerdrClient
from dot_herdr.webhooks import verify,deliver_one,headers,destination,decode_secret,PinnedHTTPS,PublicTransport,CallbackError

ISSUER='https://auth.example.invalid'; RESOURCE='https://connector.example.invalid/mcp'
SECRET='whsec_'+base64.b64encode(b'x'*32).decode()
USER=principal_key(ISSUER,'user-demo')

def agent(state='working',rev=1,completion=0):
    return {'terminal_id':'terminal_demo','pane_id':'pane_demo','agent_status':state,'revision':rev,'state_change_seq':rev,'completion_seq':completion}

class Clock:
    def __init__(self):self.now=2000000000
    def __call__(self):return self.now

class FakeWebhook:
    def __init__(self):self.calls=[];self.status=202;self.throw=False
    async def post(self,url,body,hs):
        self.calls.append((url,body,hs))
        if self.throw:raise TimeoutError
        if 'verification_' in hs['webhook-id']:
            return 200,body
        return self.status,b'{}'

class FakeHerdr:
    def __init__(self):self.current=agent()
    async def agent(self,pane):return dict(self.current)
    async def visible(self,pane,lines):return {'text':'Synthetic decision options: A or B.','revision':0,'truncated':False}

class Verifier:
    async def verify_token(self,token):
        if token not in ('synthetic-user','synthetic-other'):return None
        return AccessToken(token=token,client_id='synthetic-client',subject='user-demo' if token=='synthetic-user' else 'other-demo',
                           resource=RESOURCE,scopes=['herdr:observe'],claims={'iss':ISSUER})

class CoreTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'journal.sqlite';self.clock=Clock()
        self.store=Store(self.path,self.clock);self.store.enroll('parent_demo',USER,'owner_demo','pane_demo','terminal_demo',content=True)
        self.webhook=FakeWebhook()
    def tearDown(self):self.store.close();self.temp.cleanup()
    async def subscribe(self,name=NAMES[0]):
        args={'subject_key':'parent_demo'};url='https://callback.example.invalid/event'
        sub=self.store.subscription_identity(USER,name,args,url)
        await verify(self.webhook,url,SECRET,sub,self.clock)
        return self.store.activate(USER,name,args,url,SECRET)
    async def test_vertical_capture_delivery_signature_detail_receipt_restart(self):
        sub=await self.subscribe();self.store.observe('parent_demo',agent(),'baseline')
        ids=self.store.observe('parent_demo',agent('blocked',2))
        attention=next(i for i in ids if self.store.event(USER,i)['name']==NAMES[0])
        self.assertTrue(await deliver_one(self.store,self.webhook))
        _,body,hs=self.webhook.calls[-1]
        signed=(hs['webhook-id']+'.'+hs['webhook-timestamp']+'.').encode()+body
        expected='v1,'+base64.b64encode(hmac.new(b'x'*32,signed,hashlib.sha256).digest()).decode()
        self.assertEqual(hs['webhook-signature'],expected)
        self.assertEqual(json.loads(body)['data']['goal_status'],'unknown')
        self.assertEqual(self.store.state(USER,'parent_demo')['state']['agent_status'],'blocked')
        r=self.store.receipt(USER,attention,sub['id'],'started','observed')
        self.clock.now+=5
        self.assertEqual(r,self.store.receipt(USER,attention,sub['id'],'started','observed'))
        with self.assertRaisesRegex(Rejected,'receipt_conflict'):self.store.receipt(USER,attention,sub['id'],'started','no_action')
        self.store.close();self.store=Store(self.path,self.clock)
        self.assertFalse(await deliver_one(self.store,self.webhook))
        self.assertEqual(len(self.store.timeline(USER,'parent_demo')['events']),2)
    async def test_pending_restart_retains_id_and_bytes(self):
        await self.subscribe();self.store.observe('parent_demo',agent(),'baseline')
        ids=self.store.observe('parent_demo',agent('blocked',2));pending=self.store.claim()
        self.store.close();self.store=Store(self.path,self.clock)
        await deliver_one(self.store,self.webhook)
        self.assertEqual(self.webhook.calls[-1][1],pending['body'].encode())
        self.assertEqual(self.webhook.calls[-1][2]['webhook-id'],pending['event'])
    async def test_duplicate_presentation_and_baseline_do_not_wake(self):
        await self.subscribe();self.assertEqual(self.store.observe('parent_demo',agent('blocked')) ,[])
        a=agent('blocked',2);a['title']='Do things';self.assertEqual(self.store.observe('parent_demo',a),[])
        self.assertIsNone(self.store.claim())
    async def test_turn_is_not_goal_success(self):
        self.store.observe('parent_demo',agent());ids=self.store.observe('parent_demo',agent('done',2,1))
        turns=[self.store.event(USER,i) for i in ids if self.store.event(USER,i)['name']==NAMES[1]]
        self.assertEqual(len(turns),1);self.assertEqual(turns[0]['data']['goal_status'],'unknown')
        self.assertEqual(self.store.observe('parent_demo',agent('idle',3,1))[0] in ids,False)
    async def test_identity_regression_rollback_and_gaps(self):
        self.store.observe('parent_demo',agent(rev=2))
        bad=agent('blocked',3);bad['terminal_id']='replacement'
        with self.assertRaisesRegex(Rejected,'identity_changed'):self.store.observe('parent_demo',bad)
        self.assertEqual(self.store.timeline(USER,'parent_demo')['events'],[])
        with self.assertRaises(Rejected):self.store.observe('parent_demo',agent(rev=1))
        self.store.gap('parent_demo','disconnected');self.store.gap('parent_demo','disconnected')
        self.assertEqual(len(self.store.timeline(USER,'parent_demo')['events']),1)
        # First recovered observation is a baseline, never a reconstructed turn/blocked episode.
        self.assertEqual(self.store.observe('parent_demo',agent('blocked',4,2)),[])
    async def test_scope_isolation_and_forged_receipt(self):
        sub=await self.subscribe();self.store.observe('parent_demo',agent());ids=self.store.observe('parent_demo',agent('blocked',2))
        for action in (lambda:self.store.state('other','parent_demo'),lambda:self.store.event('other',ids[0]),
                       lambda:self.store.receipt('other',ids[0],sub['id'],'started','observed')):
            with self.assertRaisesRegex(Rejected,'forbidden_scope'):action()
    async def test_receipt_without_subscription_key_uses_the_single_delivered_watch(self):
        # Automation hosts see the event body, not the X-MCP-Subscription-Id header.
        sub=await self.subscribe();self.store.observe('parent_demo',agent(),'baseline');ids=self.store.observe('parent_demo',agent('blocked',2))
        attention=next(i for i in ids if self.store.event(USER,i)['name']==NAMES[0])
        r=self.store.receipt(USER,attention,None,'finished','observed')
        self.assertEqual(r['subscription_key'],sub['id'])
        self.assertEqual(r,self.store.receipt(USER,attention,sub['id'],'finished','observed'))
        with self.assertRaisesRegex(Rejected,'forbidden_scope'):self.store.receipt('other',attention,None,'finished','observed')
    async def test_receipt_without_subscription_key_refuses_several_watches(self):
        await self.subscribe()
        args={'subject_key':'parent_demo'};url='https://callback.example.invalid/other'
        await verify(self.webhook,url,SECRET,self.store.subscription_identity(USER,NAMES[0],args,url),self.clock)
        self.store.activate(USER,NAMES[0],args,url,SECRET)
        self.store.observe('parent_demo',agent(),'baseline');ids=self.store.observe('parent_demo',agent('blocked',2))
        attention=next(i for i in ids if self.store.event(USER,i)['name']==NAMES[0])
        with self.assertRaisesRegex(Rejected,'subscription_key_required'):self.store.receipt(USER,attention,None,'finished','observed')
    async def test_unsubscribe_expiry_and_roster_revocation(self):
        sub=await self.subscribe();self.store.observe('parent_demo',agent());self.store.observe('parent_demo',agent('blocked',2))
        self.store.unsubscribe(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event')
        self.assertFalse(await deliver_one(self.store,self.webhook))
        self.assertEqual(self.store.activate(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event',SECRET)['id'],sub['id'])
        await self.subscribe(NAMES[1]);self.store.observe('parent_demo',agent('idle',3,1));self.clock.now+=4000
        self.assertFalse(await deliver_one(self.store,self.webhook))
        self.store.sync_roster(set())
        with self.assertRaises(Rejected):self.store.state(USER,'parent_demo')
    async def test_retry_acceptance_does_not_wait_for_receipt(self):
        await self.subscribe();self.store.observe('parent_demo',agent());self.store.observe('parent_demo',agent('blocked',2))
        self.webhook.throw=True;await deliver_one(self.store,self.webhook);event=self.webhook.calls[-1][2]['webhook-id']
        self.clock.now+=100;self.webhook.throw=False;await deliver_one(self.store,self.webhook)
        self.assertEqual(self.webhook.calls[-1][2]['webhook-id'],event)
        self.clock.now+=100;self.assertFalse(await deliver_one(self.store,self.webhook))
    async def test_schema_and_default_payload_privacy(self):
        self.store.observe('parent_demo',agent());a=agent('blocked',2);a.update(title='sensitive-title',cwd='/private/source',tokens={'secret':'not for export'})
        for eid in self.store.observe('parent_demo',a):
            e=self.store.event(USER,eid);schema=next(x for x in catalog() if x['name']==e['name'])['payloadSchema']
            jsonschema.validate(e['data'],schema);self.assertNotIn('sensitive-title',json.dumps(e));self.assertNotIn('/private',json.dumps(e))
    async def test_store_requires_private_directory(self):
        os.chmod(self.temp.name,0o755)
        with self.assertRaisesRegex(Rejected,'private_store_required'):Store(Path(self.temp.name)/'unsafe.sqlite')
        os.chmod(self.temp.name,0o700)

class RegressionTests(unittest.IsolatedAsyncioTestCase):
    setUp=CoreTests.setUp
    tearDown=CoreTests.tearDown
    subscribe=CoreTests.subscribe
    async def test_malformed_metadata_cannot_smuggle_content(self):
        self.store.enroll('no_content',USER,'owner_demo','pane_demo','terminal_demo',content=False)
        self.store.observe('no_content',agent())
        for field,value in (('interactive_ready',{'private':'synthetic withheld'}),('screen_detection_skipped','synthetic withheld'),('launch_pending',1),('state_change_seq',{'private':'synthetic withheld'})):
            bad=agent('blocked',2);bad[field]=value
            with self.assertRaisesRegex(Rejected,'malformed_source'):self.store.observe('no_content',bad)
            self.assertNotIn('withheld',json.dumps(self.store.state(USER,'no_content')));self.assertEqual(self.store.timeline(USER,'no_content')['events'],[])
    async def test_restart_source_session_baseline_does_not_invent_turns(self):
        from dot_herdr.herdr import prepare_observation_session
        self.store.observe('parent_demo',agent());self.store.close();self.store=Store(self.path,self.clock)
        prepare_observation_session(self.store)
        self.assertEqual(self.store.state(USER,'parent_demo')['known_gap'],'disconnected')
        self.assertEqual(self.store.observe('parent_demo',agent('done',9,5),'reconciliation'),[])
        self.assertEqual([e['name'] for e in self.store.timeline(USER,'parent_demo')['events']],[NAMES[3]])
    async def test_legacy_schema_migration_preserves_journal_outbox(self):
        import sqlite3
        await self.subscribe();self.store.observe('parent_demo',agent());self.store.observe('parent_demo',agent('blocked',2))
        original=self.store.timeline(USER,'parent_demo')['events'];self.store.close()
        db=sqlite3.connect(self.path)
        db.execute('ALTER TABLE subscriptions DROP COLUMN previous_secret');db.execute('ALTER TABLE subscriptions DROP COLUMN rotation_until');db.execute('PRAGMA user_version=0');db.commit();db.close()
        self.store=Store(self.path,self.clock)
        self.assertEqual(self.store.timeline(USER,'parent_demo')['events'],original)
        self.assertIsNotNone(self.store.claim());self.assertEqual(self.store.db.execute('PRAGMA user_version').fetchone()[0],2)
    async def test_future_schema_rejected_and_ownership_released(self):
        self.store.db.execute('PRAGMA user_version=999');self.store.close()
        for _ in range(2):
            with self.assertRaisesRegex(Rejected,'unsupported_store_schema'):Store(self.path,self.clock)
        import sqlite3
        db=sqlite3.connect(self.path);db.execute('PRAGMA user_version=1');db.close();self.store=Store(self.path,self.clock)
    async def test_late_old_epoch_terminal_response_cannot_disable_new_watch(self):
        for status in (410,401,403):
            await self.subscribe();self.store.observe('parent_demo',agent('working',self.clock.now));self.store.observe('parent_demo',agent('blocked',self.clock.now+1))
            old=self.store.claim();self.assertIsNotNone(old)
            self.store.unsubscribe(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event')
            new=await self.subscribe();before=dict(self.store.db.execute('SELECT active,epoch FROM subscriptions WHERE id=?',(new['id'],)).fetchone())
            self.store.delivered(old,status)
            after=dict(self.store.db.execute('SELECT active,epoch FROM subscriptions WHERE id=?',(new['id'],)).fetchone())
            self.assertEqual(after,before);self.assertEqual(after['active'],1)
            self.clock.now+=100
            self.store.observe('parent_demo',agent('working',self.clock.now));self.store.observe('parent_demo',agent('blocked',self.clock.now+1))
            self.assertIsNotNone(self.store.claim())
            self.store.unsubscribe(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event')
            self.clock.now+=100
    async def test_refresh_before_exactly_matches_persisted_expiration(self):
        from dot_herdr.core import iso
        def advancing():
            self.clock.now+=1;return self.clock.now
        self.store.clock=advancing
        sub=self.store.activate(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event',SECRET)
        expires=self.store.db.execute('SELECT expires FROM subscriptions WHERE id=?',(sub['id'],)).fetchone()['expires']
        self.assertEqual(sub['refreshBefore'],iso(expires))
    async def test_expired_refresh_does_not_revive_pending(self):
        sub=await self.subscribe();self.store.observe('parent_demo',agent());self.store.observe('parent_demo',agent('blocked',2))
        self.clock.now+=3601
        new=await self.subscribe();self.assertEqual(sub['id'],new['id']);self.assertIsNone(self.store.claim())
        self.store.observe('parent_demo',agent('working',3));self.store.observe('parent_demo',agent('blocked',4))
        self.assertIsNotNone(self.store.claim())
    async def test_exclusive_store_ownership(self):
        with self.assertRaisesRegex(Rejected,'store_already_owned'):Store(self.path,self.clock)
        self.store.close();self.store=Store(self.path,self.clock)
    async def test_rotation_and_restart_and_resubscribe(self):
        sub=await self.subscribe();self.store.observe('parent_demo',agent());self.store.observe('parent_demo',agent('blocked',2))
        other='whsec_'+base64.b64encode(b'y'*32).decode()
        new=self.store.activate(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event',other)
        self.assertEqual(sub['id'],new['id']);await deliver_one(self.store,self.webhook)
        self.assertEqual(len(self.webhook.calls[-1][2]['webhook-signature'].split()),2)
        self.store.unsubscribe(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event')
        self.assertEqual((await self.subscribe())['id'],sub['id']);self.assertIsNone(self.store.claim())
    async def test_verification_cache_secret_scoped_and_bounded(self):
        url='https://callback.example.invalid/event'
        self.assertFalse(self.store.verification_cached(USER,url,SECRET));self.store.verified(USER,url,SECRET)
        self.assertTrue(self.store.verification_cached(USER,url,SECRET));self.assertFalse(self.store.verification_cached('other',url,SECRET))
        self.assertFalse(self.store.verification_cached(USER,url,SECRET+'x'))
        self.clock.now+=61;self.assertFalse(self.store.verification_cached(USER,url,SECRET))
    async def test_callback_error_categories_do_not_leak(self):
        import ssl
        for failure,reason in ((TimeoutError('private URL'),'timeout'),(ssl.SSLError('private TLS details'),'tls_error'),(ConnectionRefusedError('private destination'),'connection_refused')):
            class Failed:
                async def post(self,*args):raise failure
            with self.assertRaises(CallbackError) as e:await verify(Failed(),'https://callback.example.invalid',SECRET,'sub',self.clock)
            self.assertEqual(e.exception.reason,reason);self.assertNotIn('private',str(e.exception))
        class HTTPFail:
            async def post(self,*args):return 503,b'private response'
        with self.assertRaises(CallbackError) as e:await verify(HTTPFail(),'https://callback.example.invalid',SECRET,'sub',self.clock)
        self.assertEqual(e.exception.reason,'http_5xx')
        class PolicyFail:
            async def post(self,*args):raise Rejected('callback_policy_rejected')
        with self.assertRaises(Rejected) as e:await verify(PolicyFail(),'https://callback.example.invalid',SECRET,'sub',self.clock)
        self.assertNotIsInstance(e.exception,CallbackError)
        class HTTP4xx:
            async def post(self,*args):return 403,b'private'
        with self.assertRaises(CallbackError) as e:await verify(HTTP4xx(),'https://callback.example.invalid',SECRET,'sub',self.clock)
        self.assertEqual(e.exception.reason,'http_4xx')
    async def test_schema_migration_rolls_back_on_failure(self):
        import sqlite3
        self.store.close();db=sqlite3.connect(self.path)
        db.execute('ALTER TABLE subscriptions DROP COLUMN previous_secret');db.execute('ALTER TABLE subscriptions DROP COLUMN rotation_until');db.execute('PRAGMA user_version=0');db.commit();db.close()
        real_connect=sqlite3.connect
        def blocked(*args,**kw):
            connection=real_connect(*args,**kw)
            def authorize(action,arg1,arg2,*rest):
                if action==sqlite3.SQLITE_ALTER_TABLE and 'rotation_until' not in {r[1] for r in connection.execute('PRAGMA table_info(subscriptions)')}:
                    # Deny the second ALTER only, after the first new column exists.
                    if 'previous_secret' in {r[1] for r in connection.execute('PRAGMA table_info(subscriptions)')}:return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            connection.set_authorizer(authorize);return connection
        with patch('dot_herdr.core.sqlite3.connect',side_effect=blocked):
            with self.assertRaises(sqlite3.DatabaseError):Store(self.path,self.clock)
        db=real_connect(self.path);columns={r[1] for r in db.execute('PRAGMA table_info(subscriptions)')}
        self.assertNotIn('previous_secret',columns);self.assertNotIn('rotation_until',columns);self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],0);db.close()
        self.store=Store(self.path,self.clock)
    async def test_challenge_failure_does_not_activate(self):
        class BadWebhook:
            async def post(self,*args):return 200,b'{"challenge":"old-replayed"}'
        with self.assertRaisesRegex(Rejected,'callback_verification_failed'):await verify(BadWebhook(),'https://callback.example.invalid',SECRET,'sub',self.clock)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM subscriptions').fetchone()[0],0)
    async def test_stop_during_inflight_does_not_retry(self):
        sub=await self.subscribe();self.store.observe('parent_demo',agent());self.store.observe('parent_demo',agent('blocked',2))
        store=self.store
        class StopWebhook:
            async def post(self,*args):
                store.unsubscribe(USER,NAMES[0],{'subject_key':'parent_demo'},'https://callback.example.invalid/event');return 503,b'{}'
        await deliver_one(store,StopWebhook());self.assertIsNone(store.claim())
    async def test_terminal_statuses_and_bounded_retry(self):
        for status in (410,413,503):
            url='https://callback.example.invalid/'+str(status)
            self.store.activate(USER,NAMES[0],{'subject_key':'parent_demo'},url,SECRET)
            self.store.observe('parent_demo',agent('working',self.clock.now));self.store.observe('parent_demo',agent('blocked',self.clock.now+1))
            self.webhook.status=status
            for attempt in range(7):
                await deliver_one(self.store,self.webhook);self.clock.now+=100
            rows=self.store.db.execute('SELECT d.attempts,d.state FROM deliveries d JOIN subscriptions s ON s.id=d.sub WHERE s.url=?',(url,)).fetchall()
            self.assertEqual(len(rows),1);self.assertEqual(rows[0]['state'],'dead_letter');self.assertEqual(rows[0]['attempts'],6 if status==503 else 1)
            self.store.unsubscribe(USER,NAMES[0],{'subject_key':'parent_demo'},url)
    async def test_payload_limit_at_transport_boundary(self):
        transport=PublicTransport()
        with patch.object(transport,'_post',return_value=(202,b'{}')) as send:
            await transport.post('https://synthetic.invalid',b'x'*262144,{})
            self.assertEqual(send.call_count,1)
            with self.assertRaisesRegex(Rejected,'payload_too_large'):await transport.post('https://synthetic.invalid',b'x'*262145,{})
            self.assertEqual(send.call_count,1)
    async def test_signing_key_boundaries_and_fresh_retry_timestamp(self):
        for size in (24,64):self.assertEqual(len(decode_secret('whsec_'+base64.b64encode(b'x'*size).decode())),size)
        for size in (23,65):
            with self.assertRaises(Rejected):decode_secret('whsec_'+base64.b64encode(b'x'*size).decode())
        await self.subscribe();self.store.observe('parent_demo',agent());self.store.observe('parent_demo',agent('blocked',2))
        self.webhook.throw=True;await deliver_one(self.store,self.webhook);old=self.webhook.calls[-1]
        self.clock.now+=100;self.webhook.throw=False;await deliver_one(self.store,self.webhook);new=self.webhook.calls[-1]
        self.assertEqual(old[1],new[1]);self.assertEqual(old[2]['webhook-id'],new[2]['webhook-id'])
        self.assertNotEqual(old[2]['webhook-timestamp'],new[2]['webhook-timestamp']);self.assertNotEqual(old[2]['webhook-signature'],new[2]['webhook-signature'])
        self.assertEqual(new[2]['X-MCP-Subscription-Id'],self.store.db.execute('SELECT id FROM subscriptions').fetchone()['id'])
    async def test_signed_malformed_scope_fails_closed(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from dot_herdr.endpoint import JWTVerifier
        import time
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        c={'iss':ISSUER,'aud':RESOURCE,'sub':'user-demo','client_id':'client-demo','exp':int(time.time())+60,'iat':int(time.time()),'scope':['herdr:observe']}
        verifier=JWTVerifier(ISSUER,RESOURCE,public)
        self.assertIsNone(await verifier.verify_token(jwt.encode(c,key,algorithm='RS256')))
        c['scope']='herdr:observe';self.assertIsNotNone(await verifier.verify_token(jwt.encode(c,key,algorithm='RS256')))
        c['aud']='https://wrong.invalid';self.assertIsNone(await verifier.verify_token(jwt.encode(c,key,algorithm='RS256')))

class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    setUp=CoreTests.setUp
    tearDown=CoreTests.tearDown
    async def test_mcp_skill_import_catalog_resource_and_auth(self):
        from importlib.resources import files
        from dot_herdr.skills import SKILL_URI,SKILL_BASE,SKILL_FILES
        raw=files('dot_herdr').joinpath('skills','herdr-connector','SKILL.md').read_bytes()
        expected_frontmatter=json.loads(raw.decode().split('---\n',2)[1])
        server=build(self.store,FakeHerdr(),self.webhook,Verifier(),ISSUER,RESOURCE)
        app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000',trust_env=False) as client:
                async def rpc(method,params=None,token='synthetic-user'):
                    hs={'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method}
                    if token:hs['Authorization']='Bearer '+token
                    if method=='resources/read':hs['Mcp-Name']=params['uri']
                    body={'jsonrpc':'2.0','id':1,'method':method,'params':{**(params or {}),'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}}
                    response=await client.post('/mcp',headers=hs,json=body)
                    return response,response.json()
                response,discovery=await rpc('server/discover')
                self.assertEqual(response.status_code,200)
                self.assertIn('io.modelcontextprotocol/skills',discovery['result']['capabilities']['extensions'])
                _,listing=await rpc('skills/list',{})
                entries=listing['result']['skills'];self.assertEqual(len(entries),1)
                entry=entries[0];self.assertEqual(entry['uri'],SKILL_URI)
                self.assertEqual(entry['frontmatter'],expected_frontmatter)
                self.assertEqual(entry['resources'],[{'uri':SKILL_BASE+path,'digest':'sha256:'+hashlib.sha256(files('dot_herdr').joinpath('skills','herdr-connector',path).read_bytes()).hexdigest()} for path in SKILL_FILES])
                self.assertNotIn('nextCursor',listing['result'])
                _,retrieved=await rpc('skills/get',{'uri':SKILL_URI})
                self.assertEqual(retrieved['result']['skill'],entry)
                _,resource=await rpc('resources/read',{'uri':SKILL_URI})
                contents=resource['result']['contents'];self.assertEqual(len(contents),1)
                self.assertEqual(contents[0]['uri'],SKILL_URI)
                self.assertEqual(contents[0]['text'].encode(),raw)
                # Imported references and direct MCP reads are the same bytes.
                for path in SKILL_FILES[1:]:
                    uri=SKILL_BASE+path
                    _,reference=await rpc('resources/read',{'uri':uri})
                    contents=reference['result']['contents']
                    self.assertEqual(contents[0]['text'].encode(),files('dot_herdr').joinpath('skills','herdr-connector',path).read_bytes())
                    denied,_=await rpc('resources/read',{'uri':uri},token=None)
                    self.assertEqual(denied.status_code,401)
                _,bad_cursor=await rpc('skills/list',{'cursor':'unknown-page'})
                self.assertEqual(bad_cursor['error']['code'],-32602)
                for uri in ('skill://dot-herdr/other/SKILL.md','file:///etc/passwd','skill://dot-herdr/herdr-connector/../../private/config.json'):
                    _,unknown=await rpc('skills/get',{'uri':uri})
                    self.assertEqual(unknown['error']['code'],-32011)
                    _,unreadable=await rpc('resources/read',{'uri':uri})
                    self.assertIn('error',unreadable)
                for method,params in (('skills/list',{}),('skills/get',{'uri':SKILL_URI}),('resources/read',{'uri':SKILL_URI})):
                    response,_=await rpc(method,params,token=None)
                    self.assertEqual(response.status_code,401)
    async def test_real_jwt_through_sdk_auth_middleware(self):
        import time,jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from dot_herdr.endpoint import JWTVerifier
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        server=build(self.store,FakeHerdr(),self.webhook,JWTVerifier(ISSUER,RESOURCE,public),ISSUER,RESOURCE)
        app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
        claims={'iss':ISSUER,'aud':RESOURCE,'sub':'user-demo','client_id':'synthetic-client','exp':int(time.time())+60,'iat':int(time.time()),'scope':'herdr:observe'}
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000',trust_env=False) as client:
                async def call(c,k=key):
                    token=jwt.encode(c,k,algorithm='RS256')
                    return await client.post('/mcp',headers={'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream','Mcp-Method':'server/discover','MCP-Protocol-Version':'2026-07-28'},json={'jsonrpc':'2.0','id':1,'method':'server/discover','params':{'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}})
                self.assertEqual((await call(claims)).status_code,200)
                for change in ({'scope':['herdr:observe']},{'aud':'https://wrong.invalid'},{'iss':'https://wrong.invalid'},{'exp':int(time.time())-60}):
                    self.assertEqual((await call({**claims,**change})).status_code,401)
                self.assertEqual((await call({**claims,'scope':'unrelated'})).status_code,403)
                self.assertEqual((await call(claims,rsa.generate_private_key(public_exponent=65537,key_size=2048))).status_code,401)
    async def test_config_check_does_not_open_source_or_store(self):
        import sys
        from dot_herdr.cli import main
        key=Path(self.temp.name)/'synthetic-public.pem';from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        key.write_bytes(rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        config=Path(self.temp.name)/'private.json'
        config.write_text(json.dumps({'store':str(Path(self.temp.name)/'never-created.sqlite'),'socket':'/synthetic/no-socket','issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(key),'subjects':[{'key':'parent_demo','user_subject':'user-demo','owner':'owner_demo','pane':'pane_demo','terminal':'terminal_demo'}]}));config.chmod(0o600)
        with patch.object(sys,'argv',['dot-herdr','check','--config',str(config)]),patch('dot_herdr.cli.Store') as opened:
            main();opened.assert_not_called()
        self.assertFalse((Path(self.temp.name)/'never-created.sqlite').exists())
    async def test_real_sdk_asgi_endpoint_vertical_and_auth(self):
        source=FakeHerdr();server=build(self.store,source,self.webhook,Verifier(),ISSUER,RESOURCE)
        app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000',trust_env=False) as client:
                async def rpc(method,params={},token='synthetic-user'):
                    p={**params,'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}
                    hs={'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method}
                    if method=='tools/call':hs['Mcp-Name']=params['name']
                    r=await client.post('/mcp',headers=hs,json={'jsonrpc':'2.0','id':1,'method':method,'params':p})
                    return r,r.json()
                response,result=await rpc('server/discover');self.assertEqual(response.status_code,200);self.assertIn('events',result['result']['capabilities'])
                _,result=await rpc('events/list');self.assertEqual(len(result['result']['events']),4)
                delivery={'mode':'webhook','url':'https://callback.example.invalid/event','secret':SECRET}
                _,result=await rpc('events/subscribe',{'name':NAMES[0],'arguments':{'subject_key':'parent_demo'},'delivery':delivery})
                self.assertNotIn('error',result);sub=result['result']['id']
                _,no_replay=await rpc('events/subscribe',{'name':NAMES[0],'arguments':{'subject_key':'parent_demo'},'delivery':delivery,'cursor':'unsupported'})
                self.assertEqual(no_replay['error']['code'],-32014)
                _,forbidden=await rpc('events/subscribe',{'name':NAMES[0],'arguments':{'subject_key':'parent_demo'},'delivery':delivery},token='synthetic-other')
                self.assertEqual(forbidden['error']['code'],-32012)
                _,unknown=await rpc('events/subscribe',{'name':'unknown.event','arguments':{'subject_key':'parent_demo'},'delivery':delivery})
                self.assertEqual(unknown['error']['code'],-32011)
                class BadChallenge:
                    async def post(self,*args):return 200,b'{"challenge":"old"}'
                original_post=self.webhook.post;self.webhook.post=BadChallenge().post
                _,failed=await rpc('events/subscribe',{'name':NAMES[0],'arguments':{'subject_key':'parent_demo'},'delivery':{**delivery,'url':'https://bad.example.invalid'}})
                self.assertEqual(failed['error']['code'],-32015);self.assertEqual(failed['error']['data']['reason'],'challenge_failed')
                self.webhook.post=original_post
                self.store.observe('parent_demo',source.current);source.current=agent('blocked',2);ids=self.store.observe('parent_demo',source.current)
                await deliver_one(self.store,self.webhook)
                _,result=await rpc('tools/call',{'name':'get_agent_state','arguments':{'subject_key':'parent_demo'}})
                self.assertFalse(result['result'].get('isError',False));self.assertEqual(result['result']['structuredContent']['state']['agent_status'],'blocked')
                _,result=await rpc('tools/call',{'name':'read_visible_context','arguments':{'subject_key':'parent_demo','expected_generation':1}})
                self.assertIn('Synthetic decision',result['result']['structuredContent']['text'])
                self.assertEqual(result['result']['structuredContent']['revision'],0)
                self.assertEqual(result['result']['structuredContent']['source_agent_revision'],2)
                count=len(self.webhook.calls)
                _,refreshed=await rpc('events/subscribe',{'name':NAMES[0],'arguments':{'subject_key':'parent_demo'},'delivery':delivery,'ttlMs':None})
                self.assertEqual(refreshed['result']['id'],sub);self.assertEqual(len(self.webhook.calls),count)
                replacement={**delivery,'secret':'whsec_'+base64.b64encode(b'y'*32).decode()}
                _,rotated=await rpc('events/subscribe',{'name':NAMES[0],'arguments':{'subject_key':'parent_demo'},'delivery':replacement,'ttlMs':60000})
                self.assertEqual(rotated['result']['id'],sub);self.assertEqual(len(self.webhook.calls),count+1)
                attention=next(i for i in ids if self.store.event(USER,i)['name']==NAMES[0])
                _,result=await rpc('tools/call',{'name':'record_triage_receipt','arguments':{'event_id':attention,'subscription_key':sub,'phase':'started','disposition':'observed'}})
                self.assertFalse(result['result'].get('isError',False))
                _,other=await rpc('tools/call',{'name':'get_agent_state','arguments':{'subject_key':'parent_demo'}},token='synthetic-other')
                self.assertTrue(other['result']['isError'])
                unauthorized=await client.post('/mcp',json={});self.assertEqual(unauthorized.status_code,401)
                _,result=await rpc('events/unsubscribe',{'name':NAMES[0],'arguments':{'subject_key':'parent_demo'},'delivery':{'mode':'webhook','url':delivery['url']}})
                self.assertNotIn('error',result)
                async def revoke_visible(pane,lines):
                    self.store.sync_roster(set());return {'text':'must not return','revision':0,'truncated':False}
                source.visible=revoke_visible
                _,result=await rpc('tools/call',{'name':'read_visible_context','arguments':{'subject_key':'parent_demo','expected_generation':1}})
                self.assertTrue(result['result']['isError']);self.assertNotIn('must not return',json.dumps(result))

class SecurityTests(unittest.TestCase):
    def test_public_destination_all_answers_checked_and_no_redirect(self):
        def resolver(host,port,**kw):return [(2,1,6,'',('93.184.216.34',443))]
        p,ips=destination('https://example.invalid/event',resolver);self.assertEqual(ips,['93.184.216.34'])
        for url in ['http://example.invalid','https://u:p@example.invalid','https://example.invalid:8443','https://example.invalid/#x']:
            with self.assertRaises(Rejected):destination(url,resolver)
        def mixed(*a,**kw):return resolver(*a,**kw)+[(2,1,6,'',('127.0.0.1',443))]
        with self.assertRaises(Rejected):destination('https://example.invalid',mixed)
    def test_connection_pins_ip_preserves_tls_host(self):
        client=PinnedHTTPS('example.invalid','93.184.216.34')
        with patch('socket.create_connection') as connect,patch.object(client._context,'wrap_socket') as tls:
            client.connect();self.assertEqual(connect.call_args[0][0],('93.184.216.34',443));self.assertEqual(tls.call_args.kwargs['server_hostname'],'example.invalid')
    def test_bad_secret_and_altered_bytes(self):
        for secret in ('x','whsec_!!!','whsec_'+base64.b64encode(b'bad').decode()):
            with self.assertRaises(Rejected):decode_secret(secret)
        self.assertNotEqual(headers(SECRET,'evt',b'a','sub',1)['webhook-signature'],headers(SECRET,'evt',b'b','sub',1)['webhook-signature'])

class HerdrWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_read_decoder_and_reject_unknown_method(self):
        client=HerdrClient('synthetic-unused')
        class Writer:
            sent=b''
            def write(self,x):self.sent+=x
            async def drain(self):pass
            def close(self):pass
            async def wait_closed(self):pass
        reader=asyncio.StreamReader();reader.feed_data(json.dumps({'id':'read','result':{'agent':agent()}}).encode()+b'\n');reader.feed_eof();writer=Writer()
        async def fake_open():return reader,writer
        client._open=fake_open
        self.assertEqual((await client.agent('pane_demo'))['terminal_id'],'terminal_demo')
        self.assertEqual(json.loads(writer.sent)['method'],'agent.get')
        with self.assertRaises(Rejected):await client.request('client_shell.surface.set',{})
    async def test_oversized_and_partial_frame(self):
        client=HerdrClient('unused');reader=asyncio.StreamReader(limit=262145);reader.feed_data(b'x'*262146+b'\n');reader.feed_eof()
        with self.assertRaises(Rejected):await client._line(reader)

if __name__=='__main__':unittest.main()
