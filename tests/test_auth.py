import asyncio
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from dot_herdr.auth import JWTVerifier,discover_provider,fetch_json
from dot_herdr.core import Rejected
from dot_herdr.endpoint import PairingSession,build_pairing,principal_key
from dot_herdr.setup import TEMPLATE,validate_config,doctor,placeholders

ISSUER='https://issuer.example.test'
RESOURCE='https://connector.example.test/mcp'

class AuthTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.public=cls.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    def token(self,**changes):
        claims={'iss':ISSUER,'aud':RESOURCE,'sub':'account-one','client_id':'client-one','exp':int(time.time())+120,'iat':int(time.time()),'scope':'herdr:observe'}
        claims.update(changes)
        return jwt.encode(claims,self.key,algorithm='RS256',headers={'kid':'key-one'})
    def jwks(self,key=None,kid='key-one'):
        return {'keys':[{**jwt.algorithms.RSAAlgorithm.to_jwk((key or self.key).public_key(),as_dict=True),'kid':kid,'use':'sig','alg':'RS256'}]}
    async def test_jwks_unknown_key_bounded_concurrency_rotation_and_expiry(self):
        calls=[];clock=[1000];document=self.jwks()
        async def fetch(url):calls.append(url);await asyncio.sleep(0);return document
        verifier=JWTVerifier(ISSUER,RESOURCE,jwks_url=ISSUER+'/jwks',fetch=fetch,clock=lambda:clock[0])
        tokens=await asyncio.gather(*[verifier.verify_token(self.token()) for _ in range(20)])
        self.assertTrue(all(tokens));self.assertEqual(len(calls),1)
        unknown=jwt.encode({'iss':ISSUER,'aud':RESOURCE,'sub':'two','client_id':'c','exp':int(time.time())+120,'iat':int(time.time())},self.other,algorithm='RS256',headers={'kid':'key-two'})
        self.assertIsNone(await verifier.verify_token(unknown));self.assertEqual(len(calls),1)
        clock[0]+=31;document=self.jwks(self.other,'key-two')
        self.assertIsNotNone(await verifier.verify_token(unknown));self.assertEqual(len(calls),2)
        self.assertIsNone(await verifier.verify_token(self.token()))
        clock[0]+=301
        async def broken(url):raise Rejected('offline')
        verifier.fetch=broken
        self.assertIsNone(await verifier.verify_token(unknown))
    async def test_wrong_claims_keys_and_token_key_urls_denied(self):
        verifier=JWTVerifier(ISSUER,RESOURCE,self.public)
        self.assertIsNotNone(await verifier.verify_token(self.token()));self.assertIsNotNone(verifier.last_verified_at)
        for changes in ({'iss':'https://wrong.test'},{'aud':'wrong'},{'exp':1},{'iat':time.time()+300},{'sub':''},{'client_id':''},{'scope':['herdr:observe']},{'exp':float('inf')},{'iat':True}):
            with self.subTest(changes=changes):self.assertIsNone(await verifier.verify_token(self.token(**changes)))
        for header in ({'jku':'https://attacker.test/jwks'},{'jwk':{}},{'x5u':'https://attacker.test/cert'},{'crit':['custom']}):
            claims=jwt.decode(self.token(),options={'verify_signature':False})
            self.assertIsNone(await verifier.verify_token(jwt.encode(claims,self.key,algorithm='RS256',headers=header)))
        claims=jwt.decode(self.token(),options={'verify_signature':False})
        self.assertIsNone(await verifier.verify_token(jwt.encode(claims,self.other,algorithm='RS256')))
        self.assertIsNone(await verifier.verify_token('x'*16385))
    async def test_verified_request_persists_approved_scope_names_only(self):
        from dot_herdr.auth import record_verified_scopes
        from dot_herdr.connections import connection_record,save_connection,connection_path
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);root.chmod(0o700);config=root/'config.json'
            record=connection_record(config);record.update(identity=principal_key(ISSUER,'account-one'),approved_client_id='client-one');save_connection(config,record)
            verifier=JWTVerifier(ISSUER,RESOURCE,self.public,on_verified=lambda token:record_verified_scopes(config,token))
            signed=self.token(scope='herdr:observe herdr:control')
            self.assertIsNotNone(await verifier.verify_token(signed))
            self.assertEqual(connection_record(config)['verified_client_scopes']['client-one']['scopes'],['herdr:control','herdr:observe'])
            self.assertNotIn(signed,connection_path(config).read_text())
            self.assertIsNotNone(await verifier.verify_token(self.token(sub='other',scope='herdr:observe')))
            self.assertEqual(connection_record(config)['verified_client_scopes']['client-one']['scopes'],['herdr:control','herdr:observe'])
    async def test_bad_jwks_never_accepted(self):
        small=rsa.generate_private_key(public_exponent=65537,key_size=1024)
        row=self.jwks()['keys'][0]
        for document in ({'keys':[]},{'keys':[row,row]},self.jwks(small),{'keys':[{**row,'d':'secret'}]}, {'keys':[{**row,'alg':'HS256'}]}, {'keys':[{**row,'key_ops':['sign']}]}, {'keys':[{}]}):
            async def fetch(url):return document
            verifier=JWTVerifier(ISSUER,RESOURCE,jwks_url=ISSUER+'/jwks',fetch=fetch)
            self.assertIsNone(await verifier.verify_token(self.token()))
        for url in ('http://issuer.example.test/jwks','https://other.test/jwks','https://issuer.example.test:444/jwks','https://a:b@issuer.example.test/jwks'):
            with self.assertRaises(Rejected):JWTVerifier(ISSUER,RESOURCE,jwks_url=url)
    def metadata(self):
        return {'issuer':ISSUER,'authorization_endpoint':ISSUER+'/authorize','token_endpoint':ISSUER+'/token','jwks_uri':ISSUER+'/jwks','response_types_supported':['code'],'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],'scopes_supported':['herdr:observe','herdr:control'],'client_id_metadata_document_supported':True}
    async def test_discovery_recipe_and_origin_pin(self):
        document=self.metadata();calls=[]
        async def fetch(url):calls.append(url);return document
        result=await discover_provider(ISSUER,RESOURCE,fetch=fetch)
        self.assertTrue(result['metadata_compatible']);self.assertEqual(result['registration'],'cimd')
        self.assertIn('access_token_format_and_claims',result['unverified'])
        for field,value in (('issuer','https://wrong.test'),('jwks_uri','https://other.test/jwks'),('code_challenge_methods_supported',['plain']),('token_endpoint_auth_methods_supported',['client_secret_basic']),('scopes_supported',['openid']),('client_id_metadata_document_supported',False),('code_challenge_methods_supported',None),('scopes_supported',[{}])):
            document={**self.metadata(),field:value}
            with self.subTest(field=field),self.assertRaises(Rejected):await discover_provider(ISSUER,RESOURCE,fetch=fetch)
    async def test_fetch_rejects_redirect_and_large_documents(self):
        original=httpx2.AsyncClient
        for response in (httpx2.Response(302,headers={'Location':'https://other.test'}),httpx2.Response(200,content=b' '*65537),httpx2.Response(200,json=[])):
            def client(**kwargs):
                self.assertFalse(kwargs['trust_env']);self.assertFalse(kwargs['follow_redirects'])
                return original(transport=httpx2.MockTransport(lambda request:response),**kwargs)
            with patch('dot_herdr.auth.httpx2.AsyncClient',side_effect=client),self.assertRaises(Rejected):await fetch_json(ISSUER+'/jwks')
    async def test_pairing_http_is_authenticated_identity_only_and_requires_local_confirmation(self):
        pairing=PairingSession(ISSUER)
        verifier=JWTVerifier(ISSUER,RESOURCE,self.public)
        server=build_pairing(verifier,ISSUER,RESOURCE,pairing)
        tools=await server.list_tools();self.assertEqual([t.name for t in tools],['get_profile'])
        descriptor=tools[0].model_dump(by_alias=True)
        self.assertEqual(descriptor['_meta']['openai/profile'],True)
        self.assertEqual(descriptor['outputSchema']['required'],['id'])
        self.assertFalse(descriptor['outputSchema']['additionalProperties'])
        self.assertFalse(descriptor['inputSchema']['additionalProperties'])
        app=server.streamable_http_app(json_response=True,stateless_http=True,host='127.0.0.1')
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1:8000') as client:
                async def call(token=None,name='get_profile'):
                    headers={'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':'tools/call','Mcp-Name':name}
                    if token:headers['Authorization']='Bearer '+token
                    return await client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':{},'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}})
                self.assertEqual((await call()).status_code,401);self.assertEqual(pairing.candidates(),[])
                response=await call(self.token());self.assertEqual(response.status_code,200,response.text)
                result=response.json()['result'];who=principal_key(ISSUER,'account-one')
                self.assertEqual(result['structuredContent'],{'id':who})
                self.assertEqual(json.loads(result['content'][0]['text']),{'id':who})
                await call(self.token(sub='account-two'))
                self.assertEqual(len(pairing.candidates()),2);self.assertFalse(pairing.closed)
                self.assertEqual(pairing.candidates()[0]['scopes'],['herdr:observe'])
                denied=await call(self.token(),name='get_agent_state');self.assertTrue(denied.json()['result']['isError'])
                approved=pairing.confirm(who)
                self.assertEqual({k:approved[k] for k in ('issuer','subject','principal')},{'issuer':ISSUER,'subject':'account-one','principal':who})
                self.assertEqual(approved['client_id'],'client-one');self.assertEqual(approved['scopes'],['herdr:observe'])
                self.assertEqual((await call(self.token())).status_code,401)
    async def test_pairing_capacity_expiry_refusal_and_wrong_issuer(self):
        tick=[0];pairing=PairingSession(ISSUER,ttl=1,max_candidates=1,clock=lambda:tick[0])
        verifier=JWTVerifier(ISSUER,RESOURCE,self.public)
        first=await verifier.verify_token(self.token());second=await verifier.verify_token(self.token(sub='second'))
        pairing.observe(first)
        with self.assertRaisesRegex(Rejected,'limit'):pairing.observe(second)
        with self.assertRaisesRegex(Rejected,'unavailable'):pairing.confirm(principal_key(ISSUER,'second'))
        tick[0]=1
        with self.assertRaisesRegex(Rejected,'expired'):pairing.confirm(principal_key(ISSUER,'account-one'))
        self.assertEqual(pairing._candidates,{})
        pairing=PairingSession(ISSUER);first.claims['iss']='https://wrong.test'
        with self.assertRaisesRegex(Rejected,'denied'):pairing.observe(first)
        pairing.close()
        with self.assertRaises(Rejected):pairing.candidates()
    def test_config_sources_inactive_and_offline_doctor(self):
        cfg={k:copy.deepcopy(v) for k,v in TEMPLATE.items() if k!='public_key'}
        cfg.update(issuer=ISSUER,resource=RESOURCE,jwks_url=ISSUER+'/jwks')
        self.assertEqual(validate_config(cfg),cfg)
        for bad in ({**cfg,'public_key':'/tmp/key'}, {k:v for k,v in cfg.items() if k!='jwks_url'}, {**cfg,'jwks_url':'https://elsewhere.test/jwks'}):
            with self.assertRaises(Rejected):validate_config(bad)
        inactive={**cfg,'subjects':[],'session_users':[],'inactive':True};validate_config(inactive)
        with self.assertRaises(Rejected):validate_config({**cfg,'inactive':True})
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'config.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
            with patch('dot_herdr.auth.fetch_json',side_effect=AssertionError('network')):report=doctor(path)
            self.assertIn({'name':'issuer_bound_jwks','status':'configured_not_fetched'},report['checks'])

class SetupBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def test_setup_lock_refuses_second_flow_and_releases_without_inode_replacement(self):
        from dot_herdr.connections import SetupLock
        with tempfile.TemporaryDirectory() as folder:
            config=Path(folder)/'config.json'
            with SetupLock(config) as lock:
                inode=lock.path.stat().st_ino
                with self.assertRaisesRegex(Rejected,'setup_already_running'):
                    with SetupLock(config):pass
            with SetupLock(config) as lock:self.assertEqual(lock.path.stat().st_ino,inode)
            lock.path.chmod(0o644)
            with self.assertRaisesRegex(Rejected,'private_setup_lock_required'):
                with SetupLock(config):pass
    async def test_pairing_total_deadline_cancels_login_stage(self):
        from dot_herdr.onboarding import pairing_identity
        stopped=[]
        async def pending(*args,**kwargs):
            try:await asyncio.Event().wait()
            finally:stopped.append(True)
        with patch('dot_herdr.onboarding._pairing_identity',side_effect=pending):
            self.assertIsNone(await pairing_identity('/unused',{}, {},timeout=.01))
        self.assertEqual(stopped,[True])
    async def test_authenticated_discovery_missing_cli_never_claims_identity(self):
        from dot_herdr.login import request_authenticated_discovery
        with patch('dot_herdr.login.shutil.which',return_value=None):
            self.assertEqual(await request_authenticated_discovery(),{'status':'missing_codex'})
