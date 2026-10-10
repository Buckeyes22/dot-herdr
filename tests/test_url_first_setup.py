"""URL-first metadata, pending choices and route defaults use synthetic state."""
import asyncio
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx2
from dot_herdr.auth import discover_resource,discover_provider,fetch_json
from dot_herdr.core import Rejected
from dot_herdr.connections import connection_record,save_connection
from dot_herdr.onboarding import guided_setup,draft_path,pending_auth_path,save_config

URL='https://mcp.example.test/mcp'
ISSUER='https://auth.example.test'

class URLFirstTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.home_patch=patch('pathlib.Path.home',return_value=self.root);self.home_patch.start();self.addCleanup(self.home_patch.stop)
        self.path=self.root/'config.json';self.socket=self.root/'source.sock';self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.listener.bind(str(self.socket))
        self.messages=[]
    def tearDown(self):self.listener.close();self.temp.cleanup()
    def source(self):
        class Source:
            async def request(self,method,params):
                if method=='ping':return {'version':'0.9.3','protocol':22}
                if method=='agent.list':return {'agents':[{'pane_id':'pane','terminal_id':'term','agent':'codex','agent_session':None}]}
                raise AssertionError(method)
            async def agent(self,pane):return {'pane_id':'pane','terminal_id':'term','agent_session':None,'agent':'codex'}
        return Source()
    def provider(self):
        return {'issuer':ISSUER,'authorization_endpoint':ISSUER+'/authorize','token_endpoint':ISSUER+'/token','jwks_uri':ISSUER+'/jwks','response_types_supported':['code'],'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],'scopes_supported':['herdr:observe','herdr:control'],'client_id_metadata_document_supported':True}
    async def test_unavailable_resource_uses_only_valid_same_origin_authorization_server(self):
        endpoint='https://mcp.example.test:8443/mcp';origin='https://mcp.example.test:8443';calls=[]
        async def fetch(url):
            calls.append(url)
            if 'oauth-protected-resource' in url:raise Rejected('auth_discovery_unavailable')
            data=self.provider()
            for field in ('issuer','authorization_endpoint','token_endpoint','jwks_uri'):data[field]=data[field].replace(ISSUER,origin)
            return data
        result=await discover_resource(endpoint,fetch=fetch)
        self.assertEqual(result['issuers'],[origin]);self.assertEqual(result['source'],'same_origin_authorization_server')
        self.assertEqual(calls,[origin+'/.well-known/oauth-protected-resource/mcp',origin+'/.well-known/oauth-authorization-server'])
        async def wrong(url):
            data=await fetch(url)
            if 'oauth-authorization-server' in url:data['issuer']='https://other.example.test'
            return data
        with self.assertRaisesRegex(Rejected,'provider_issuer_mismatch'):await discover_resource(endpoint,fetch=wrong)
        async def oidc_only(url):
            if 'oauth-protected-resource' in url or 'oauth-authorization-server' in url:raise Rejected('auth_discovery_unavailable')
            return self.provider()
        with self.assertRaisesRegex(Rejected,'provider_discovery_unavailable'):await discover_resource(endpoint,fetch=oidc_only)
        for invalid in ({'resource':'https://other.example.test/mcp','authorization_servers':[origin]},
                        {'resource':endpoint,'authorization_servers':[]},
                        {'issuer':origin}):
            async def present(url):return invalid
            with self.assertRaises(Rejected):await discover_resource(endpoint,fetch=present)
    async def test_unavailable_resource_guided_confirmation_and_resume(self):
        endpoint='https://mcp.example.test/mcp';origin='https://mcp.example.test';answers=iter(['1','1','n','1','y']);prompts=[]
        original=httpx2.AsyncClient
        def client(**kwargs):
            def respond(request):
                if 'oauth-protected-resource' in str(request.url):return httpx2.Response(502)
                data=self.provider()
                for field in ('issuer','authorization_endpoint','token_endpoint','jwks_uri'):data[field]=data[field].replace(ISSUER,origin)
                return httpx2.Response(200,json=data)
            return original(transport=httpx2.MockTransport(respond),**kwargs)
        with patch('dot_herdr.auth.httpx2.AsyncClient',side_effect=client):
            result=await guided_setup(self.path,str(self.socket),endpoint=endpoint,route='https',prepare=False,
                                      ask=lambda prompt:(prompts.append(prompt),next(answers))[1],say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(result['stage'],'wiring');self.assertEqual(len([p for p in prompts if '[y/N]' in p and 'sign-in' in p]),1)
        self.assertTrue(any('same address' in message for message in self.messages))
        draft=json.loads(draft_path(self.path).read_text());self.assertEqual((draft['issuer'],draft['resource'],draft['jwks_url']),(origin,endpoint,origin+'/jwks'))
        with patch('dot_herdr.auth.discover_provider',return_value={'jwks_url':origin+'/jwks'}):
            resumed=await guided_setup(self.path,prepare=False,ask=lambda _:self.fail('confirmation repeated'),say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(resumed['stage'],'wiring')
    async def test_connection_errors_fallback_but_invalid_document_does_not(self):
        endpoint='https://mcp.example.test/mcp';origin='https://mcp.example.test';original=httpx2.AsyncClient
        for failure in (httpx2.ConnectError('refused'),httpx2.ReadTimeout('timed out')):
            def client(**kwargs):
                def respond(request):
                    if 'oauth-protected-resource' in str(request.url):raise failure
                    data=self.provider()
                    for field in ('issuer','authorization_endpoint','token_endpoint','jwks_uri'):data[field]=data[field].replace(ISSUER,origin)
                    return httpx2.Response(200,json=data)
                return original(transport=httpx2.MockTransport(respond),**kwargs)
            with patch('dot_herdr.auth.httpx2.AsyncClient',side_effect=client):
                self.assertEqual((await discover_resource(endpoint))['source'],'same_origin_authorization_server')
        def invalid_client(**kwargs):return original(transport=httpx2.MockTransport(lambda request:httpx2.Response(200,content=b'{invalid')),**kwargs)
        with patch('dot_herdr.auth.httpx2.AsyncClient',side_effect=invalid_client),self.assertRaisesRegex(Rejected,'invalid_auth_document'):
            await discover_resource(endpoint)
    async def test_noninteractive_fallback_waits_for_one_local_confirmation(self):
        endpoint='https://mcp.example.test/mcp';origin='https://mcp.example.test'
        cfg={'store':str(self.root/'state.sqlite'),'socket':str(self.socket),'issuer':'https://replace.invalid','resource':'https://replace.invalid/mcp',
             'public_key':str(self.root/'key.pem'),'subjects':[{'key':'agent','user_subject':'replace-with-approved-issuer-subject','owner':'operator','pane':'pane','terminal':'term'}],'session_users':[]}
        save_config(draft_path(self.path),cfg)
        record=connection_record(self.path);record.update(route='https',wiring='registered-plugin');save_connection(self.path,record)
        async def resource(url):return {'resource':endpoint,'issuers':[origin],'source':'same_origin_authorization_server'}
        async def provider(*args):return {'jwks_url':origin+'/jwks'}
        with patch('dot_herdr.auth.discover_resource',side_effect=resource),patch('dot_herdr.auth.discover_provider',side_effect=provider):
            first=await guided_setup(self.path,endpoint=endpoint,interactive=False,ask=lambda _:self.fail('noninteractive prompt'),say=self.messages.append,client_factory=lambda _:self.source())
            self.assertEqual(first['stage'],'provider');self.assertIn('confirm',first['next_action'])
            self.assertNotIn('confirmed_same_origin',json.loads(pending_auth_path(self.path).read_text()))
            prompts=[]
            second=await guided_setup(self.path,prepare=False,ask=lambda prompt:(prompts.append(prompt),'y')[1],say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(second['stage'],'wiring');self.assertEqual(len(prompts),1)
    async def test_protected_resource_exact_url_https_and_bounded_fetch(self):
        calls=[]
        async def fetch(url):calls.append(url);return {'resource':URL,'authorization_servers':[ISSUER]}
        result=await discover_resource(URL,fetch=fetch)
        self.assertEqual(result['issuers'],[ISSUER]);self.assertEqual(calls,['https://mcp.example.test/.well-known/oauth-protected-resource/mcp'])
        for value in ('http://mcp.example.test/mcp','https://mcp.example.test/mcp?x=1'):
            with self.assertRaises(Rejected):await discover_resource(value,fetch=fetch)
        async def wrong(url):return {'resource':'https://other.example.test/mcp','authorization_servers':[ISSUER]}
        with self.assertRaisesRegex(Rejected,'protected_resource_mismatch'):await discover_resource(URL,fetch=wrong)
        original=httpx2.AsyncClient
        for response in (httpx2.Response(302,headers={'Location':'https://other.example.test/mcp'}),httpx2.Response(200,content=b' '*65537)):
            def client(**kwargs):
                self.assertFalse(kwargs['follow_redirects']);self.assertFalse(kwargs['trust_env'])
                return original(transport=httpx2.MockTransport(lambda request:response),**kwargs)
            with patch('dot_herdr.auth.httpx2.AsyncClient',side_effect=client),self.assertRaises(Rejected):await fetch_json(URL)
    async def test_provider_missing_metadata_is_specific_and_oidc_fallback(self):
        for field in ('jwks_uri','scopes_supported'):
            data=self.provider();data.pop(field)
            async def fetch(url):return data
            with self.assertRaisesRegex(Rejected,'provider_'+field+'_missing'):await discover_provider(ISSUER,URL,fetch=fetch)
        urls=[]
        async def fallback(url):
            urls.append(url)
            if 'oauth-authorization-server' in url:raise Rejected('auth_discovery_unavailable')
            return self.provider()
        result=await discover_provider(ISSUER,URL,fetch=fallback)
        self.assertTrue(result['metadata_compatible']);self.assertIn('openid-configuration',urls[-1])
    async def test_pending_choice_resumes_without_repeat_or_runnable_config(self):
        answers=iter(['1','1','n','1','2',URL]);seen=[]
        async def resource(url):return {'resource':URL,'issuers':[ISSUER]}
        async def fail(*args):raise Rejected('provider_jwks_uri_missing')
        with patch('dot_herdr.auth.discover_resource',side_effect=resource),patch('dot_herdr.auth.discover_provider',side_effect=fail):
            result=await guided_setup(self.path,str(self.socket),ask=lambda prompt:(seen.append(prompt),next(answers))[1],say=self.messages.append,client_factory=lambda _:self.source())
            self.assertEqual(result['stage'],'provider');self.assertIn('jwks_uri',result['next_action'])
            self.assertEqual(json.loads(pending_auth_path(self.path).read_text())['resource'],URL)
            self.assertIn('.invalid',json.loads(draft_path(self.path).read_text())['resource'])
            result=await guided_setup(self.path,ask=lambda _:self.fail('reasked'),say=self.messages.append,client_factory=lambda _:self.source())
            self.assertEqual(result['stage'],'provider')
        self.assertEqual(connection_record(self.path)['wiring'],'registered-plugin')
        self.assertEqual(connection_record(self.path)['client_app'],'chatgpt-web')
        self.assertEqual(len([prompt for prompt in seen if prompt.startswith('Where will you use Herdr?')]),1)
    async def test_endpoint_discovers_provider_and_defaults_registered_without_cli(self):
        answers=iter(['1','1','n','1'])
        async def resource(url):return {'resource':URL,'issuers':[ISSUER]}
        async def provider(*args):return {'jwks_url':ISSUER+'/jwks'}
        with patch('dot_herdr.auth.discover_resource',side_effect=resource),patch('dot_herdr.auth.discover_provider',side_effect=provider),patch('dot_herdr.onboarding.shutil.which',return_value=None):
            result=await guided_setup(self.path,str(self.socket),endpoint=URL,route='https',prepare=False,ask=lambda _:next(answers),say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(result['stage'],'wiring')
        draft=json.loads(draft_path(self.path).read_text())
        self.assertEqual((draft['issuer'],draft['resource'],draft['jwks_url']),(ISSUER,URL,ISSUER+'/jwks'))
        self.assertEqual(connection_record(self.path)['wiring'],'registered-plugin')
    async def test_endpoint_replaces_pending_url_and_noninteractive_does_not_prompt(self):
        answers=iter(['1','1','n','1','2',''])
        result=await guided_setup(self.path,str(self.socket),endpoint=URL,ask=lambda _:next(answers),say=self.messages.append,client_factory=lambda _:self.source(),interactive=False)
        self.assertEqual(result['stage'],'access')
        result=await guided_setup(self.path,str(self.socket),ask=lambda _:next(answers),say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(result['stage'],'provider')
        newer='https://new.example.test/mcp'
        async def unavailable(url):raise Rejected('auth_discovery_unavailable')
        with patch('dot_herdr.auth.discover_resource',side_effect=unavailable):
            result=await guided_setup(self.path,endpoint=newer,ask=lambda _:self.fail('endpoint should avoid prompt'),say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(result['stage'],'provider');self.assertEqual(json.loads(pending_auth_path(self.path).read_text())['resource'],newer)
    async def test_service_manager_pid_must_own_fresh_ready_runtime(self):
        self.path.write_text('synthetic');self.path.chmod(0o600)
        cfg={'store':str(self.root/'state.sqlite'),'socket':str(self.socket),'issuer':ISSUER,'resource':URL,
             'public_key':str(self.root/'key.pem'),'subjects':[{'key':'agent','user_subject':'user','owner':'operator','pane':'pane','terminal':'term'}],'session_users':[]}
        record=connection_record(self.path);record.update(route='https',wiring='registered-plugin',client_app='desktop',app_id='asdk_app_synthetic',background=True)
        save_connection(self.path,record)
        async def fast(_):return None
        with patch('dot_herdr.onboarding.load_config',return_value=cfg),patch('dot_herdr.connections.prepare_connections',return_value={'owned':{}}),patch('dot_herdr.service.install'),patch('dot_herdr.service.manage'),patch('dot_herdr.service.service_status',return_value={'state':'active','pid':42}),patch('dot_herdr.status.runtime_observation',return_value={'state':'running','pid':43,'workers':{'observer':'running','delivery':'running'}}),patch('asyncio.sleep',side_effect=fast),patch('dot_herdr.connection_check.check_connection',side_effect=AssertionError('unready runtime reached check')):
            result=await guided_setup(self.path,ask=lambda _:self.fail('no prompt'),say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(result['stage'],'runtime')
    async def test_interrupted_account_handoff_keeps_draft_and_grants(self):
        cfg={'store':str(self.root/'state.sqlite'),'socket':str(self.socket),'issuer':ISSUER,'resource':URL,
             'jwks_url':ISSUER+'/jwks','subjects':[{'key':'agent','user_subject':'replace-with-approved-issuer-subject','owner':'operator','pane':'pane','terminal':'term','control':False}],'session_users':[]}
        save_config(draft_path(self.path),cfg)
        record=connection_record(self.path);record.update(route='https',wiring='registered-plugin');save_connection(self.path,record)
        async def provider(*args):return {'jwks_url':ISSUER+'/jwks'}
        with patch('dot_herdr.auth.discover_provider',side_effect=provider),patch('dot_herdr.onboarding.pairing_identity',return_value=None):
            first=await guided_setup(self.path,ask=lambda _:self.fail('no input before pairing'),say=self.messages.append,client_factory=lambda _:self.source())
            second=await guided_setup(self.path,ask=lambda _:self.fail('resume reasked setup input'),say=self.messages.append,client_factory=lambda _:self.source())
        with patch('dot_herdr.auth.discover_provider',side_effect=provider),patch('dot_herdr.onboarding.pairing_identity',side_effect=EOFError):
            cancelled=await guided_setup(self.path,ask=lambda _:self.fail('cancelled handoff reasked setup input'),say=self.messages.append,client_factory=lambda _:self.source())
        self.assertEqual(first['stage'],second['stage']);self.assertEqual(first['stage'],'identity')
        self.assertEqual(cancelled['stage'],'identity')
        self.assertFalse(self.path.exists());self.assertEqual(json.loads(draft_path(self.path).read_text())['subjects'],cfg['subjects'])
    async def test_replaced_source_does_not_inherit_pending_grants(self):
        cfg={'store':str(self.root/'state.sqlite'),'socket':str(self.socket),'issuer':ISSUER,'resource':URL,
             'public_key':str(self.root/'key.pem'),'subjects':[{'key':'agent','user_subject':'replace-with-approved-issuer-subject','owner':'operator','pane':'pane','terminal':'term'}],'session_users':[]}
        save_config(draft_path(self.path),cfg);before=draft_path(self.path).read_bytes()
        class Changed:
            async def request(self,method,params):return {'version':'0.9.3','protocol':22}
            async def agent(self,pane):return {'pane_id':'pane','terminal_id':'replacement','agent_session':None}
        result=await guided_setup(self.path,ask=lambda _:self.fail('changed source cannot prompt for approval'),say=self.messages.append,client_factory=lambda _:Changed())
        self.assertEqual(result['stage'],'source');self.assertEqual(draft_path(self.path).read_bytes(),before);self.assertFalse(self.path.exists())
