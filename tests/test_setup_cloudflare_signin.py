"""Guided setup uses isolated files, fake Cloudflare and an offline public origin."""
import asyncio
import contextlib
import io
import json
import logging
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx2
from dot_herdr import onboarding, cloudflare, signin, runtime
from dot_herdr.connections import connection_record
from dot_herdr.core import Rejected
from tests.test_cloudflare import FakeCloudflare

OWNER_INPUT='owner-entry-for-offline-fixture'
API_INPUT='api-entry-for-offline-fixture'
HOST='herdr.example.com'
ORIGIN='https://'+HOST

class Source:
    async def request(self,method,params):
        if method=='ping':return {'version':'0.9.3','protocol':22}
        if method=='agent.list':return {'agents':[]}
        raise AssertionError(method)

class GuidedCloudflareTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.path=self.root/'config.json';self.sock_path=self.root/'source.sock'
        self.sock=socket.socket(socket.AF_UNIX);self.sock.bind(str(self.sock_path));self.addCleanup(self.sock.close)
        self.binary=self.root/'cloudflared';self.marker=self.root/'child-started'
        self.binary.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "cloudflared version fixture"; exit 0; fi\necho "$@" > '+str(self.marker)+'\nexec sleep 60\n');self.binary.chmod(0o700)
        self.fake=FakeCloudflare();self.messages=[];self.prompts=[];self.hidden=[]
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ,{'HOME':str(self.root),'XDG_CONFIG_HOME':str(self.root/'cfg'),'XDG_DATA_HOME':str(self.root/'data'),'XDG_STATE_HOME':str(self.root/'state'),'XDG_CACHE_HOME':str(self.root/'cache'),'XDG_RUNTIME_DIR':str(self.root/'run')}))
        self.stack.enter_context(patch('pathlib.Path.home',return_value=self.root))
        detect=cloudflare.detect_cloudflared
        self.stack.enter_context(patch('dot_herdr.cloudflare.detect_cloudflared',side_effect=lambda:detect(which=lambda _:str(self.binary))))
        self.stack.enter_context(patch('dot_herdr.cloudflare.CloudflareAPI',side_effect=lambda token:self.fake.api(token)))
        self.stack.enter_context(patch('sys.stdin.isatty',return_value=True))
        self.stack.enter_context(patch('dot_herdr.onboarding.clear_pending_input'))
        self.stack.enter_context(patch('dot_herdr.cli.getpass.getpass',side_effect=lambda prompt:(self.hidden.append(prompt) or API_INPUT)))
        self.stack.enter_context(patch('dot_herdr.auth.discover_resource',side_effect=AssertionError('built-in must skip discovery')))
        self.stack.enter_context(patch('socket.create_connection',side_effect=AssertionError('network forbidden')))
        self.output=io.StringIO();self.stack.enter_context(contextlib.redirect_stdout(self.output));self.stack.enter_context(contextlib.redirect_stderr(self.output))
        self.log_output=io.StringIO();handler=logging.StreamHandler(self.log_output);logging.getLogger().addHandler(handler);self.addCleanup(logging.getLogger().removeHandler,handler)
    async def setup_flow(self,answers=(),**kwargs):
        values=iter(answers)
        def ask(prompt):
            self.prompts.append(prompt)
            try:return next(values)
            except StopIteration:raise EOFError from None
        kwargs.setdefault('hidden_prompt',lambda prompt:(self.hidden.append(prompt) or OWNER_INPUT))
        return await onboarding.guided_setup(self.path,str(self.sock_path),ask=ask,say=self.messages.append,client_factory=lambda _:Source(),**kwargs)
    def cfg(self):return json.loads(onboarding.draft_path(self.path).read_text())
    def assert_private(self):
        transcript='\n'.join(self.messages+self.prompts+self.hidden)+self.output.getvalue()+self.log_output.getvalue()
        for secret in (OWNER_INPUT,API_INPUT):
            self.assertNotIn(secret,transcript)
            for file in self.root.rglob('*'):
                if file.is_file():self.assertNotIn(secret.encode(),file.read_bytes(),str(file))
        file=signin.signin_root(self.path)/'password.json'
        self.assertEqual(file.stat().st_mode&0o777,0o600)
        data=json.loads(file.read_text());self.assertEqual(data['n'],16384);self.assertIn('hash',data);self.assertIn('salt',data)
        self.assertTrue(signin.verify_password(signin.signin_root(self.path),OWNER_INPUT))
    async def test_route_password_mismatch_exposure_before_provider_and_resume(self):
        entries=iter([OWNER_INPUT,'different-entry',OWNER_INPUT,OWNER_INPUT])
        def hidden(prompt):
            self.hidden.append(prompt)
            self.assertTrue(self.fake.dns,'exposure must precede password/provider')
            return next(entries)
        result=await self.setup_flow(['3','1','4',HOST,'1',''],prepare=False,hidden_prompt=hidden)
        self.assertEqual(result['stage'],'wiring')
        cfg=self.cfg();self.assertEqual((cfg['signin'],cfg['issuer'],cfg['jwks_url']),('builtin',ORIGIN,ORIGIN+'/.well-known/jwks.json'))
        record=connection_record(self.path);self.assertEqual(record['route'],'https');self.assertEqual(record['exposure']['mode'],'api')
        route=next(p for p in self.prompts if p.startswith('Route:'));self.assertLess(route.index('Cloudflare'),route.index('HTTPS URL'));self.assertIn('Secure MCP Tunnel',route);self.assertIn('advanced loopback',route)
        self.assertIn('cloudflared version fixture','\n'.join(self.messages));self.assertEqual(len([p for p in self.hidden if 'sign-in password' in p]),4)
        self.assertIn('Passwords do not match; try again.',self.messages)
        before=onboarding.draft_path(self.path).read_bytes();old_prompts=len(self.prompts);old_hidden=len(self.hidden)
        self.assertEqual((await self.setup_flow(prepare=False))['stage'],'wiring')
        self.assertEqual(len(self.prompts),old_prompts);self.assertEqual(len(self.hidden),old_hidden);self.assertEqual(onboarding.draft_path(self.path).read_bytes(),before)
        self.assert_private()
    async def test_missing_binary_hostname_and_credentials_resume(self):
        with patch('dot_herdr.cloudflare.detect_cloudflared',return_value=None):
            result=await self.setup_flow(['3','1','4',''])
            self.assertEqual(result['stage'],'cloudflare-hostname')
            result=await self.setup_flow([HOST]);self.assertEqual(result['stage'],'cloudflare-install');self.assertIn(cloudflare.INSTALL_DOCS,result['next_action'])
        result=await self.setup_flow(['']);self.assertEqual(result['stage'],'cloudflare-credentials')
        result=await self.setup_flow(['1',''],prepare=False);self.assertEqual(result['stage'],'wiring');self.assert_private()
    async def test_failed_exposure_and_password_resume_without_reasking_choices(self):
        self.fake.fail_dns=True
        result=await self.setup_flow(['3','1','4',HOST,'1']);self.assertEqual(result['stage'],'cloudflare-exposure')
        self.fake.fail_dns=False
        result=await self.setup_flow([''],hidden_prompt=lambda _:(_ for _ in ()).throw(EOFError()))
        self.assertEqual(result['stage'],'signin-password')
        self.assertEqual((await self.setup_flow(prepare=False))['stage'],'wiring');self.assert_private()
    async def test_provider_choice_noninteractive_pause_then_resume(self):
        result=await self.setup_flow(['3','1','4',HOST,'1',''],prepare=False)
        self.assertEqual(result['stage'],'wiring')
        # A completed choice is retained even for noninteractive resumes.
        self.assertEqual((await self.setup_flow(interactive=False,prepare=False))['stage'],'wiring');self.assert_private()
    async def test_login_fallback_notice_precedes_login_and_external_provider(self):
        events=[]
        original=cloudflare.expose_login
        tid='00000000-0000-0000-0000-000000000001'
        def run(arguments,**kwargs):
            if arguments[1:]==['tunnel','login']:
                notices=[m for m in self.messages if 'cert.pem' in m]
                self.assertEqual(len(notices),1);events.append('login')
                directory=self.root/'.cloudflared';directory.mkdir(mode=0o700)
                (directory/'cert.pem').write_text('offline certificate')
            if arguments[1:3]==['tunnel','create']:
                creds=self.root/'.cloudflared'/(tid+'.json');creds.write_text('{}');creds.chmod(0o600)
                return __import__('subprocess').CompletedProcess(arguments,0,stdout=tid,stderr='')
            return __import__('subprocess').CompletedProcess(arguments,0,stdout='',stderr='')
        def login(*args,**kwargs):return original(*args,run=run,home=self.root,**kwargs)
        async def resource(url):events.append('discovery');return {'issuers':['https://auth.example.com']}
        async def provider(*args):return {'jwks_url':'https://auth.example.com/jwks'}
        with patch('dot_herdr.cloudflare.expose_login',side_effect=login),patch('dot_herdr.auth.discover_resource',side_effect=resource),patch('dot_herdr.auth.discover_provider',side_effect=provider):
            result=await self.setup_flow(['3','1','4',HOST,'2','2'],prepare=False)
        self.assertEqual(result['stage'],'wiring');self.assertEqual(events,['login','discovery']);self.assertNotIn('signin',self.cfg());self.assertEqual(self.hidden,[])
    async def test_activation_password_absent_from_config_records_and_output(self):
        identity={'subject':'opaque-owner','principal':'opaque-profile','verified_at':1,'expires_at':9999999999}
        with patch('dot_herdr.onboarding.pairing_identity',return_value=identity),patch('dot_herdr.connections.prepare_connections',return_value={'owned':{}}),patch('dot_herdr.status.runtime_observation',return_value={'state':'running'}),patch('dot_herdr.connection_check.check_connection',return_value={'status':'pending','phase':'test_target'}),patch('dot_herdr.maintenance.refresh_inventory'):
            await self.setup_flow(['3','1','4',HOST,'1','','n'])
        self.assertTrue(self.path.exists());self.assertFalse(onboarding.draft_path(self.path).exists())
        self.assertFalse(self.path.with_name(self.path.name+'.setup-choices.json').exists())
        active=json.loads(self.path.read_text());self.assertEqual(active['signin'],'builtin');self.assertEqual(active['session_users'],['opaque-owner']);self.assert_private()
        before=self.path.read_bytes();count=len(self.hidden)
        with patch('dot_herdr.connections.prepare_connections',return_value={'owned':{}}),patch('dot_herdr.status.runtime_observation',return_value={'state':'running'}),patch('dot_herdr.connection_check.check_connection',return_value={'status':'pending','phase':'test_target'}),patch('dot_herdr.maintenance.refresh_inventory'):
            await self.setup_flow()
        self.assertEqual(self.path.read_bytes(),before);self.assertEqual(len(self.hidden),count);self.assert_private()
    async def test_local_port_and_pending_provider_choice_resume(self):
        cfg={'store':str(self.root/'state/connector.sqlite'),'socket':str(self.sock_path),'issuer':'https://replace.invalid','resource':'https://replace.invalid/mcp','public_key':str(self.root/'key.pem'),'subjects':[],'session_users':['replace-with-approved-issuer-subject'],'local_port':8123}
        onboarding.save_config(onboarding.draft_path(self.path),cfg)
        from dot_herdr.connections import save_connection
        record=connection_record(self.path);record.update(route='https',wiring='registered-plugin',client_app='chatgpt-web');save_connection(self.path,record)
        onboarding._setup_choices(self.path,cloudflare=True,hostname=HOST,mode='api')
        exposure=await cloudflare.expose_api(self.path,HOST,8123,API_INPUT,api=self.fake.api(API_INPUT),cloudflared=str(self.binary))
        record['exposure']=exposure;save_connection(self.path,record)
        self.assertEqual((await self.setup_flow(interactive=False))['stage'],'provider-choice')
        self.assertEqual((await self.setup_flow([''],prepare=False))['stage'],'wiring')
        ingress=next(body['config']['ingress'] for method,url,body in self.fake.calls if url.endswith('/configurations'))
        self.assertEqual(ingress[0]['service'],'http://127.0.0.1:8123');self.assert_private()
    async def test_status_and_existing_cloudflare_migration_preserve_url_provider(self):
        await self.setup_flow(['3','1','4',HOST,'1',''],prepare=False)
        onboarding.save_config(self.path,self.cfg())
        from dot_herdr.status import status
        from dot_herdr.connections import migrate_connection
        before=self.path.read_bytes();record=connection_record(self.path)
        with patch('dot_herdr.status.runtime_observation',return_value={'state':'stopped'}),patch('dot_herdr.status.port_in_use',return_value=False),patch('dot_herdr.service.service_status',return_value={'state':'inactive'}):
            observed=await status(self.path)
        self.assertEqual(observed['observations']['route']['url'],ORIGIN+'/mcp')
        with patch('dot_herdr.cli.expose_cloudflare',return_value=record['exposure']):
            result=migrate_connection(self.path,'https','registered-plugin',to='cloudflare',say=self.messages.append)
        self.assertEqual(result['saved_route'],'https');self.assertEqual(result['endpoint'],ORIGIN+'/mcp');self.assertEqual(self.path.read_bytes(),before);self.assertEqual(connection_record(self.path)['exposure'],record['exposure']);self.assert_private()
    async def test_existing_https_builtin_option(self):
        with patch('dot_herdr.auth.discover_resource',side_effect=Rejected('auth_discovery_unavailable')):
            result=await self.setup_flow(['3','1','2',ORIGIN+'/mcp','1'],prepare=False)
        self.assertEqual(result['stage'],'wiring');self.assertEqual(self.cfg()['signin'],'builtin');self.assertNotIn('exposure',connection_record(self.path));self.assert_private()
    async def test_https_advertised_provider_has_no_new_prompt(self):
        calls=[]
        async def resource(url):calls.append(('resource',url));return {'issuers':['https://auth.example.com']}
        async def provider(*args):calls.append(('provider',args));return {'jwks_url':'https://auth.example.com/jwks'}
        with patch('dot_herdr.auth.discover_resource',side_effect=resource),patch('dot_herdr.auth.discover_provider',side_effect=provider):
            result=await self.setup_flow(['3','1','2',ORIGIN+'/mcp'],prepare=False)
        self.assertEqual(result['stage'],'wiring');self.assertNotIn('signin',self.cfg())
        self.assertEqual(calls,[('resource',ORIGIN+'/mcp'),('provider',('https://auth.example.com',ORIGIN+'/mcp',None))])
        url_index=next(i for i,p in enumerate(self.prompts) if p.startswith('Existing HTTPS'))
        self.assertEqual(self.prompts[url_index+1:],[])
        self.assertIn('This URL already advertises a sign-in service; using it. (The built-in sign-in service is for URLs without one.)',self.messages)

    async def test_advertised_provider_keeps_existing_background_choice(self):
        identity={'subject':'opaque-owner','principal':'opaque-profile','verified_at':1,'expires_at':9999999999}
        with patch('dot_herdr.auth.discover_resource',return_value={'issuers':['https://auth.example.com']}),patch('dot_herdr.auth.discover_provider',return_value={'jwks_url':'https://auth.example.com/jwks'}),patch('dot_herdr.onboarding.pairing_identity',return_value=identity),patch('dot_herdr.connections.prepare_connections',return_value={'owned':{}}),patch('dot_herdr.status.runtime_observation',return_value={'state':'running'}),patch('dot_herdr.connection_check.check_connection',return_value={'status':'pending','phase':'test_target'}),patch('dot_herdr.maintenance.refresh_inventory'):
            await self.setup_flow(['3','1','2',ORIGIN+'/mcp','n'])
        self.assertNotIn('signin',json.loads(self.path.read_text()))
        self.assertFalse(connection_record(self.path)['background'])
        self.assertFalse(self.path.with_name(self.path.name+'.setup-choices.json').exists())

    async def test_https_provider_choice_interruption_resumes_saved_url(self):
        with patch('dot_herdr.auth.discover_resource',side_effect=Rejected('auth_discovery_unavailable')):
            result=await self.setup_flow(['3','1','2',ORIGIN+'/mcp'],prepare=False)
            self.assertEqual(result['stage'],'provider')
            result=await self.setup_flow(interactive=False,prepare=False)
            self.assertEqual(result['stage'],'provider')
            count=len(self.prompts)
            result=await self.setup_flow(['1'],prepare=False)
        self.assertEqual(result['stage'],'wiring')
        self.assertFalse(any(p.startswith('Existing HTTPS') for p in self.prompts[count:]))
        self.assertEqual(self.cfg()['signin'],'builtin');self.assert_private()

    async def test_unadvertised_choice_two_enter_and_eof_keep_existing_pending_message(self):
        message="Could not reach this URL's resource details. In this setup terminal, resume when the URL or sign-in service answers."
        with patch('dot_herdr.auth.discover_resource',side_effect=Rejected('auth_discovery_unavailable')):
            for answers in (['3','1','2',ORIGIN+'/mcp','2'],[''],[]):
                result=await self.setup_flow(answers,prepare=False)
                self.assertEqual(result,{'status':'pending','stage':'provider','next_action':message})
        self.assertEqual(self.hidden,[])
        self.assertNotIn('signin',self.cfg())
        self.assertFalse((signin.signin_root(self.path)/'password.json').exists())
        self.assertIn("1) Use the built-in sign-in service (recommended if you don't already run one); 2) Stop and fix the advertised sign-in service",self.messages)

    async def test_advertised_provider_repair_keeps_existing_pending_flow(self):
        with patch('dot_herdr.auth.discover_resource',return_value={'issuers':['https://auth.example.com']}),patch('dot_herdr.auth.discover_provider',side_effect=Rejected('provider_jwks_uri_missing')):
            result=await self.setup_flow(['3','1','2',ORIGIN+'/mcp'],prepare=False)
            self.assertEqual(result['stage'],'provider')
            self.assertIn('jwks_uri',result['next_action'])
            self.assertEqual((await self.setup_flow(prepare=False))['stage'],'provider')
        self.assertEqual(self.hidden,[])
        self.assertFalse(any(p.startswith('Sign-in service [1/2') for p in self.prompts))

    async def test_same_origin_provider_retains_confirmation_without_new_choice(self):
        with patch('dot_herdr.auth.discover_resource',return_value={'issuers':[ORIGIN],'source':'same_origin_authorization_server'}),patch('dot_herdr.auth.discover_provider',return_value={'jwks_url':ORIGIN+'/.well-known/jwks.json'}):
            result=await self.setup_flow(['3','1','2',ORIGIN+'/mcp','y'],prepare=False)
        self.assertEqual(result['stage'],'wiring');self.assertNotIn('signin',self.cfg())
        self.assertTrue(self.prompts[-1].startswith('Use this same-address sign-in service'))
        self.assertFalse(any(p.startswith('Sign-in service [1/2') for p in self.prompts))
        self.assertIn('This URL already advertises a sign-in service; using it. (The built-in sign-in service is for URLs without one.)',self.messages)

    async def test_https_builtin_keeps_original_arguments_without_recursion(self):
        original=onboarding._guided_setup
        with patch('dot_herdr.auth.discover_resource',side_effect=Rejected('auth_discovery_unavailable')),patch('dot_herdr.onboarding._guided_setup',wraps=original) as guided:
            result=await self.setup_flow(['3',ORIGIN+'/mcp','1'],route='https',wiring='standalone',client_app='desktop',oauth_client_id='offline-client',prepare=False,launch=False,login=False,download=False)
        self.assertEqual(guided.await_count,1);self.assertEqual(result['stage'],'wiring')
        self.assertEqual(self.cfg()['oauth_client_id'],'offline-client')
        record=connection_record(self.path);self.assertEqual((record['route'],record['wiring'],record['client_app']),('https','standalone','desktop'))
        self.assert_private()

    async def test_fake_end_to_end_pairing_launch_public_confirmation_and_note_order(self):
        class Server:
            def __init__(self,config):self.started=False;self.should_exit=False
            async def serve(self):
                self.started=True
                while not self.should_exit:await asyncio.sleep(.01)
        original=onboarding.pairing_identity;calls=[]
        async def pairing(*args,**kwargs):return await original(*args,timeout=2,**kwargs)
        async def fetch(url):
            for _ in range(50):
                if self.marker.exists():break
                await asyncio.sleep(.01)
            self.assertTrue(self.marker.exists());calls.append(url)
            cfg=self.cfg();app=signin.app(signin.signin_root(self.path),issuer=cfg['issuer'],resource=cfg['resource'])
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url=ORIGIN) as client:
                response=await client.get(url);self.assertEqual(response.status_code,200);return response.json()
        with patch('uvicorn.Server',Server),patch('dot_herdr.status.port_in_use',return_value=False),patch('dot_herdr.onboarding.pairing_identity',side_effect=pairing):
            result=await self.setup_flow(['3','1','4',HOST,'1',''],public_fetch=fetch)
        self.assertEqual(result['stage'],'identity');self.assertEqual(calls,[ORIGIN+'/.well-known/oauth-authorization-server',ORIGIN+'/.well-known/jwks.json'])
        self.assertIn('run --token-file',self.marker.read_text())
        note=next(i for i,m in enumerate(self.messages) if "bot protection blocks" in m)
        plugin=next(i for i,m in enumerate(self.messages) if 'Add custom MCP server' in m)
        self.assertLess(note,plugin);self.assert_private()
    async def test_public_failure_is_specific_and_resumable(self):
        class Server:
            def __init__(self,config):self.started=False;self.should_exit=False
            async def serve(self):
                self.started=True
                while not self.should_exit:await asyncio.sleep(.01)
        async def fetch(url):raise Rejected('cloudflare_bot_protection')
        with patch('uvicorn.Server',Server),patch('dot_herdr.status.port_in_use',return_value=False):
            result=await self.setup_flow(['3','1','4',HOST,'1',''],public_fetch=fetch)
        self.assertEqual(result['stage'],'public-provider');self.assertIn('bot protection',result['next_action']);self.assertFalse(any('Add custom MCP server' in m for m in self.messages));self.assert_private()
        original=onboarding.pairing_identity
        async def pairing(*args,**kwargs):return await original(*args,timeout=1,**kwargs)
        async def good_fetch(url):
            app=signin.app(signin.signin_root(self.path),issuer=ORIGIN,resource=ORIGIN+'/mcp')
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url=ORIGIN) as client:return (await client.get(url)).json()
        with patch('uvicorn.Server',Server),patch('dot_herdr.status.port_in_use',return_value=False),patch('dot_herdr.onboarding.pairing_identity',side_effect=pairing):
            resumed=await self.setup_flow(public_fetch=good_fetch)
        self.assertEqual(resumed['stage'],'identity');self.assertTrue(any('Add custom MCP server' in m for m in self.messages));self.assert_private()


class PublicConfirmationTests(unittest.IsolatedAsyncioTestCase):
    async def test_wrong_public_issuer_and_timeout_transport(self):
        cfg={'issuer':ORIGIN,'resource':ORIGIN+'/mcp','jwks_url':ORIGIN+'/.well-known/jwks.json'}
        async def wrong(url):return {'issuer':'https://other.example.com'}
        with self.assertRaisesRegex(Rejected,'provider_issuer_mismatch'):await onboarding._confirm_public_signin(cfg,wrong)
        original=httpx2.AsyncClient
        def fail(request):raise httpx2.ReadTimeout('offline timeout')
        with patch('httpx2.AsyncClient',side_effect=lambda **kwargs:original(transport=httpx2.MockTransport(fail),**kwargs)),self.assertRaisesRegex(Rejected,'cloudflare_timeout'):await onboarding._public_signin_fetch(ORIGIN+'/metadata')
    async def test_status_advice_and_bounded_fetch(self):
        original=httpx2.AsyncClient
        for status,reason in ((403,'cloudflare_bot_protection'),(530,'cloudflare_tunnel_down'),(524,'cloudflare_timeout')):
            def client(**kwargs):
                self.assertFalse(kwargs['follow_redirects']);self.assertFalse(kwargs['trust_env'])
                return original(transport=httpx2.MockTransport(lambda _:httpx2.Response(status,headers={'cf-mitigated':'challenge'} if status==403 else {})),**kwargs)
            with patch('httpx2.AsyncClient',side_effect=client),self.assertRaisesRegex(Rejected,reason):await onboarding._public_signin_fetch(ORIGIN+'/metadata')
            self.assertTrue(onboarding._public_signin_advice(reason,ORIGIN+'/mcp'))
        for response in (httpx2.Response(302),httpx2.Response(200,content=b' '*65537)):
            with patch('httpx2.AsyncClient',side_effect=lambda **kwargs:original(transport=httpx2.MockTransport(lambda _:response),**kwargs)),self.assertRaises(Rejected):await onboarding._public_signin_fetch(ORIGIN+'/metadata')
    async def test_public_issuer_keys_mismatch_and_empty_jwks(self):
        cfg={'issuer':ORIGIN,'resource':ORIGIN+'/mcp','jwks_url':ORIGIN+'/.well-known/jwks.json'}
        with patch('dot_herdr.auth.discover_provider',return_value={'issuer':ORIGIN,'jwks_url':ORIGIN+'/other'}),self.assertRaisesRegex(Rejected,'provider_key_origin_changed'):await onboarding._confirm_public_signin(cfg)
        with patch('dot_herdr.auth.discover_provider',return_value=cfg),self.assertRaisesRegex(Rejected,'invalid_provider_jwks'):await onboarding._confirm_public_signin(cfg,fetch=unittest.mock.AsyncMock(return_value={'keys':[]}))

    async def test_retry_recovers_after_two_tunnel_failures(self):
        cfg={'issuer':ORIGIN,'resource':ORIGIN+'/mcp','jwks_url':ORIGIN+'/.well-known/jwks.json'}
        now=[0.0];calls=[]
        async def sleep(seconds):now[0]+=seconds
        with tempfile.TemporaryDirectory() as directory:
            app=signin.app(Path(directory),issuer=ORIGIN,resource=cfg['resource'])
            async def fetch(url):
                calls.append(url)
                if len(calls)<=2:raise Rejected('cloudflare_tunnel_down')
                async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url=ORIGIN) as client:return (await client.get(url)).json()
            await onboarding._confirm_public_signin(cfg,fetch,clock=lambda:now[0],sleep=sleep)
        self.assertEqual(len(calls),4);self.assertAlmostEqual(now[0],3)

    async def test_unrecovered_retry_bounded_by_startup_pairing_and_child(self):
        cfg={'issuer':ORIGIN,'resource':ORIGIN+'/mcp','jwks_url':ORIGIN+'/.well-known/jwks.json'}
        for reason in ('cloudflare_tunnel_down','cloudflare_timeout'):
            for deadline,expected in ((1000,60),(2.5,2.5)):
                now=[0.0];calls=[]
                async def sleep(seconds):now[0]+=seconds
                async def fetch(url):calls.append(url);raise Rejected(reason)
                with self.assertRaisesRegex(Rejected,reason):await onboarding._confirm_public_signin(cfg,fetch,deadline=deadline,clock=lambda:now[0],sleep=sleep)
                self.assertAlmostEqual(now[0],expected);self.assertLessEqual(len(calls),10)
        child=__import__('types').SimpleNamespace(returncode=None);now=[0.0];calls=[]
        async def sleep(seconds):now[0]+=seconds;child.returncode=1
        async def fetch(url):calls.append(url);raise Rejected('cloudflare_tunnel_down')
        with self.assertRaisesRegex(Rejected,'cloudflare_tunnel_down'):await onboarding._confirm_public_signin(cfg,fetch,child=child,clock=lambda:now[0],sleep=sleep)
        self.assertEqual(len(calls),1);self.assertLessEqual(now[0],.2)

    async def test_bot_protection_and_mismatch_never_retry(self):
        cfg={'issuer':ORIGIN,'resource':ORIGIN+'/mcp','jwks_url':ORIGIN+'/.well-known/jwks.json'}
        for reason in ('cloudflare_bot_protection','provider_issuer_mismatch'):
            async def fetch(url):raise Rejected(reason)
            sleep=unittest.mock.AsyncMock()
            with self.assertRaisesRegex(Rejected,reason):await onboarding._confirm_public_signin(cfg,fetch,sleep=sleep)
            sleep.assert_not_awaited()

    async def test_classification_matches_live_status_and_exact_advice(self):
        from dot_herdr.login import _cloudflare_advice
        original=httpx2.AsyncClient
        for code,headers,body,reason in (
            (403,{},b'Forbidden','auth_discovery_unavailable'),
            (503,{},b'unavailable','auth_discovery_unavailable'),
            (403,{'server':'cloudflare'},b'Just a moment','cloudflare_bot_protection'),
            (403,{'cf-mitigated':'challenge'},b'','cloudflare_bot_protection'),
            (530,{},b'','cloudflare_tunnel_down'),
            (502,{},b'error code: 1033','cloudflare_tunnel_down'),
            (524,{},b'','cloudflare_timeout'),
        ):
            def client(**kwargs):
                self.assertFalse(kwargs['trust_env']);self.assertFalse(kwargs['follow_redirects']);self.assertEqual(kwargs['timeout'],5)
                return original(transport=httpx2.MockTransport(lambda _:httpx2.Response(code,headers=headers,content=body)),**kwargs)
            with patch('httpx2.AsyncClient',side_effect=client),self.assertRaisesRegex(Rejected,reason):await onboarding._public_signin_fetch(ORIGIN+'/metadata')
            advice=_cloudflare_advice(code,headers,body,ORIGIN+'/mcp')
            if advice:self.assertEqual(onboarding._public_signin_advice(reason,ORIGIN+'/mcp'),advice)
        for response in (httpx2.Response(200,headers={'content-encoding':'gzip'}),httpx2.Response(530,content=b'x'*65537)):
            with patch('httpx2.AsyncClient',side_effect=lambda **kwargs:original(transport=httpx2.MockTransport(lambda _:response),**kwargs)),self.assertRaises(Rejected):await onboarding._public_signin_fetch(ORIGIN+'/metadata')

if __name__=='__main__':unittest.main()
