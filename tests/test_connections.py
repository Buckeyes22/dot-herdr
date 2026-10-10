"""Desktop/tunnel onboarding must preserve existing settings and real authentication."""
import asyncio
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
import zipfile
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dot_herdr.connections import NAME, LOCAL_URL, prepare_connections, prepare_plugin, register_mcp, open_link
from dot_herdr.core import Rejected, Store
from dot_herdr.endpoint import JWTVerifier, build
from dot_herdr.skills import SKILL_FILES
from dot_herdr.tunnel import prepare_tunnel, profile_settings, runtime_command, check_tunnel, install_client


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='herdr desktop ')
        self.home = Path(self.temp.name)
        self.cfg = {'resource': 'https://connector.example.test/mcp'}
    def tearDown(self):
        self.temp.cleanup()
    def prepare(self, **kwargs):
        kwargs.setdefault('wiring','plugin-http')
        return prepare_connections(self.cfg, home=self.home, codex_home=self.home/'.codex', launch=False, say=lambda _:None, **kwargs)
    def test_default_settings_plugin_creates_no_duplicate_connections(self):
        result=prepare_connections(self.cfg,home=self.home,codex_home=self.home/'.codex',launch=False,say=lambda _:None)
        self.assertEqual(result['registration']['status'],'settings_plugin')
        self.assertEqual(result['local_package'],{'status':'not_prepared','reason':'plugin_created_in_chatgpt_settings'})
        self.assertFalse((self.home/'.codex').exists())

    def test_preserves_marketplace_comments_other_mcp_tables_and_reruns(self):
        marketplace = self.home/'.agents/plugins/marketplace.json'
        marketplace.parent.mkdir(parents=True)
        original = {'name':'existing','interface':{'displayName':'My plugins'},'extra':{'keep':True},
                    'plugins':[{'name':'other','source':'./other','custom':'retained'}]}
        marketplace.write_text(json.dumps(original))
        config = self.home/'.codex/config.toml'
        config.parent.mkdir(parents=True)
        prefix = '# Keep this comment\nmodel = "gpt-6-sol"\n[mcp_servers.other]\nurl = "https://other.example.test"\n'
        config.write_text(prefix)
        result = self.prepare()
        standalone=self.prepare(wiring='standalone',endpoint=LOCAL_URL)
        new = json.loads(marketplace.read_text())
        self.assertEqual(new['plugins'][0], original['plugins'][0])
        self.assertEqual(new['interface'], original['interface'])
        self.assertEqual(new['extra'], original['extra'])
        self.assertTrue(config.read_text().startswith(prefix))
        self.assertEqual(tomllib.loads(config.read_text())['mcp_servers'][NAME]['url'],LOCAL_URL)
        self.assertEqual(tomllib.loads(config.read_text())['mcp_servers'][NAME]['oauth_resource'],self.cfg['resource'])
        self.assertEqual(config.with_name('config.toml.dot-herdr-backup').read_text(),prefix)
        self.assertEqual(json.loads(marketplace.with_name('marketplace.json.dot-herdr-backup').read_text()),original)
        before = (marketplace.read_bytes(),config.read_bytes())
        self.assertEqual(self.prepare(wiring='standalone',endpoint=LOCAL_URL)['registration']['status'],'existing')
        self.assertEqual((marketplace.read_bytes(),config.read_bytes()),before)
        self.assertIn('%20',result['link'])
        plugin = Path(result['plugin'])
        self.assertEqual(json.loads((plugin/'mcp.json').read_text())['mcpServers'][NAME]['type'],'streamable-http')
        for name in SKILL_FILES:
            self.assertEqual((plugin/'skills/herdr-connector'/name).read_bytes(),files('dot_herdr').joinpath('skills','herdr-connector',name).read_bytes())
        self.assertEqual(json.loads((plugin/'plugin.json').read_text())['license'],'MIT')
        self.assertFalse((plugin/'config.json').exists())
    def test_conflicting_mcp_and_malformed_toml_leave_plugin_and_config_untouched(self):
        config = self.home/'.codex/config.toml'; config.parent.mkdir()
        for body in ('bad = [','[mcp_servers."'+NAME+'"]\nurl="https://other.example.test"\n',
                     '[mcp_servers."'+NAME+'"]\nurl="'+LOCAL_URL+'"\nenabled=false\n'):
            config.write_text(body)
            with self.assertRaises(Rejected):self.prepare(wiring='standalone',endpoint=LOCAL_URL)
            self.assertEqual(config.read_text(),body)
            self.assertFalse((self.home/'.agents').exists())
    def test_unowned_plugin_conflicting_marketplace_and_symlinks_are_rejected(self):
        plugin=self.home/'.codex/plugins'/NAME;plugin.mkdir(parents=True)
        (plugin/'private').write_text('leave me')
        with self.assertRaisesRegex(Rejected,'unowned_plugin'):self.prepare()
        self.assertFalse((self.home/'.codex/config.toml').exists())
        (plugin/'private').unlink();plugin.rmdir()
        real=self.home/'real';real.mkdir();plugin.symlink_to(real,target_is_directory=True)
        with self.assertRaisesRegex(Rejected,'symlink'):self.prepare()
        self.assertEqual(list(real.iterdir()),[])
        plugin.unlink()
        marketplace=self.home/'.agents/plugins/marketplace.json';marketplace.parent.mkdir(parents=True)
        body=json.dumps({'name':'mine','plugins':[{'name':NAME,'source':'./other'}]})
        marketplace.write_text(body)
        with self.assertRaisesRegex(Rejected,'existing_marketplace_entry'):self.prepare()
        self.assertEqual(marketplace.read_text(),body)
        self.assertFalse((self.home/'.codex/config.toml').exists())
    def test_registered_connection_mapping_and_explicit_endpoint(self):
        result=self.prepare(wiring='registered-plugin',app_id='plugin_asdk_app_fixture',endpoint=self.cfg['resource'])
        self.assertFalse((self.home/'.codex/config.toml').exists())
        self.assertFalse((Path(result['plugin'])/'mcp.json').exists())
        plugin=Path(result['plugin'])
        self.assertEqual(json.loads((plugin/'.app.json').read_text()),{'apps':{'herdr':{'id':'asdk_app_fixture'}}})
        self.assertEqual(json.loads((plugin/'plugin.json').read_text())['extensions']['com.openai']['apps'],'./.app.json')
        with self.assertRaisesRegex(Rejected,'retain_registered_server_id'):self.prepare(endpoint=self.cfg['resource'])
        with self.assertRaisesRegex(Rejected,'endpoint_must'):self.prepare(endpoint='http://192.168.1.1/mcp')  # release-check: allow private-ip (rejection test vector)
    def test_no_register_and_failed_desktop_handoff_remain_reviewable(self):
        result=self.prepare(register=False)
        self.assertFalse((self.home/'.codex/config.toml').exists())
        self.assertEqual(result['registration']['status'],'plugin_http_prepared')
        with patch('dot_herdr.connections.shutil.which',return_value=None):self.assertFalse(open_link(result['link']))
        with patch('dot_herdr.connections.shutil.which',return_value='/xdg-open'),patch('dot_herdr.connections.subprocess.run',side_effect=subprocess.TimeoutExpired('open',10)):
            self.assertFalse(open_link(result['link']))
    def test_pending_resource_prepares_plugin_and_registers_when_completed(self):
        self.cfg['resource']='https://connector.example.invalid/mcp'
        first=self.prepare(wiring='standalone')
        self.assertEqual(first['registration']['status'],'pending_resource')
        self.assertNotIn('plugin',first)
        self.assertFalse((self.home/'.codex/config.toml').exists())
        self.cfg['resource']='https://connector.example.test/mcp'
        second=self.prepare(wiring='standalone')
        self.assertEqual(second['registration']['status'],'registered')
        self.assertEqual(tomllib.loads((self.home/'.codex/config.toml').read_text())['mcp_servers'][NAME]['oauth_resource'],self.cfg['resource'])

    def test_configured_client_uses_nested_oauth_and_preserves_existing_settings(self):
        home=self.home/'.codex'
        result=register_mcp(home,resource=self.cfg['resource'],client_id='public-client')
        config=Path(result['config']);body=config.read_bytes()
        server=tomllib.loads(body.decode())['mcp_servers'][NAME]
        self.assertEqual(server['oauth'],{'client_id':'public-client'})
        self.assertNotIn('oauth_client_id',server)
        self.assertEqual(register_mcp(home,resource=self.cfg['resource'],client_id='public-client')['status'],'existing')
        self.assertEqual(config.read_bytes(),body)
        with self.assertRaisesRegex(Rejected,'existing_mcp_entry'):
            register_mcp(home,resource=self.cfg['resource'],client_id='different-client')
        self.assertEqual(config.read_bytes(),body)
        for oauth in ('oauth = "malformed"\n','oauth_client_id = "public-client"\n'):
            config.write_text('[mcp_servers."'+NAME+'"]\nurl = '+json.dumps(LOCAL_URL)+'\n'+oauth)
            with self.assertRaisesRegex(Rejected,'existing_mcp_entry'):
                register_mcp(home,resource=self.cfg['resource'],client_id='public-client')

    def test_cleanup_continues_after_malformed_marketplace_and_changed_plugin_files(self):
        from dot_herdr.connections import remove_owned_connections
        for marketplace_body in ('{','[]','{"plugins":null}','{"plugins":{}}'):
            with self.subTest(marketplace_body=marketplace_body),tempfile.TemporaryDirectory() as folder:
                home=Path(folder);codex_home=home/'.codex'
                result=register_mcp(codex_home,resource=self.cfg['resource'],client_id='public-client')
                plugin=codex_home/'plugins'/NAME;plugin.mkdir(parents=True)
                good=plugin/'owned';good.write_bytes(b'owned')
                changed=plugin/'changed';changed.write_bytes(b'changed')
                target=plugin/'symlink';target.symlink_to(good)
                marketplace=home/'.agents/plugins/marketplace.json';marketplace.parent.mkdir(parents=True);marketplace.write_text(marketplace_body)
                record={'endpoint':LOCAL_URL,'owned':{'plugin_files':{str(target):'untrusted',str(changed):'old-digest',str(good):hashlib.sha256(b'owned').hexdigest()},
                    'marketplace':str(marketplace),'marketplace_entry':{'name':NAME},'standalone_config':result['config'],'standalone_block':result['owned_table']}}
                with patch('dot_herdr.connections.connection_record',return_value=record),patch('dot_herdr.connections.Path.home',return_value=home),\
                     patch.dict(os.environ,{'CODEX_HOME':str(codex_home)}),patch('dot_herdr.setup.load_config',return_value={**self.cfg,'oauth_client_id':'public-client'}):
                    cleaned=remove_owned_connections(home/'config.json')
                self.assertFalse(good.exists())
                self.assertEqual(changed.read_bytes(),b'changed');self.assertTrue(target.is_symlink())
                self.assertEqual(marketplace.read_text(),marketplace_body)
                self.assertNotIn(NAME,tomllib.loads(Path(result['config']).read_text()).get('mcp_servers',{}))
                self.assertIn(str(marketplace)+'#'+NAME,cleaned['preserved'])
                self.assertIn(result['config']+'#'+NAME,cleaned['removed'])

    def test_cleanup_retains_extended_oauth_table(self):
        from dot_herdr.connections import remove_owned_connections
        home=self.home/'.codex';result=register_mcp(home,resource=self.cfg['resource'],client_id='public-client')
        config=Path(result['config'])
        with config.open('a') as stream:stream.write('callback_url = "http://127.0.0.1/callback/custom"\n')
        body=config.read_bytes()
        record={'endpoint':LOCAL_URL,'owned':{'standalone_config':str(config),'standalone_block':result['owned_table']}}
        with patch('dot_herdr.connections.connection_record',return_value=record),patch.dict(os.environ,{'CODEX_HOME':str(home)}),\
             patch('dot_herdr.setup.load_config',return_value={**self.cfg,'oauth_client_id':'public-client'}):
            cleaned=remove_owned_connections(self.home/'config.json')
        self.assertEqual(config.read_bytes(),body)
        self.assertEqual(cleaned,{'removed':[],'preserved':[str(config)+'#'+NAME]})


class TunnelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.config=self.root/'config.json'
        self.binary=self.root/'tunnel-client';self.binary.write_bytes(b'fixture executable');self.binary.chmod(0o700)
    def tearDown(self):self.temp.cleanup()
    def init(self,args,**kwargs):
        self.assertNotIn('CONTROL_PLANE_API_KEY',kwargs['env'])
        folder=Path(args[args.index('--profile-dir')+1]);profile=folder/'dot-herdr.yaml'
        profile.write_text('control_plane:\n  api_key: "env:CONTROL_PLANE_API_KEY"\nmcp:\n  url: "'+LOCAL_URL+'"\n')
        return subprocess.CompletedProcess(args,0,b'local only',b'')
    def prepare(self,id='tunnel_fixture'):
        with patch('dot_herdr.tunnel.shutil.which',return_value=str(self.binary)),patch('dot_herdr.tunnel.subprocess.run',side_effect=self.init):
            return prepare_tunnel(self.config,id,say=lambda _:None)
    def test_profile_is_private_resumable_and_has_no_secret(self):
        with patch.dict(os.environ,{'CONTROL_PLANE_API_KEY':'secret-fixture-key'}):value=self.prepare()
        self.assertEqual(profile_settings(self.config),value)
        root=self.root/'tunnel'
        self.assertEqual(root.stat().st_mode&0o777,0o700)
        self.assertEqual((root/'profiles/dot-herdr.yaml').stat().st_mode&0o777,0o600)
        self.assertEqual((root/'settings.json').stat().st_mode&0o777,0o600)
        for path in root.rglob('*'):
            if path.is_file():self.assertNotIn(b'secret-fixture-key',path.read_bytes())
        with patch('dot_herdr.tunnel.subprocess.run') as called:
            self.assertEqual(prepare_tunnel(self.config,'tunnel_fixture',say=lambda _:None),value)
            called.assert_not_called()
        with self.assertRaisesRegex(Rejected,'existing_id_mismatch'):prepare_tunnel(self.config,'tunnel_other')
        (root/'profiles/dot-herdr.yaml').write_text('changed')
        with self.assertRaisesRegex(Rejected,'profile_changed'):profile_settings(self.config)
    def test_runtime_keeps_key_in_environment_and_drops_unsafe_overrides(self):
        self.prepare()
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(Rejected,'api_key_required'):runtime_command(self.config)
        with patch.dict(os.environ,{'CONTROL_PLANE_API_KEY':'secret-fixture-key','OPENAI_ADMIN_KEY':'admin-secret',
                                    'CONTROL_PLANE_BASE_URL':'https://evil.example.test','MCP_EXTRA_HEADERS':'Authorization: secret','LOG_HTTP_RAW_UNSAFE':'true'}):
            args,env=runtime_command(self.config,cfg={'issuer':'https://auth.example.test/oauth','resource':'https://connector.example.test/mcp'})
        self.assertNotIn('secret-fixture-key',' '.join(args))
        self.assertEqual(env['CONTROL_PLANE_API_KEY'],'secret-fixture-key')
        for key in ('OPENAI_ADMIN_KEY','CONTROL_PLANE_BASE_URL','MCP_EXTRA_HEADERS','LOG_HTTP_RAW_UNSAFE'):self.assertNotIn(key,env)
        self.assertIn('https://api.openai.com',args)
        self.assertIn('https://auth.example.test',args);self.assertIn('https://connector.example.test',args)
        self.binary.write_bytes(b'replaced')
        with self.assertRaisesRegex(Rejected,'client_changed'):profile_settings(self.config)
    def test_doctor_redacts_external_output_and_times_out(self):
        self.prepare();messages=[]
        with patch.dict(os.environ,{'CONTROL_PLANE_API_KEY':'key'}),patch('dot_herdr.tunnel.subprocess.run',return_value=subprocess.CompletedProcess([],1,b'secret',b'private token')):
            with self.assertRaisesRegex(Rejected,'doctor_failed'):check_tunnel(self.config,say=messages.append)
        self.assertEqual(messages,[])
        with patch.dict(os.environ,{'CONTROL_PLANE_API_KEY':'key'}),patch('dot_herdr.tunnel.subprocess.run',side_effect=subprocess.TimeoutExpired('doctor',45)):
            with self.assertRaisesRegex(Rejected,'doctor_failed'):check_tunnel(self.config)
    def test_download_verifies_bundle_digest_and_extracts_only_fixed_entries(self):
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w') as archive:
            for name in ('tunnel-client','LICENSE','NOTICE','tunnel-client-v0.0.16-linux-amd64-licenses.txt','tunnel-client-v0.0.16-linux-amd64.spdx.json','../../outside'):
                archive.writestr(name,b'fixture data')
        bundle=raw.getvalue()
        asset={'name':'tunnel-client-v0.0.16-linux-amd64.zip',
               'browser_download_url':'https://github.com/openai/tunnel-client/releases/download/v0.0.16/tunnel-client-v0.0.16-linux-amd64.zip',
               'digest':'sha256:'+hashlib.sha256(bundle).hexdigest()}
        release=json.dumps({'tag_name':'v0.0.16','assets':[asset]}).encode()
        with patch('dot_herdr.tunnel.platform.system',return_value='Linux'),patch('dot_herdr.tunnel.platform.machine',return_value='x86_64'),patch('dot_herdr.tunnel.fetch',side_effect=[release,bundle]):
            binary,receipt=install_client(self.root)
        self.assertEqual(binary.read_bytes(),b'fixture data')
        self.assertEqual(receipt['release'],'v0.0.16')
        self.assertFalse((self.root/'outside').exists())
        self.assertTrue((binary.parent/'NOTICE').exists())
        with patch('dot_herdr.tunnel.platform.system',return_value='Linux'),patch('dot_herdr.tunnel.platform.machine',return_value='x86_64'),patch('dot_herdr.tunnel.fetch',side_effect=[release,b'changed']):
            with self.assertRaisesRegex(Rejected,'digest_mismatch'):install_client(self.root)
    def test_missing_client_does_not_claim_readiness_or_create_profile(self):
        with patch('dot_herdr.tunnel.shutil.which',return_value=None):
            with self.assertRaisesRegex(Rejected,'client_missing'):prepare_tunnel(self.config,'tunnel_fixture',download=False)
        self.assertFalse((self.root/'tunnel/settings.json').exists())


class HTTPBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_loopback_discovery_preserves_audience_auth_and_host_origin_checks(self):
        issuer='https://auth.example.test';resource='https://connector.example.test/mcp'
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public=key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()
        with tempfile.TemporaryDirectory() as temp:
            store=Store(Path(temp)/'state.sqlite')
            server=build(store,None,None,JWTVerifier(issuer,resource,public),issuer,resource)
            app=server.streamable_http_app(json_response=True,stateless_http=True)
            try:
                async with app.router.lifespan_context(app):
                    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url=LOCAL_URL.removesuffix('/mcp'),trust_env=False) as client:
                        headers={'Accept':'application/json, text/event-stream','Mcp-Method':'server/discover','MCP-Protocol-Version':'2026-07-28'}
                        body={'jsonrpc':'2.0','id':1,'method':'server/discover','params':{'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}}
                        response=await client.post('/mcp',headers=headers,json=body)
                        self.assertEqual(response.status_code,401)
                        self.assertIn('http://127.0.0.1:8000/.well-known/oauth-protected-resource/mcp',response.headers['www-authenticate'])
                        metadata=await client.get('/.well-known/oauth-protected-resource/mcp')
                        self.assertEqual(metadata.status_code,200)
                        self.assertEqual(metadata.json()['resource'],resource)
                        self.assertEqual(metadata.json()['scopes_supported'],['herdr:observe','herdr:control'])
                        claims={'iss':issuer,'aud':resource,'sub':'fixture','client_id':'fixture','iat':int(time.time()),'exp':int(time.time())+60,'scope':'herdr:observe'}
                        for aud,expected in ((resource,200),(LOCAL_URL,401)):
                            token=jwt.encode({**claims,'aud':aud},key,algorithm='RS256')
                            self.assertEqual((await client.post('/mcp',headers={**headers,'Authorization':'Bearer '+token},json=body)).status_code,expected)
                        for host,origin,expected in (('evil.example.test',None,421),('connector.example.test','https://evil.example.test',403),('connector.example.test',None,401)):
                            extra={'Host':host}
                            if origin:extra['Origin']=origin
                            response=await client.post('/mcp',headers={**headers,**extra},json=body)
                            self.assertEqual(response.status_code,expected)
                            if host=='connector.example.test' and origin is None:self.assertIn(resource.removesuffix('/mcp'),response.headers['www-authenticate'])
                        self.assertEqual((await client.get('/.well-known/oauth-protected-resource/mcp',headers={'Host':'evil.example.test'})).status_code,421)
            finally:store.close()


class SupervisionTests(unittest.TestCase):
    def run_case(self, exit_code=None, launch_error=False, login=False):
        """Exercise CLI lifecycle without dialing Herdr, OpenAI or a real listener."""
        from dot_herdr.cli import main
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);root.chmod(0o700)
            state=root/'state';state.mkdir(mode=0o700)
            key=root/'public.pem'
            key.write_bytes(rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
            config=root/'config.json';config.write_text(json.dumps({'store':str(state/'connector.sqlite'),'socket':str(root/'unused.sock'),
                'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(key),'subjects':[],'session_users':['fixture']}));config.chmod(0o600)
            class Child:
                def __init__(self):self.returncode=exit_code;self.terminated=False;self.stopped=asyncio.Event()
                async def wait(self):
                    if self.returncode is None:await self.stopped.wait()
                    return self.returncode
                def terminate(self):self.terminated=True;self.returncode=0;self.stopped.set()
                def kill(self):self.returncode=-9;self.stopped.set()
            children=[]
            async def launch(*args,**kwargs):
                if launch_error:raise OSError('fixture failure')
                child=Child();children.append(child);return child
            class HTTP:
                def __init__(self,*args):self.started=False;self.should_exit=False
                async def serve(self):
                    self.started=True
                    for _ in range(25):
                        if self.should_exit:return
                        await asyncio.sleep(0.01)
            async def idle(*args):await asyncio.Event().wait()
            login_events=[]
            async def sign_in(*args):
                login_events.append('started')
                try:await asyncio.Event().wait()
                finally:login_events.append('cancelled')
            with patch.object(sys,'argv',['dot-herdr','run','--config',str(config),'--tunnel',*(['--login'] if login else [])]),\
                 patch('dot_herdr.tunnel.runtime_command',return_value=(['fixture-client'],{})),\
                 patch('uvicorn.Server',HTTP),patch('dot_herdr.herdr.watch',idle),\
                 patch('dot_herdr.login.login_mcp',side_effect=sign_in),\
                 patch('asyncio.create_subprocess_exec',side_effect=launch):
                if exit_code is not None or launch_error:
                    with self.assertRaises(SystemExit) as error:main()
                    self.assertEqual(error.exception.code,2 if launch_error else 1)
                else:main()
            # Store closes even when the tunnel fails; a fresh owner can acquire it.
            store=Store(state/'connector.sqlite');store.close()
            if login:self.assertEqual(login_events,['started','cancelled'])
            return children
    def test_foreground_http_shutdown_terminates_tunnel_and_releases_store(self):
        children=self.run_case();self.assertEqual(len(children),1);self.assertTrue(children[0].terminated)
    def test_failed_tunnel_and_launch_failure_stop_http_and_release_store(self):
        children=self.run_case(exit_code=42);self.assertEqual(children[0].returncode,42)
        self.assertEqual(self.run_case(launch_error=True),[])
    def test_shutdown_cancels_unfinished_sign_in_and_tunnel(self):
        children=self.run_case(login=True);self.assertTrue(children[0].terminated)
