"""Offline CLI contracts: hidden credentials, exposure ownership and migration."""
import asyncio
import getpass
import io
import json
import logging
import os
from pathlib import Path
import pty
import select
import stat
import subprocess
import sys
import tempfile
import termios
import threading
import unittest
import warnings
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from unittest.mock import patch

import httpx2
from dot_herdr import cli, cloudflare, signin, maintenance
from dot_herdr.connections import connection_record, save_connection, migrate_connection
from dot_herdr.core import Rejected
from tests.test_cloudflare import FakeCloudflare

OWNER_INPUT = 'offline-owner-entry'
API_INPUT = 'offline-api-entry'
TUNNEL_ID = '12345678-1234-1234-1234-123456789abc'


class FakeAPI:
    def __init__(self):
        self.tunnels=[]; self.dns=[]; self.calls=[]

    def handle(self, req):
        self.calls.append((req.method, req.url.path))
        body=json.loads(req.content) if req.content else {}
        path=req.url.path
        value={}
        if path=='/zones':
            value=[{'id':'zone','name':'example.test','account':{'id':'account'}}]
        elif path=='/accounts/account/cfd_tunnels':value=self.tunnels
        elif path=='/accounts/account/cfd_tunnel':
            value={'id':TUNNEL_ID,'name':body['name']}; self.tunnels.append(value)
        elif path.endswith('/token'):value='offline-run-entry'
        elif path=='/zones/zone/dns_records':
            if req.method=='GET':value=self.dns
            else:
                value={'id':'dns',**body};self.dns.append(value)
        elif '/dns_records/' in path:self.dns=[]
        elif path.endswith('/connections'):pass
        elif path=='/accounts/account/cfd_tunnel/'+TUNNEL_ID:
            if req.method=='DELETE':self.tunnels=[]
            else:value=self.tunnels[0]
        elif path.endswith('/configurations'):pass
        else:raise AssertionError(path)
        return httpx2.Response(200,json={'success':True,'result':value})


class HiddenInputTests(unittest.TestCase):
    def prompt_trial(self, fail_terminal, api_token=False):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)
        synthetic = 'synthetic-owner-password'
        wake = threading.Event()
        stop = threading.Event()
        class Prompts(io.StringIO):
            def write(self, value):
                result = super().write(value)
                if value.endswith(': '):
                    wake.set()
                return result
        prompt_output = Prompts()
        echoed = bytearray()
        def provide_input():
            for _ in range(1 if api_token else 2):
                if not wake.wait(2) or stop.is_set():
                    return
                wake.clear()
                os.write(master, (synthetic + '\n').encode())
                if select.select([master], [], [], 1)[0]:
                    echoed.extend(os.read(master, 4096))
        writer = threading.Thread(target=provide_input)
        writer.start()
        accepted = None
        rejection = None
        with os.fdopen(os.dup(slave), 'r') as terminal:
            original_getattr = getpass.termios.tcgetattr
            def attributes(fd):
                if fail_terminal:
                    raise termios.error('synthetic terminal failure')
                return original_getattr(fd)
            with patch.object(sys, 'stdin', terminal), patch.object(sys, 'stderr', prompt_output), \
                    patch.object(getpass.os, 'open', side_effect=OSError('synthetic no controlling tty')), \
                    patch.object(getpass.termios, 'tcgetattr', side_effect=attributes):
                try:
                    if api_token:
                        from dot_herdr.cli import cloudflare_token
                        accepted = cloudflare_token()
                    else:
                        accepted = signin.ask_new_password(getpass=getpass.getpass, say=lambda _: None)
                except Rejected as exc:
                    rejection = str(exc)
        stop.set()
        wake.set()
        writer.join(3)
        if fail_terminal:
            self.assertEqual(rejection, 'hidden_input_unavailable_use_a_real_terminal')
            self.assertEqual(prompt_output.getvalue(), '')
            self.assertIsNone(accepted)
            self.assertNotIn(synthetic.encode(), echoed)
        return accepted, synthetic, echoed

    def test_control_normal_password_prompt_disables_echo(self):
        accepted, synthetic, echoed = self.prompt_trial(False)
        self.assertEqual(accepted, synthetic)
        self.assertNotIn(synthetic.encode(), echoed)

    def test_password_prompt_refuses_echoing_getpass_fallback(self):
        accepted, synthetic, echoed = self.prompt_trial(True)
        self.assertFalse(accepted is not None and synthetic.encode() in echoed,
                         'password accepted after getpass fallback echoed it to the terminal')

    def test_api_token_prompt_refuses_echoing_getpass_fallback(self):
        accepted, synthetic, echoed = self.prompt_trial(True, api_token=True)
        self.assertFalse(accepted is not None and synthetic.encode() in echoed,
                         'API token accepted after getpass fallback echoed it to the terminal')


class PasswordPromptTests(unittest.TestCase):
    def test_retries_and_three_round_limit_without_echo(self):
        for entries, explanation in [(['short']*2,'at least 8'),(['x'*1025]*2,'at most 1024'),([OWNER_INPUT,'different-entry'],'do not match')]:
            with self.subTest(explanation=explanation):
                hidden=[]; messages=[]; answers=iter(entries+[OWNER_INPUT]*2)
                def get(prompt):hidden.append(prompt);return next(answers)
                self.assertEqual(signin.ask_new_password(getpass=get,say=messages.append),OWNER_INPUT)
                self.assertEqual(len(hidden),4);self.assertIn(explanation,messages[0])
                self.assertNotIn(OWNER_INPUT,repr(messages)+repr(hidden))
        hidden=[]
        with self.assertRaisesRegex(Rejected,'password_not_set'):
            signin.ask_new_password(getpass=lambda p:(hidden.append(p) or 'short'),say=lambda _:None)
        self.assertEqual(len(hidden),6)

    def test_second_entry_refuses_fallback_and_restores_warning_filters(self):
        before = list(warnings.filters)
        calls = []
        def hidden(prompt):
            calls.append(prompt)
            if len(calls) == 2:
                warnings.warn('synthetic terminal failure', getpass.GetPassWarning)
                self.fail('fallback read reached')
            return OWNER_INPUT
        with self.assertRaisesRegex(Rejected, '^hidden_input_unavailable_use_a_real_terminal$'):
            signin.ask_new_password(getpass=hidden, say=self.fail)
        self.assertEqual(len(calls), 2)
        self.assertEqual(warnings.filters, before)

    def test_boundary_lengths_are_accepted(self):
        for size in (8,1024):
            entry='x'*size
            self.assertEqual(signin.ask_new_password(getpass=lambda _:entry,say=self.fail),entry)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.home.chmod(0o700)
        self.config=self.home/'cfg'/'config.json';self.config.parent.mkdir(mode=0o700)
        self.cfg={'store':str(self.config.parent/'state'/'connector.sqlite'), 'socket':str(self.home/'source.sock'),
                  'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp',
                  'public_key':str(self.home/'public.pem'),'subjects':[],'inactive':True,'session_users':[]}
        self.fake=FakeAPI()
        self.binary=self.home/'bin'/'cloudflared';self.binary.parent.mkdir()
        self.binary.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo "cloudflared offline-test"; exit; fi\nmkdir -p "$HOME/.cloudflared"\ncase "$2" in\nlist) cat "$HOME/.cloudflared/owned.json";;\nlogin) touch "$HOME/.cloudflared/cert.pem";;\ncreate) echo "{}" > "$HOME/.cloudflared/12345678-1234-1234-1234-123456789abc.json"; printf \'[{"id":"12345678-1234-1234-1234-123456789abc","name":"%s"}]\' "$3" > "$HOME/.cloudflared/owned.json"; echo "Created tunnel 12345678-1234-1234-1234-123456789abc";;\nesac\n');self.binary.chmod(0o700)
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('dot_herdr.onboarding.clear_pending_input'))
        self.stack.enter_context(patch.dict(os.environ,{'HOME':str(self.home),'XDG_CONFIG_HOME':str(self.home/'cfg'),'CODEX_HOME':str(self.home/'.codex'),'PATH':str(self.binary.parent)+':'+os.environ['PATH']}))
        api_class=cloudflare.CloudflareAPI
        self.stack.enter_context(patch.object(cloudflare,'CloudflareAPI',side_effect=lambda token:api_class(token,transport=httpx2.MockTransport(self.fake.handle),base_url='https://offline.example.test')))
        self.messages=[]
        class Capture(logging.Handler):
            def emit(handler, record):self.messages.append(record.getMessage())
        handler=Capture();logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler,handler)

    def configure(self,route='https'):
        self.config.write_text(json.dumps(self.cfg));self.config.chmod(0o600)
        record=connection_record(self.config);record.update(route=route,wiring='registered-plugin',endpoint=self.cfg['resource'],owned={})
        save_connection(self.config,record)

    def run_cli(self,*args,terminal=False,entry=API_INPUT):
        out=io.StringIO();err=io.StringIO();prompts=[]
        with patch.object(sys,'argv',['dot-herdr',*args,'--config',str(self.config)]),patch('sys.stdin.isatty',return_value=terminal),patch.object(cli.getpass,'getpass',side_effect=lambda p:(prompts.append(p) or entry)),redirect_stdout(out),redirect_stderr(err):
            try:cli.main();code=0
            except SystemExit as ex:code=ex.code
        result=(code,out.getvalue(),err.getvalue(),prompts)
        if entry:self.assertNotIn(entry,repr(result)+repr(self.messages))
        return result

    def assert_secret_absent(self,entry):
        for path in self.home.rglob('*'):
            if path.is_file():self.assertNotIn(entry.encode(),path.read_bytes(),str(path))
        self.assertNotIn(entry,repr(self.messages))

    def token_file(self):
        # The input credential is outside the HOME/config tree under inspection.
        temp=tempfile.NamedTemporaryFile();self.addCleanup(temp.close)
        temp.write(('  '+API_INPUT+'\n').encode());temp.flush()
        return Path(temp.name)

    def test_signin_requires_terminal_and_no_setup_then_changes_password(self):
        code,_,err,_=self.run_cli('signin','set-password',entry=OWNER_INPUT)
        self.assertEqual(code,2);self.assertIn('signin_password_requires_terminal',err)
        self.assertFalse((self.config.parent/'signin').exists())
        code,out,_,prompts=self.run_cli('signin','set-password',terminal=True,entry=OWNER_INPUT)
        self.assertEqual(code,0);self.assertEqual(out,'Sign-in password set.\n');self.assertEqual(len(prompts),2)
        self.assertFalse(self.config.exists())
        root=signin.signin_root(self.config)
        self.assertTrue(signin.verify_password(root,OWNER_INPUT))
        self.assertEqual(stat.S_IMODE((root/'password.json').stat().st_mode),0o600)
        self.assertEqual(set(json.loads((root/'password.json').read_text())),{'salt','n','r','p','dklen','hash'})
        self.configure();before=self.config.read_bytes();receipt=connection_record(self.config)
        self.assertEqual(self.run_cli('signin','set-password',terminal=True,entry=OWNER_INPUT)[0],0)
        self.assertEqual(self.config.read_bytes(),before);self.assertEqual(connection_record(self.config),receipt)
        self.assert_secret_absent(OWNER_INPUT)

    def test_api_prompt_create_rerun_and_remove_without_secrets(self):
        self.configure();before=self.config.read_bytes()
        code,out,err,prompts=self.run_cli('expose','cloudflare',terminal=True)
        self.assertEqual(code,0,err);self.assertIn(str(self.binary),out);self.assertIn('cloudflared offline-test',out)
        for permission in ('Account › Cloudflare Tunnel › Edit','Zone › DNS › Edit','Zone › Zone › Read'):self.assertIn(permission,prompts[0])
        self.assertIn('dot-herdr service restart',out);self.assertIn('dot-herdr run',out)
        first=connection_record(self.config);self.assertEqual(first['exposure']['hostname'],'connector.example.test')
        self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        self.assertEqual(len(self.fake.tunnels),1)
        self.assertEqual((self.config.parent/'cloudflare'/'tunnel.token').stat().st_mode & 0o777,0o600)
        self.assertEqual(self.run_cli('expose','cloudflare','--remove',terminal=True)[0],0)
        self.assertNotIn('exposure',connection_record(self.config));self.assertFalse(self.fake.tunnels);self.assertFalse(self.fake.dns)
        self.assertEqual(self.config.read_bytes(),before);self.assert_secret_absent(API_INPUT)

    def test_token_file_stripped_create_and_remove_and_default_port(self):
        self.configure();token=self.token_file()
        calls=[];original=cloudflare.expose_api
        async def capture(config,hostname,port,entry,**kwargs):
            self.assertEqual(entry,API_INPUT);calls.append((hostname,port));return await original(config,hostname,port,entry,**kwargs)
        with patch.object(cloudflare,'expose_api',side_effect=capture):
            self.assertEqual(self.run_cli('expose','cloudflare','--token-file',str(token))[0],0)
        self.assertEqual(calls,[('connector.example.test',8000)])
        self.assert_secret_absent(API_INPUT)
        self.assertEqual(self.run_cli('expose','cloudflare','--remove','--token-file',str(token))[0],0)
        self.assert_secret_absent(API_INPUT)

    def test_token_file_validation_and_no_terminal_prompt(self):
        self.configure()
        self.assertIn('cloudflare_api_token_requires_terminal_or_token_file',self.run_cli('expose','cloudflare')[2])
        outside=self.token_file();link=self.home/'link';link.symlink_to(outside)
        huge=self.home/'huge';huge.write_bytes(b'x'*4097)
        fifo=self.home/'fifo';os.mkfifo(fifo)
        for path in (link,huge,fifo,self.home,self.home/'absent'):
            self.assertIn('cloudflare_token_file_requires_owned_regular_file_at_most_4kib',self.run_cli('expose','cloudflare','--token-file',str(path))[2])
        with patch.object(cli.os,'getuid',return_value=os.getuid()+1):
            with self.assertRaises(Rejected):cli.cloudflare_token(outside)
        self.assertFalse(self.fake.calls)

    def test_detect_missing_and_loaded_config_required(self):
        self.assertNotEqual(self.run_cli('expose','cloudflare')[0],0)
        self.configure()
        with patch.object(cloudflare,'detect_cloudflared',return_value=None):
            code,out,err,_=self.run_cli('expose','cloudflare')
        self.assertEqual(code,2);self.assertIn(cloudflare.INSTALL_DOCS,out)
        self.assertIn('cloudflared_not_found_install_it_see_docs_reachability',err);self.assertFalse(self.fake.calls)

    def test_login_fake_executable_notice_before_login_and_remove(self):
        self.configure();self.cfg['local_port']=8123;self.config.write_text(json.dumps(self.cfg))
        original=cloudflare.expose_login
        def run(args,**kwargs):
            if args[-1]=='login':self.assertIn('account-wide certificate',sys.stdout.getvalue())
            return subprocess.run(args,**kwargs)
        def expose(*args,**kwargs):return original(*args,run=run,**kwargs)
        with patch.object(cloudflare,'expose_login',side_effect=expose):
            code,out,err,_=self.run_cli('expose','cloudflare','--login')
        self.assertEqual(code,0,err);self.assertIn('account-wide certificate',out)
        cert=self.home/'.cloudflared'/'cert.pem';self.assertTrue(cert.exists())
        journal=cloudflare.Journal(self.config).read();config_path=Path(journal['config'])
        rules=json.loads(config_path.read_text())['ingress'];self.assertEqual(rules[0]['service'],'http://127.0.0.1:8123')
        self.assertEqual(rules[0]['originRequest']['httpHostHeader'],'connector.example.test')
        self.assertEqual(config_path.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.run_cli('expose','cloudflare','--remove','--token-file',str(self.token_file()))[0],0)
        self.assertTrue(cert.exists());self.assertFalse(config_path.exists());self.assertNotIn('exposure',connection_record(self.config))

    def test_login_remove_optional_token_refuses_echoing_fallback(self):
        self.configure()
        self.assertEqual(self.run_cli('expose','cloudflare','--login')[0],0)
        journal = cloudflare.Journal(self.config).read()
        receipt = connection_record(self.config)
        def unavailable(prompt):
            warnings.warn('synthetic terminal failure', getpass.GetPassWarning)
            self.fail('fallback read reached')
        with patch('sys.stdin.isatty',return_value=True), patch.object(cli.getpass,'getpass',side_effect=unavailable), patch.object(cloudflare,'remove') as remover:
            with self.assertRaisesRegex(Rejected,'^hidden_input_unavailable_use_a_real_terminal$'):
                cli.expose_cloudflare(self.config,remove=True,say=lambda _:None)
        remover.assert_not_called()
        self.assertEqual(cloudflare.Journal(self.config).read(),journal)
        self.assertEqual(connection_record(self.config),receipt)

    def test_api_remove_without_cloudflared_on_path(self):
        self.configure()
        self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        # Isolate this CLI contract from the cloudflared binary check.
        module=cloudflare
        async def remove(config, *, token, cloudflared, say):
            self.assertIsNone(cloudflared);self.assertEqual(token,API_INPUT)
            api=module.CloudflareAPI(token)
            journal=module.Journal(config);value=journal.read()
            await api.delete_dns(value['zone']['id'],value['dns']['id'])
            await api.delete_tunnel(value['account'],value['tunnel']['id'])
            Path(value['token_file']).unlink();journal.remove()
        with patch.dict(os.environ,{'PATH':str(self.home/'empty-path')}),patch.object(cloudflare,'remove',side_effect=remove) as remover:
            code,out,err,_=self.run_cli('expose','cloudflare','--remove',terminal=True)
        self.assertEqual(code,0,err);remover.assert_called_once()
        self.assertIn('cloudflared was not found',out);self.assertNotIn(cloudflare.INSTALL_DOCS,out)
        self.assertFalse(self.fake.dns);self.assertFalse(self.fake.tunnels)
        self.assertNotIn('exposure',connection_record(self.config));self.assert_secret_absent(API_INPUT)

    def test_login_remove_without_cloudflared_requires_install(self):
        self.configure()
        self.assertEqual(self.run_cli('expose','cloudflare','--login')[0],0)
        receipt=connection_record(self.config)
        with patch.dict(os.environ,{'PATH':str(self.home/'empty-path')}),patch.object(cloudflare,'remove') as remover:
            code,out,err,prompts=self.run_cli('expose','cloudflare','--remove',terminal=True)
        self.assertEqual(code,2);self.assertIn(cloudflare.INSTALL_DOCS,out)
        self.assertIn('cloudflared_not_found_install_it_see_docs_reachability',err)
        remover.assert_not_called();self.assertEqual(prompts,[])
        self.assertEqual(connection_record(self.config),receipt)

    def test_pending_summary_uses_v2_cleanup_state(self):
        self.configure();self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        journal=cloudflare.Journal(self.config);original=journal.read()
        for dns,removed,phase,expected,absent in (
            (None,False,'complete','tunnel pending deletion','local files pending deletion'),
            (original['dns'],True,'complete','DNS record pending deletion','tunnel pending deletion'),
            (None,True,'complete','local files pending deletion','tunnel pending deletion'),
            (None,False,'tunnel_created','partially provisioned exposure cleanup pending','local files pending deletion'),
        ):
            with self.subTest(removed=removed,phase=phase,dns=bool(dns)):
                value=dict(original,dns=dns,tunnel_removed=removed,phase=phase);journal.write(value)
                with patch.object(cloudflare,'remove',new=unittest.mock.AsyncMock()):
                    code,out,err,_=self.run_cli('expose','cloudflare','--remove',terminal=True)
                self.assertEqual(code,0,err);self.assertIn(expected,out);self.assertNotIn(absent,out)
                self.assertIn('exposure',connection_record(self.config))

    def test_login_remove_optional_prompt_token_file_and_skip(self):
        for mode in ('file','prompt','skip','unattended'):
            with self.subTest(mode=mode):
                self.configure()
                self.assertEqual(self.run_cli('expose','cloudflare','--login')[0],0)
                journal=cloudflare.Journal(self.config).read()
                self.fake.dns=[{'id':'dns','type':'CNAME','name':journal['hostname'],'content':journal['dns']['content']}]
                args=['expose','cloudflare','--remove']
                if mode=='file':args+=['--token-file',str(self.token_file())]
                original=cloudflare.remove
                with patch.object(cloudflare,'remove',wraps=original) as remove:
                    code,out,err,prompts=self.run_cli(*args,terminal=mode in ('prompt','skip'),entry='' if mode=='skip' else API_INPUT)
                self.assertEqual(code,0,err)
                self.assertEqual(remove.call_args.kwargs['token'],API_INPUT if mode in ('file','prompt') else None)
                if mode in ('prompt','skip'):
                    self.assertEqual(len(prompts),1)
                    self.assertIn('Optional: a Cloudflare API token (Zone › DNS › Edit, Zone › Zone › Read)',prompts[0])
                    self.assertIn('press Enter to skip',prompts[0])
                else:self.assertEqual(prompts,[])
                if mode in ('file','prompt'):self.assertFalse(self.fake.dns)
                else:
                    self.assertIn('Delete this CNAME manually',out)
                    self.assertIn('DNS record pending deletion',out)
                    self.assertNotIn('tunnel pending deletion',out)
                    self.assertNotIn('local files pending deletion',out)
                    self.assertIn('exposure',connection_record(self.config))
                    self.assertEqual(self.run_cli('expose','cloudflare','--remove','--token-file',str(self.token_file()))[0],0)
                self.assertTrue((self.home/'.cloudflared'/'cert.pem').exists())
                self.assert_secret_absent(API_INPUT)

    def test_remove_retains_exposure_until_journal_is_gone(self):
        self.configure()
        self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        receipt=connection_record(self.config)
        async def pending(config,**kwargs):
            journal=cloudflare.Journal(config);value=journal.read()
            value['tunnel_removed']=True;journal.write(value)
        with patch.object(cloudflare,'remove',side_effect=pending):
            code,out,err,_=self.run_cli('expose','cloudflare','--remove',terminal=True)
        self.assertEqual(code,0,err);self.assertEqual(connection_record(self.config),receipt)
        self.assertIn('DNS record pending deletion',out)
        self.assertIn('Re-running dot-herdr expose cloudflare --remove finishes',out)
        self.assertNotIn('Cloudflare exposure removed;',out)
        self.assertEqual(self.run_cli('expose','cloudflare','--remove',terminal=True)[0],0)
        self.assertIsNone(cloudflare.Journal(self.config).read())
        self.assertNotIn('exposure',connection_record(self.config))

    def test_tunnel_migration_warns_only_for_installed_openai_tunnel(self):
        for route,installed,warn in [('tunnel',{'tunnel':True},True),('tunnel',{'tunnel':False},False),('tunnel',None,False),('https',{'tunnel':True},False)]:
            with self.subTest(route=route,installed=installed):
                self.configure(route)
                with patch('dot_herdr.service.service_record',return_value=installed):
                    code,out,err,_=self.run_cli('migrate-route','--to','cloudflare','--confirm',terminal=True)
                self.assertEqual(code,0,err)
                self.assertEqual('must be reinstalled without --tunnel: dot-herdr service install' in out,warn)
                if warn:self.assertIn('Run refuses an OpenAI tunnel together with a Cloudflare exposure',out)
                self.assertEqual(connection_record(self.config)['route'],'https')

    def test_uninstall_successful_call_with_remaining_journal_is_incomplete(self):
        self.configure();self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        with ExitStack() as stack:
            stack.enter_context(patch.object(maintenance,'installed_prefix',return_value=self.home/'install'))
            stack.enter_context(patch.object(maintenance,'refresh_inventory'))
            stack.enter_context(patch('dot_herdr.installation.inventory',return_value={'releases':[]}))
            remove=stack.enter_context(patch('dot_herdr.installation.uninstall',return_value={'status':'uninstalled'}))
            stack.enter_context(patch('dot_herdr.access.service_adapter',return_value=None))
            stack.enter_context(patch.object(cli,'expose_cloudflare',return_value=None))
            notices=[]
            result=maintenance.uninstall(self.config,purge=True,confirm_purge=True,interactive=True,ask=lambda _:'yes',say=notices.append)
            self.assertEqual(result['exposure']['status'],'removal_incomplete')
            self.assertEqual(result['exposure']['next_action'],'dot-herdr expose cloudflare --remove')
            self.assertEqual(remove.call_args.kwargs['purge_paths'],[])
            self.assertIsNotNone(cloudflare.Journal(self.config).read())
            self.assertIn('ownership records retained',repr(notices))

    def test_cloudflare_migration_confirm_preserves_plugin_and_https(self):
        for route in ('https','tunnel'):
            with self.subTest(route=route):
                self.configure(route);record=connection_record(self.config)
                self.assertIn('migration_requires_explicit_route_wiring_and_confirm',self.run_cli('migrate-route','--to','cloudflare')[2])
                self.assertEqual(connection_record(self.config),record)
                self.assertIn('migration_requires_explicit_route_wiring_and_confirm',self.run_cli('migrate-route','--to','cloudflare','--confirm')[2])
                code,out,err,_=self.run_cli('migrate-route','--to','cloudflare','--confirm',terminal=True)
                self.assertEqual(code,0,err);self.assertIn('Plugin URL is unchanged: '+self.cfg['resource'],out)
                after=connection_record(self.config);self.assertEqual(after['route'],'https')
                for key in ('wiring','endpoint','owned'):self.assertEqual(after[key],record[key])
        self.assert_secret_absent(API_INPUT)

    def test_remove_failure_keeps_exposure_and_api_entry_out_of_errors(self):
        self.configure();self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        receipt=connection_record(self.config)
        def fail(req):return httpx2.Response(403,json={'success':False,'errors':[{'message':API_INPUT}]})
        with patch.object(self.fake,'handle',side_effect=fail):
            code,_,err,_=self.run_cli('expose','cloudflare','--remove',terminal=True)
        self.assertEqual(code,2);self.assertIn('cloudflare_api_operation_failed',err)
        self.assertEqual(connection_record(self.config),receipt)
        self.assertIsNotNone(cloudflare.Journal(self.config).read());self.assert_secret_absent(API_INPUT)

    def test_uninstall_failed_removal_retains_evidence_and_finishes_local_cleanup(self):
        self.configure();self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        with ExitStack() as stack:
            stack.enter_context(patch.object(maintenance,'installed_prefix',return_value=self.home/'install'))
            stack.enter_context(patch.object(maintenance,'refresh_inventory'))
            stack.enter_context(patch('dot_herdr.installation.inventory',return_value={'releases':[]}))
            remove=stack.enter_context(patch('dot_herdr.installation.uninstall',return_value={'status':'uninstalled'}))
            stack.enter_context(patch('dot_herdr.access.service_adapter',return_value=None))
            flow=stack.enter_context(patch.object(cli,'expose_cloudflare',side_effect=Rejected('cloudflare_api_unavailable')))
            notices=[]
            result=maintenance.uninstall(self.config,purge=True,confirm_purge=True,interactive=True,ask=lambda _:'yes',say=notices.append)
            self.assertEqual(result['status'],'uninstalled');self.assertEqual(result['exposure']['status'],'removal_incomplete')
            flow.assert_called_once_with(self.config,remove=True,say=notices.append)
            self.assertEqual(remove.call_args.kwargs['purge_paths'],[])
            self.assertIsNotNone(cloudflare.Journal(self.config).read())
            self.assertIn('dot-herdr expose cloudflare --remove',repr(notices))

    def test_migration_login_token_file_cancel_and_invalid_source(self):
        self.configure();token=self.token_file()
        self.assertEqual(self.run_cli('migrate-route','--to','cloudflare','--confirm','--route','https','--wiring','registered-plugin','--token-file',str(token))[0],0)
        self.assertEqual(self.run_cli('expose','cloudflare','--remove','--token-file',str(token))[0],0)
        with patch('builtins.input',return_value='n'):
            self.assertIn('migration_cancelled',self.run_cli('migrate-route','--to','cloudflare',terminal=True)[2])
        with patch('builtins.input',return_value='yes'):
            self.assertEqual(self.run_cli('migrate-route','--to','cloudflare','--login',terminal=True)[0],0)
        self.configure('loopback')
        self.assertIn('cloudflare_migration_requires_existing_https_or_tunnel',self.run_cli('migrate-route','--to','cloudflare','--confirm','--route','https','--wiring','registered-plugin')[2])
        with self.assertRaisesRegex(Rejected,'invalid_migration_target'):migrate_connection(self.config,'https','registered-plugin',to='other')

    def test_parser_old_action_and_flag_rejections(self):
        for args,reason in [(('check','status'),'action is only for service'),(('check','--login'),'--login is only for run'),(('signin','cloudflare'),'signin requires set-password'),(('expose','set-password'),'expose requires cloudflare'),(('run','--remove'),'--remove is only for expose'),(('run','--token-file','/tmp/unused'),'--token-file is only for'),(('run','--token-file',''),'--token-file is only for'),(('migrate-route','--to','other'),'invalid choice'),(('expose','cloudflare','--login','--token-file','/tmp/unused'),'cannot be combined')]:
            code,_,err,_=self.run_cli(*args);self.assertEqual(code,2);self.assertIn(reason,err)
        self.configure()
        with patch('dot_herdr.runtime.run',new=unittest.mock.AsyncMock()) as run:
            # Bypass key-source loading only: assert --login retains its run meaning.
            with patch('dot_herdr.auth.verifier_from_config'):
                self.assertEqual(self.run_cli('run','--login')[0],0)
            self.assertTrue(run.call_args.kwargs['login'])

    def test_uninstall_absent_or_unreadable_journal_without_receipt(self):
        for state in ('absent','invalid','read_error'):
            with self.subTest(state=state),ExitStack() as stack:
                self.configure();journal=cloudflare.Journal(self.config)
                if state=='invalid':
                    journal.root.mkdir(mode=0o700);journal.path.write_text('{}');journal.path.chmod(0o600)
                elif state=='read_error':
                    stack.enter_context(patch.object(cloudflare.Journal,'read',side_effect=OSError('synthetic read failure')))
                stack.enter_context(patch.object(maintenance,'installed_prefix',return_value=self.home/'install'))
                stack.enter_context(patch.object(maintenance,'refresh_inventory'))
                stack.enter_context(patch('dot_herdr.installation.inventory',return_value={'releases':[]}))
                stack.enter_context(patch('dot_herdr.access.service_adapter',return_value=None))
                remove=stack.enter_context(patch('dot_herdr.installation.uninstall',return_value={'status':'uninstalled'}))
                cleanup=stack.enter_context(patch('dot_herdr.connections.remove_owned_connections',return_value={'removed':[]}))
                notices=[]
                result=maintenance.uninstall(self.config,purge=True,confirm_purge=True,interactive=False,say=notices.append)
                cleanup.assert_called_once_with(self.config)
                self.assertEqual(remove.call_args.kwargs['purge_paths'],[self.config.parent] if state=='absent' else [])
                if state=='absent':
                    self.assertNotIn('exposure',result);self.assertFalse(journal.root.exists())
                else:
                    self.assertEqual(result['exposure']['status'],'ownership_unreadable')
                    self.assertEqual(result['exposure']['retained_journal'],str(journal.path))
                    self.assertEqual(result['exposure']['next_action'],'dot-herdr expose cloudflare --remove')
                    self.assertIn(str(journal.path),repr(notices))
                if state=='invalid':journal.path.unlink();journal.root.rmdir()

    def test_uninstall_journal_without_receipt_offers_partial_and_complete_removal(self):
        for phase in ('complete','tunnel_created'):
            for answer,expected in [('n','retained'),('yes','removed')]:
                with self.subTest(phase=phase,answer=answer),ExitStack() as stack:
                    self.configure();self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
                    journal=cloudflare.Journal(self.config);value=journal.read();value['phase']=phase;journal.write(value)
                    record=connection_record(self.config);record.pop('exposure');save_connection(self.config,record)
                    stack.enter_context(patch.object(maintenance,'installed_prefix',return_value=self.home/'install'))
                    stack.enter_context(patch.object(maintenance,'refresh_inventory'))
                    stack.enter_context(patch('dot_herdr.installation.inventory',return_value={'releases':[]}))
                    stack.enter_context(patch('dot_herdr.access.service_adapter',return_value=None))
                    remove=stack.enter_context(patch('dot_herdr.installation.uninstall',return_value={'status':'uninstalled'}))
                    stack.enter_context(patch('sys.stdin.isatty',return_value=True))
                    stack.enter_context(patch.object(cli.getpass,'getpass',return_value=API_INPUT))
                    questions=[];notices=[]
                    result=maintenance.uninstall(self.config,purge=True,confirm_purge=True,interactive=True,
                                                 ask=lambda p:(questions.append(p) or answer),say=notices.append)
                    self.assertEqual(len(questions),1)
                    self.assertEqual(result['exposure']['status'],expected)
                    self.assertEqual(remove.call_args.kwargs['purge_paths'],[self.config.parent] if expected=='removed' else [])
                    self.assertEqual(journal.read() is None,expected=='removed')
                    if expected=='retained':
                        self.assertIn(str(journal.path),repr(notices))
                        self.assertEqual(self.run_cli('expose','cloudflare','--remove',terminal=True)[0],0)

    def test_uninstall_offer_consent_and_retained_journal_with_purge(self):
        self.configure();self.assertEqual(self.run_cli('expose','cloudflare',terminal=True)[0],0)
        for answer,interactive,status in [('n',True,'retained'),('yes',False,'retained'),('yes',True,'removed')]:
            with self.subTest(answer=answer,interactive=interactive),ExitStack() as stack:
                stack.enter_context(patch.object(maintenance,'installed_prefix',return_value=self.home/'install'))
                stack.enter_context(patch.object(maintenance,'refresh_inventory'))
                stack.enter_context(patch('dot_herdr.installation.inventory',return_value={'releases':[]}))
                remove=stack.enter_context(patch('dot_herdr.installation.uninstall',return_value={'status':'uninstalled'}))
                stack.enter_context(patch('dot_herdr.access.service_adapter',return_value=None))
                stack.enter_context(patch('sys.stdin.isatty',return_value=True))
                stack.enter_context(patch.object(cli.getpass,'getpass',return_value=API_INPUT))
                notices=[];questions=[]
                result=maintenance.uninstall(self.config,purge=True,confirm_purge=True,interactive=interactive,ask=lambda p:(questions.append(p) or answer),say=notices.append)
                self.assertEqual(result['exposure']['status'],status);self.assertIn('connector.example.test',repr(notices))
                self.assertEqual(bool(questions),interactive)
                if status=='retained':
                    self.assertEqual(remove.call_args.kwargs['purge_paths'],[])
                    self.assertIn('dot-herdr expose cloudflare --remove',repr(notices));self.assertIsNotNone(cloudflare.Journal(self.config).read())
                else:self.assertIsNone(cloudflare.Journal(self.config).read())
        self.assert_secret_absent(API_INPUT)


class UninstallJournalTests(unittest.TestCase):
    def test_r2_2_partial_exposure_journal_prevents_purge(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            config = root / 'config.json'
            cfg = {'store': str(root / 'state' / 'connector.sqlite'), 'socket': str(root / 'source.sock'),
                   'issuer': 'https://auth.example.com', 'resource': 'https://herdr.example.com/mcp',
                   'public_key': str(root / 'public.pem'), 'subjects': [], 'inactive': True}
            config.write_text(json.dumps(cfg)); config.chmod(0o600)
            binary = root / 'cloudflared'
            binary.write_text('#!/bin/sh\nexit 0\n'); binary.chmod(0o700)
            fake = FakeCloudflare(); fake.fail_token = True; fake.fail_delete = True
            with patch('dot_herdr.cloudflare.shutil.which', return_value=str(binary)):
                with self.assertRaises(Rejected):
                    asyncio.run(cloudflare.expose_api(config, 'herdr.example.com', 8000, 'synthetic-api-input', api=fake.api(), say=lambda _: None))
            journal = cloudflare.Journal(config).read()
            self.assertIsNotNone(journal)
            self.assertTrue(fake.tunnels, 'remote synthetic tunnel must still exist')
            self.assertNotIn('exposure', connection_record(config))
            with ExitStack() as stack:
                stack.enter_context(patch.object(maintenance, 'installed_prefix', return_value=root / 'install'))
                stack.enter_context(patch.object(maintenance, 'refresh_inventory'))
                stack.enter_context(patch('dot_herdr.installation.inventory', return_value={'releases': []}))
                stack.enter_context(patch('dot_herdr.access.service_adapter', return_value=None))
                remove = stack.enter_context(patch('dot_herdr.installation.uninstall', return_value={'status': 'uninstalled'}))
                notices = []
                result = maintenance.uninstall(config, purge=True, confirm_purge=True, interactive=False, say=notices.append)
            self.assertEqual(remove.call_args.kwargs['purge_paths'], [],
                             'uninstall schedules deletion of the only journal for a still-existing tunnel')

            self.assertEqual(result['exposure']['status'], 'retained')
            self.assertEqual(result['exposure']['retained_journal'], str(cloudflare.Journal(config).path))
            self.assertEqual(result['exposure']['next_action'], 'dot-herdr expose cloudflare --remove')
            self.assertIn(str(cloudflare.Journal(config).path), repr(notices))
            self.assertIsNotNone(cloudflare.Journal(config).read())
            self.assertTrue(fake.tunnels)

if __name__=='__main__':unittest.main()
