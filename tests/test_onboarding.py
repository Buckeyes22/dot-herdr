"""Setup must reduce manual work without changing source or existing grants."""
import importlib.util
import json
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dot_herdr.core import Rejected
from dot_herdr.onboarding import configure,choose_socket,running_sessions,save_config
from dot_herdr.setup import TEMPLATE,default_config_path,load_config,placeholders

AGENT={'pane_id':'pane_fixture','terminal_id':'terminal_fixture','agent':'codex','agent_status':'idle',
       'agent_session':{'source':'hook','agent':'codex','kind':'id','value':'native-fixture'},
       'terminal_title':'private secret title','cwd':'/private/project'}
class Source:
 def __init__(self,path):self.calls=[];self.current=dict(AGENT);self.version='0.9.3'
 async def request(self,method,params):
  self.calls.append((method,params))
  if method=='ping':return {'type':'pong','version':self.version,'protocol':22}
  if method=='agent.list':return {'type':'agent_list','agents':[dict(AGENT)]}
  raise AssertionError('Setup must never dispatch native writes')
 async def agent(self,pane):self.calls.append(('agent.get',{'target':pane}));return dict(self.current)

class OnboardingTests(unittest.IsolatedAsyncioTestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.config=self.root/'private/config.json'
  self.home_patch=patch('pathlib.Path.home',return_value=self.root);self.home_patch.start();self.addCleanup(self.home_patch.stop)
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket=self.root/'source.sock';self.sock.bind(str(self.socket))
  self.source=Source(str(self.socket));self.messages=[]
 def tearDown(self):self.sock.close();self.temp.cleanup()
 async def run_setup(self,answers,path=None):
  iterator=iter(answers)
  return await configure(path or self.config,str(self.socket),ask=lambda _:next(iterator),say=self.messages.append,client_factory=lambda _:self.source)
 def public_key(self):
  key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  p=self.root/'public.pem';p.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo));return p
 async def test_selected_control_auto_ids_private_files_and_local_checks(self):
  report=await self.run_setup(['2','1','y','https://auth.example.test','https://connector.example.test/mcp',str(self.public_key()),'user-fixture'])
  cfg=load_config(self.config);subject=cfg['subjects'][0]
  self.assertEqual(subject['pane'],AGENT['pane_id']);self.assertEqual(subject['terminal'],AGENT['terminal_id']);self.assertEqual(subject['native'],AGENT['agent_session'])
  self.assertTrue(subject['control']);self.assertTrue(subject['content']);self.assertEqual(cfg['session_users'],[])
  self.assertEqual(self.config.stat().st_mode&0o777,0o600);self.assertEqual(self.config.parent.stat().st_mode&0o777,0o700)
  self.assertEqual(Path(cfg['store']).parent.stat().st_mode&0o777,0o700);self.assertFalse(Path(cfg['store']).exists())
  self.assertFalse(any(c['status']=='blocked' for c in report['checks']));self.assertFalse(report['live_ready'])
  self.assertNotIn('private secret title','\n'.join(self.messages));self.assertNotIn('/private/project','\n'.join(self.messages))
  self.assertEqual([c[0] for c in self.source.calls],['ping','agent.list','agent.get'])
 async def test_whole_session_can_skip_roster_and_resume_missing_auth(self):
  report=await self.run_setup(['3','','','','',''])
  cfg=load_config(self.config);self.assertEqual(cfg['subjects'],[]);self.assertTrue(placeholders(cfg));self.assertFalse(report['live_ready'])
  before_calls=list(self.source.calls)
  report=await self.run_setup(['https://auth.example.test','https://connector.example.test/mcp',str(self.public_key()),'user-fixture'])
  cfg=load_config(self.config);self.assertEqual(cfg['session_users'],['user-fixture']);self.assertFalse(placeholders(cfg))
  self.assertEqual(self.source.calls,before_calls);self.assertEqual(report['checks'][2]['status'],'pass')
 async def test_observation_only_and_context_default_off(self):
  await self.run_setup(['1','1','','','','',''])
  subject=load_config(self.config)['subjects'][0];self.assertFalse(subject['control']);self.assertFalse(subject['content'])
 async def test_replaced_agent_duplicate_selection_bad_access_and_version_save_nothing(self):
  self.source.current['terminal_id']='replacement'
  with self.assertRaisesRegex(Rejected,'identity_changed'):await self.run_setup(['2','1','n'])
  self.assertFalse(self.config.exists())
  for answers in (['2','1,1'],['invalid']):
   with self.assertRaises(Rejected):await self.run_setup(answers)
   self.assertFalse(self.config.exists())
  self.source.version='0.9.4'
  with self.assertRaisesRegex(Rejected,'unsupported_source_version'):await self.run_setup([])
 async def test_existing_valid_or_initialized_config_retains_bytes_without_prompts(self):
  await self.run_setup(['3','','https://auth.example.test','https://connector.example.test/mcp',str(self.public_key()),'user-fixture'])
  before=self.config.read_bytes();self.source.calls.clear()
  await self.run_setup([]);self.assertEqual(self.config.read_bytes(),before);self.assertEqual(self.source.calls,[])
  Path(load_config(self.config)['store']).write_bytes(b'existing store')
  await self.run_setup([]);self.assertEqual(self.config.read_bytes(),before)
 async def test_pending_resume_no_clobber_symlink_or_unrelated_permission_changes(self):
  await self.run_setup(['3','','','','','']);cfg=load_config(self.config);before=self.config.read_bytes()
  with self.assertRaises(FileExistsError):save_config(self.config,cfg)
  with self.assertRaisesRegex(Rejected,'configuration_changed'):save_config(self.config,cfg,b'other config')
  self.assertEqual(self.config.read_bytes(),before)
  link=self.root/'link.json';link.symlink_to(self.config)
  with self.assertRaisesRegex(Rejected,'private_configuration|connection_symlink_path'):await self.run_setup([],link)
  public=self.root/'shared';public.mkdir(mode=0o755);public.chmod(0o755)
  with self.assertRaisesRegex(Rejected,'private_output_parent'):await self.run_setup(['3','','','','',''],public/'config.json')
  self.assertEqual(public.stat().st_mode&0o777,0o755);self.assertFalse((public/'config.json').exists())
  oversized={**cfg,'issuer':'https://auth.example.test/'+('x'*65536)}
  with self.assertRaisesRegex(Rejected,'configuration_too_large'):save_config(self.root/'too-large/config.json',oversized)
  self.assertFalse((self.root/'too-large').exists())
 async def test_cancel_before_save_and_private_key_are_rejected(self):
  def cancel(_):raise EOFError
  with self.assertRaises(EOFError):await configure(self.config,str(self.socket),ask=cancel,say=self.messages.append,client_factory=lambda _:self.source)
  self.assertFalse(self.config.exists())
  key=rsa.generate_private_key(public_exponent=65537,key_size=2048);p=self.root/'private.pem'
  p.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
  with self.assertRaisesRegex(Rejected,'invalid_rsa_public_key'):await self.run_setup(['3','','https://auth.example.test','https://connector.example.test/mcp',str(p),'user'])
  self.assertFalse(self.config.exists())
 def test_session_discovery_selects_only_running_explicit_choice_and_redacts_errors(self):
  data={'sessions':[{'running':False,'name':'stopped','socket_path':'/old'},{'running':True,'name':'one','socket_path':'/one'},{'running':True,'name':'two','socket_path':'/two'}]}
  response=subprocess.CompletedProcess([],0,stdout=json.dumps(data).encode(),stderr=b'')
  with patch('dot_herdr.onboarding.shutil.which',return_value='/herdr'),patch('dot_herdr.onboarding.subprocess.run',return_value=response) as called:
   self.assertEqual(len(running_sessions()),2);self.assertEqual(choose_socket(None,lambda _:'2',self.messages.append),'/two')
   self.assertEqual(called.call_args.args[0],['/herdr','session','list','--json'])
  with patch('dot_herdr.onboarding.running_sessions',return_value=[data['sessions'][1]]):
   self.assertEqual(choose_socket(None,lambda _:self.fail('single session needs no prompt'),self.messages.append),'/one')
  with patch('dot_herdr.onboarding.shutil.which',return_value='/herdr'),patch('dot_herdr.onboarding.subprocess.run',side_effect=subprocess.CalledProcessError(1,[],stderr=b'private secret')):
   with self.assertRaisesRegex(Rejected,'^session_discovery_failed_use_setup_socket$'):running_sessions()
 def test_default_path_and_session_subject_placeholders(self):
  with patch.dict(os.environ,{'XDG_CONFIG_HOME':str(self.root)}):self.assertEqual(default_config_path(),self.root/'dot-herdr/config.json')
  cfg={**TEMPLATE,'store':'/private/db','socket':'/private/sock','issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':'/private/key','subjects':[],'session_users':['replace-with-sub']}
  self.assertTrue(placeholders(cfg));cfg['session_users']=['user'];self.assertFalse(placeholders(cfg))

class InstallerTests(unittest.TestCase):
 def test_installer_refuses_unrelated_installation_or_command_before_any_process(self):
  path=Path(__file__).resolve().parents[1]/'scripts/install.py'
  # Source distributions include the installer; wheel suites run this source test.
  spec=importlib.util.spec_from_file_location('connector_installer',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);source=root/'source';source.mkdir();(source/'pyproject.toml').write_text('[project]')
   prefix=root/'prefix';prefix.mkdir();bin_dir=root/'bin'
   with patch.object(module.subprocess,'run') as run:
    with self.assertRaisesRegex(ValueError,'already used'):module.install(source,prefix,bin_dir)
    run.assert_not_called()
   prefix.rmdir();bin_dir.mkdir();(bin_dir/'dot-herdr').write_text('unrelated')
   with patch.object(module.subprocess,'run') as run:
    with self.assertRaisesRegex(ValueError,'overwritten'):module.install(source,prefix,bin_dir)
    run.assert_not_called()
   self.assertFalse(prefix.exists());self.assertEqual((bin_dir/'dot-herdr').read_text(),'unrelated')
