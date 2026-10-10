"""Schema completeness, SDK grants and bounded real Unix event transport."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import jsonschema
import test_actions
from dot_herdr.actions import METHODS, READ_METHODS, WRITE_METHODS, UNSUPPORTED_METHODS, method_schema, method_details, prepare
from dot_herdr.core import Rejected
from dot_herdr.endpoint import build
from dot_herdr.herdr import HerdrClient, MAX_EVENT_SAMPLE

P='pane_demo'
POINT={'row':0,'col':0}
QUERIES={
 'ping':{}, 'session.snapshot':{}, 'server.agent_manifests':{},
 'integration.list':{}, 'plugin.list':{}, 'plugin.action.list':{}, 'plugin.log.list':{},
 'pane.current':{'caller_pane_id':P},
 'pane.selection.read':{'pane_id':P,'anchor':POINT,'cursor':POINT},
 'pane.copy_motion':{'pane_id':P,'cursor':POINT,'motion':'next_word_start'},
 'pane.copy_search':{'pane_id':P,'cursor':POINT,'query':'hello','direction':'forward','content_revision':1},
 'pane.link.resolve':{'pane_id':P,'viewport_row':0,'col':0},
 'events.wait':{'match_event':{'event':'pane_agent_status_changed','pane_id':P,'agent_status':'idle'}}}
ACTIONS={
 'server.stop':{}, 'server.live_handoff':{'expected_version':'0.9.3','expected_protocol':22},
 'server.reload_config':{}, 'server.reload_agent_manifests':{},
 'notification.show':{'title':'Synthetic notification','sound':'none'},
 'product_announcement.dismiss':{'version':'0.9.3','id':'synthetic'}, 'release_notes.dismiss':{'version':'0.9.3'},
 'command.invoke':{'command_id':'opaque-fixture-command','pane_id':P},
 'workspace.report_metadata':{'workspace_id':'workspace_demo','source':'test','tokens':{'task':'fixture'}},
 'agent.view.set':{'source':'test','filter':{'op':'all','filters':[{'op':'eq','field':'status','value':'idle'}]},'sort':[{'field':'workspace_order'}]},
 'agent.view.clear':{'source':'test'},
 'pane.resize':{'pane_id':P,'direction':'right','amount':0.1},
 'pane.scroll':{'pane_id':P,'offset_from_bottom':0}, 'pane.clear':{'pane_id':P}, 'pane.edit_scrollback':{'pane_id':P},
 'pane.input.set':{'pane_id':P,'right_click':'herdr'}, 'pane.link.activate':{'pane_id':P,'viewport_row':0,'col':0},
 'pane.report_agent':{'pane_id':P,'source':'test','agent':'codex','state':'idle'},
 'pane.report_agent_session':{'pane_id':P,'source':'test','agent':'codex','agent_session_id':'actual-fixture-id'},
 'pane.report_metadata':{'pane_id':P,'source':'test','title':'fixture'},
 'pane.clear_agent_authority':{'pane_id':P}, 'pane.release_agent':{'pane_id':P,'source':'test','agent':'codex'},
 'popup.close':{}, 'integration.install':{'target':'codex'}, 'integration.uninstall':{'target':'codex'},
 'plugin.link':{'path':'/tmp/synthetic-plugin'}, 'plugin.unlink':{'plugin_id':'fixture'},
 'plugin.enable':{'plugin_id':'fixture'}, 'plugin.disable':{'plugin_id':'fixture'},
 'plugin.action.invoke':{'action_id':'fixture','context':{'focused_pane_id':P}},
 'plugin.pane.open':{'plugin_id':'fixture','entrypoint':'main','cwd':'/tmp','workspace_id':'workspace_demo','focus':False},
 'plugin.pane.focus':{'pane_id':P}, 'plugin.pane.close':{'pane_id':P}}

class CatalogTests(unittest.TestCase):
 def test_all_native_methods_have_resolvable_schemas_and_one_disposition(self):
  self.assertEqual(len(METHODS),102)
  self.assertEqual((len(READ_METHODS),len(WRITE_METHODS),len(UNSUPPORTED_METHODS)),(32,65,4))
  self.assertFalse(set(READ_METHODS)&set(WRITE_METHODS))
  self.assertEqual(set(METHODS),set(READ_METHODS)|set(WRITE_METHODS)|set(UNSUPPORTED_METHODS)|{'events.subscribe'})
  for method,spec in METHODS.items():
   with self.subTest(method=method):
    schema=method_schema(method);jsonschema.Draft202012Validator.check_schema(schema)
    self.assertEqual(set(schema.get('properties',{})),set(spec['fields']))
    self.assertEqual(set(schema.get('required',[])),set(spec['required']))
    def refs(value):
     if isinstance(value,dict):
      if '$ref' in value:self.assertIn(value['$ref'].removeprefix('#/$defs/'),schema['$defs'])
      for v in value.values():refs(v)
     elif isinstance(value,list):
      for v in value:refs(v)
    refs(schema)
 def test_realistic_expanded_parameters_match_native_schema(self):
  for method,params in {**QUERIES,**ACTIONS}.items():
   with self.subTest(method=method):jsonschema.validate(prepare(method,params),method_schema(method))
 def test_cloud_constraints_reject_focus_fallback_and_unbounded_waits(self):
  invalid=[('pane.current',{}),('plugin.action.invoke',{'action_id':'x'}),
   ('plugin.action.invoke',{'action_id':'x','context':{}}),
   ('command.invoke',{'command_id':'opaque'}),('plugin.link',{'path':'relative'}),
   ('plugin.pane.open',{'plugin_id':'x','entrypoint':'main','cwd':'/tmp'}),
   ('plugin.pane.open',{'plugin_id':'x','entrypoint':'main','cwd':'relative','workspace_id':'w'}),
   ('events.wait',{'match_event':{'event':'workspace_created'}}),
   ('events.wait',{'match_event':{'event':'pane_agent_status_changed','pane_id':P},'timeout_ms':None}),
   ('plugin.log.list',{'limit':101}),('plugin.log.list',{'limit':None})]
  for method,params in invalid:
   with self.subTest(method=method,params=params),self.assertRaises(Rejected):prepare(method,params)
  for method in UNSUPPORTED_METHODS:
   with self.subTest(method=method),self.assertRaises(Rejected):prepare(method,{})
 def test_discovered_routes_permissions_and_constraints_match_validation(self):
  for method,spec in METHODS.items():
   with self.subTest(method=method):
    d=method_details(method)
    self.assertEqual(d['tool'],{'query':'herdr_query','action':'herdr_action','events':'collect_native_events'}.get(spec['access']))
    self.assertEqual('herdr:control' in d['permissions']['oauth_scopes'],spec['access']=='action')
    self.assertTrue(d['permissions']['session_access_required'])
  for method in ('agent.wait','pane.wait_for_output','events.wait','agent.start'):
   constraints=method_details(method)['connector_constraints']['timeout_ms']
   params={'agent.wait':{'target':P},'pane.wait_for_output':{'pane_id':P,'source':'visible','match':{'type':'substring','value':'test'}},
           'events.wait':QUERIES['events.wait'],'agent.start':{'pane_id':P,'name':'test','kind':'codex'}}[method]
   self.assertEqual(prepare(method,params)['timeout_ms'],constraints['default'])
   for timeout in (constraints['minimum']-1,constraints['maximum']+1,None):
    with self.subTest(method=method,timeout=timeout),self.assertRaises(Rejected):prepare(method,{**params,'timeout_ms':timeout})
  self.assertEqual(method_details('plugin.pane.open')['connector_constraints']['absolute_paths'],['cwd'])
  self.assertEqual(method_details('plugin.action.invoke')['connector_constraints']['explicit_targets']['one_of_each'],[['context.focused_pane_id','context.tab_id','context.workspace_id']])

class NativeSDKTests(unittest.IsolatedAsyncioTestCase):
 setUp=test_actions.ActionTests.setUp
 tearDown=test_actions.ActionTests.tearDown
 rpc=test_actions.ActionTests.rpc
 async def test_expanded_methods_forward_through_authenticated_sdk(self):
  for method,params in QUERIES.items():
   with self.subTest(method=method):
    result=await self.rpc('herdr_query',{'method':method,'params':params},token='observer')
    self.assertFalse(result.get('isError',False),result)
    self.assertEqual(self.source.calls[-1],(method,prepare(method,params)))
  for i,(method,params) in enumerate(ACTIONS.items()):
   with self.subTest(method=method):
    args={'method':method,'params':params,'request_id':str(i)}
    first=await self.rpc('herdr_action',args)
    self.assertEqual(first['structuredContent']['outcome'],'submitted',first)
    self.assertEqual(self.source.calls[-1],(method,prepare(method,params)))
    count=len(self.source.calls)
    self.assertEqual(first,await self.rpc('herdr_action',args));self.assertEqual(len(self.source.calls),count)
 async def test_permissions_exclusions_and_method_schema_discovery(self):
  for method in ('server.stop','plugin.enable','pane.report_agent'):
   args={'method':method,'params':ACTIONS[method],'request_id':method}
   self.assertTrue((await self.rpc('herdr_action',args,token='observer'))['isError'])
   self.session_users=set()
   self.assertTrue((await self.rpc('herdr_action',args))['isError'])
   self.session_users={test_actions.USER}
  for method in UNSUPPORTED_METHODS:
   self.assertTrue((await self.rpc('herdr_action',{'method':method,'params':{},'request_id':method}))['isError'])
   descriptor=(await self.rpc('get_herdr_capabilities',{'method':method}))['structuredContent']
   self.assertEqual(descriptor['access'],'unsupported');self.assertIn('reason',descriptor)
  self.assertEqual(self.source.calls,[])
  details=(await self.rpc('get_herdr_capabilities',{'method':'agent.view.set'}))['structuredContent']
  self.assertEqual(details['inputSchema'],method_schema('agent.view.set'))
  self.assertEqual(details['tool'],'herdr_action')
  self.assertEqual(details['permissions']['oauth_scopes'],['herdr:observe','herdr:control'])
  for method in ('plugin.pane.open','events.subscribe','events.wait','pane.send_input'):
   descriptor=(await self.rpc('get_herdr_capabilities',{'method':method}))['structuredContent']
   self.assertEqual(descriptor,method_details(method))
  self.session_users=set()
  self.assertTrue((await self.rpc('get_herdr_capabilities',{'method':'agent.view.set'}))['isError'])
 async def test_collector_grants_bounds_and_forwarding(self):
  calls=[]
  async def collect(subscriptions,timeout_ms,limit):
   calls.append((subscriptions,timeout_ms,limit));return {'events':[],'end_reason':'deadline','history':'best_effort'}
  self.source.collect_events=collect
  args={'subscriptions':[{'type':'pane.agent_status_changed','pane_id':P}],'timeout_ms':10,'limit':1}
  result=await self.rpc('collect_native_events',args,token='observer')
  self.assertFalse(result.get('isError',False),result);self.assertEqual(len(calls),1)
  for extra in ({'timeout_ms':30001},{'subscriptions':[]},{'limit':101}):
   self.assertTrue((await self.rpc('collect_native_events',{**args,**extra}))['isError'])
  self.session_users=set()
  self.assertTrue((await self.rpc('collect_native_events',args))['isError']);self.assertEqual(len(calls),1)
 async def test_tool_catalog_and_native_enum_completeness(self):
  server=build(self.store,self.source,None,test_actions.Verifier(),test_actions.ISSUER,test_actions.RESOURCE,controls=self.controls,session_users=self.session_users)
  tools={t.name:t for t in await server.list_tools()}
  self.assertEqual(len(tools),19)
  for name,methods in (('herdr_query',READ_METHODS),('herdr_action',WRITE_METHODS)):
   self.assertEqual(set(tools[name].input_schema['properties']['method']['enum']),set(methods))

class EventWireTests(unittest.IsolatedAsyncioTestCase):
 async def collect(self,frames,limit=25,timeout=100,quiet=False,ack=None):
  with tempfile.TemporaryDirectory() as temp:
   path=str(Path(temp)/'events.sock');requests=[];closed=asyncio.Event()
   async def handle(reader,writer):
    try:
     request=json.loads(await reader.readline());requests.append(request)
     response=ack if ack is not None else {'id':'native-watch','result':{'type':'subscription_started'}}
     writer.write((json.dumps(response)+'\n').encode())
     for frame in frames:writer.write((json.dumps(frame)+'\n').encode())
     await writer.drain()
     if quiet:await reader.read()
    finally:
     writer.close()
     try:await writer.wait_closed()
     except OSError:pass
     closed.set()
   server=await asyncio.start_unix_server(handle,path)
   async with server:
    result=await HerdrClient(path).collect_events([{'type':'pane.closed'}],timeout,limit)
    await asyncio.wait_for(closed.wait(),1)
   self.assertEqual(len(requests),1);self.assertEqual(requests[0]['method'],'events.subscribe')
   return result
 async def test_event_limit_and_socket_closure(self):
  event={'event':'pane_closed','data':{'pane_id':P}}
  result=await self.collect([event,event],limit=1,quiet=True)
  self.assertEqual(result['events'],[event]);self.assertEqual(result['end_reason'],'event_limit')
  self.assertFalse(result['durable']);self.assertFalse(result['resume_supported'])
 async def test_deadline_and_disconnect(self):
  result=await self.collect([],timeout=10,quiet=True);self.assertEqual(result['end_reason'],'deadline')
  result=await self.collect([]);self.assertEqual(result['end_reason'],'disconnected')
 async def test_loss_and_source_error_preserve_collected_history_without_secrets(self):
  event={'event':'events_lost','data':{'count':2}}
  result=await self.collect([event,{'error':{'code':'subscription_failed','message':'private secret'}}])
  self.assertEqual(result['events'],[event]);self.assertEqual(result['reason'],'subscription_failed')
  self.assertNotIn('private secret',json.dumps(result));self.assertEqual(result['history'],'best_effort')
 async def test_malformed_ack_and_frames_are_safe(self):
  for ack in ({'id':'native-watch','result':None},{'id':'wrong','result':{}},{'id':'native-watch','error':{'code':'private-secret','message':'private secret'}}):
   with self.subTest(ack=ack):
    result=await self.collect([],ack=ack)
    self.assertEqual(result['end_reason'],'source_error');self.assertNotIn('private secret',json.dumps(result))
  result=await self.collect([{'not_an_event':'private secret'}])
  self.assertEqual(result['reason'],'malformed_source');self.assertNotIn('private secret',json.dumps(result))
 async def test_byte_budget_preserves_only_bounded_sample(self):
  event={'event':'pane_output_matched','data':{'text':'x'*70000}}
  result=await self.collect([event,event])
  self.assertEqual(len(result['events']),1);self.assertEqual(result['end_reason'],'byte_limit')
  self.assertLessEqual(len(json.dumps(result['events']).encode()),MAX_EVENT_SAMPLE)
 async def test_invalid_limits_and_unsupported_requests_never_open_socket(self):
  client=HerdrClient('/no/such/socket')
  for args in (([],10,1),([{}],0,1),([{}],10,101)):
   with self.subTest(args=args),self.assertRaises(Rejected):await client.collect_events(*args)
  for method in UNSUPPORTED_METHODS:
   with self.subTest(method=method),self.assertRaises(Rejected):await client.request(method,{})
 async def test_cancellation_closes_subscription_without_reconnect(self):
  with tempfile.TemporaryDirectory() as temp:
   path=str(Path(temp)/'cancel.sock');connected=asyncio.Event();closed=asyncio.Event();requests=[]
   async def handle(reader,writer):
    try:
     requests.append(json.loads(await reader.readline()))
     writer.write(b'{"id":"native-watch","result":{"type":"subscription_started"}}\n')
     await writer.drain();connected.set();await reader.read()
    finally:
     writer.close();await writer.wait_closed();closed.set()
   server=await asyncio.start_unix_server(handle,path)
   async with server:
    task=asyncio.create_task(HerdrClient(path).collect_events([{'type':'pane.closed'}],30000,25))
    await asyncio.wait_for(connected.wait(),1);task.cancel()
    with self.assertRaises(asyncio.CancelledError):await task
    await asyncio.wait_for(closed.wait(),1)
   self.assertEqual(len(requests),1)
