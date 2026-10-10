import asyncio
import json
import logging
from unittest.mock import patch
import os
import subprocess
import stat
import tempfile
import unittest
import uuid
from urllib.parse import parse_qs
from pathlib import Path

import httpx2
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from dot_herdr.cloudflare import (CloudflareAPI, detect_cloudflared, expose_api,
    expose_login, ingress_rules, remove, run_command)
from dot_herdr.core import Rejected
from dot_herdr import cloudflare


class FakeCloudflare:
    def __init__(self):
        self.calls=[]; self.tunnels=[]; self.dns=[]; self.n=0; self.fail_dns=False; self.fail_token=False; self.fail_delete=False
        async def handler(req):
            body=await req.json() if req.method in ('POST','PUT') else None
            self.calls.append((req.method,req.url.path,body))
            p=req.url.path
            if p=='/zones': return JSONResponse({'success':True,'result':[{'id':'zone1','name':'example.com','account':{'id':'acct1'}}]})
            if p=='/accounts/acct1/cfd_tunnels' and req.method=='GET': return JSONResponse({'success':True,'result':self.tunnels})
            if p=='/accounts/acct1/cfd_tunnel' and req.method=='POST':
                self.n+=1; t={'id':str(uuid.UUID(int=self.n)),'name':body['name'],'token':'run-token'}; self.tunnels.append(t); return JSONResponse({'success':True,'result':t})
            if p.endswith('/token'):
                if self.fail_token: return JSONResponse({'success':False},status_code=400)
                return JSONResponse({'success':True,'result':'run-token'})
            if p.endswith('/configurations'): return JSONResponse({'success':True,'result':{}})
            if p=='/zones/zone1/dns_records' and req.method=='GET': return JSONResponse({'success':True,'result':[x for x in self.dns if x['name']==req.query_params.get('name')]})
            if p=='/zones/zone1/dns_records' and req.method=='POST':
                if self.fail_dns: return JSONResponse({'success':False,'errors':[{'message':'bad'}]},status_code=400)
                self.n+=1; d={'id':f'dns{self.n}',**body}; self.dns.append(d); return JSONResponse({'success':True,'result':d})
            if '/dns_records/' in p and req.method=='DELETE':
                rid=p.rsplit('/',1)[1]; self.dns[:]=[x for x in self.dns if x['id']!=rid]; return JSONResponse({'success':True,'result':{}})
            if p.endswith('/connections') and req.method=='DELETE': return JSONResponse({'success':True,'result':{}})
            if '/cfd_tunnel/' in p and req.method=='DELETE':
                if self.fail_delete: return JSONResponse({'success':False},status_code=400)
                tid=p.rsplit('/',1)[1]; self.tunnels[:]=[x for x in self.tunnels if x['id']!=tid]; return JSONResponse({'success':True,'result':{}})
            if '/cfd_tunnel/' in p:
                tid=p.split('/cfd_tunnel/',1)[1].split('/',1)[0]
                item=next((x for x in self.tunnels if x['id']==tid),None)
                return JSONResponse({'success':True,'result':item},status_code=200 if item else 404)
            return JSONResponse({'success':False},status_code=404)
        self.app=Starlette(routes=[Route('/{path:path}',handler,methods=['GET','POST','PUT','DELETE'])])
    def api(self,token='SECRET-API-TOKEN'):
        transport=httpx2.ASGITransport(app=self.app)
        api=CloudflareAPI(token,transport=transport,base_url='http://test')
        return api


class CloudflareTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name); self.config=self.base/'dot-herdr.json'
        self.binary=self.base/'cf'; self.binary.write_text('#!/bin/sh\nexit 0\n'); self.binary.chmod(0o700)
        self.home=self.base/'home'
        env=patch.dict(os.environ,{'HOME':str(self.home)}); env.start(); self.addCleanup(env.stop)
        which=patch('dot_herdr.cloudflare.shutil.which',return_value=str(self.binary)); which.start(); self.addCleanup(which.stop)

    def journal_value(self, mode='api', tid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', phase='tunnel_created', home=None):
        j=cloudflare.Journal(self.config, home=home)
        value=cloudflare._record(j,mode,'herdr.example.com',tid,str(self.binary),zone={'id':'zone1','name':'example.com','account_id':'acct1'} if mode=='api' else None)
        value['phase']=phase
        return value

    def ownership(self):
        return json.dumps([{'id':tid,'name':'dot-herdr-'+cloudflare.install_id(self.config)} for tid in ('12345678-1234-1234-1234-123456789abc','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')])

    def test_ingress_and_detect(self):
        self.assertEqual(ingress_rules('herdr.example.com',8000),[
            {'hostname':'herdr.example.com','service':'http://127.0.0.1:8000','originRequest':{'httpHostHeader':'herdr.example.com'}},
            {'service':'http_status:404'}])
        self.assertIsNone(detect_cloudflared(which=lambda _:None))
        fake=self.base/'cloudflared'; fake.write_text('#!/bin/sh\necho cloudflared version 1\n'); fake.chmod(0o755)
        self.assertEqual(detect_cloudflared(which=lambda _:str(fake))['version'],'cloudflared version 1')

    def test_api_remove_without_cloudflared_and_login_remove_requires_it(self):
        fake=FakeCloudflare(); api=fake.api()
        asyncio.run(expose_api(self.config,'herdr.example.com',8000,'SECRET-API-TOKEN',api=api))
        self.binary.unlink()
        with patch('dot_herdr.cloudflare.shutil.which',return_value=None):
            asyncio.run(remove(self.config,api=api,say=lambda _:None))
        self.assertFalse((self.base/'cloudflare'/'journal.json').exists())

        self.binary.write_text('#!/bin/sh\nexit 0\n'); self.binary.chmod(0o700)
        home=self.base/'login-home'
        login_journal=cloudflare.Journal(self.config,home=home)
        login_journal.write(self.journal_value(mode='login',home=home))
        self.assertIsNotNone(login_journal.read())
        self.binary.unlink()
        with patch('dot_herdr.cloudflare.shutil.which',return_value=None):
            with self.assertRaises(Rejected) as raised:
                asyncio.run(remove(self.config,say=lambda _:None,home=home))
        self.assertEqual(str(raised.exception),'cloudflared_not_found_install_it_see_docs_reachability')

    def test_api_create_permissions_and_journal_hygiene(self):
        fake=FakeCloudflare(); api=fake.api(); output=[]
        record=asyncio.run(expose_api(self.config,'herdr.example.com',8000,'SECRET-API-TOKEN',api=api,say=output.append))
        self.assertEqual(record['mode'],'api')
        root=self.base/'cloudflare'; token=root/'tunnel.token'
        self.assertEqual(token.read_text(),'run-token'); self.assertEqual(stat.S_IMODE(token.stat().st_mode),0o600)
        self.assertNotIn('run-token',(root/'journal.json').read_text())
        self.assertFalse(any('SECRET-API-TOKEN' in p.read_text(errors='ignore') for p in self.base.rglob('*') if p.is_file()))
        self.assertNotIn('SECRET-API-TOKEN',repr(output))
    def test_api_idempotent_rerun(self):
        fake=FakeCloudflare(); api=fake.api()
        first=asyncio.run(expose_api(self.config,'herdr.example.com',8000,'SECRET-API-TOKEN',api=api))
        calls=len(fake.calls)
        self.assertEqual(asyncio.run(expose_api(self.config,'herdr.example.com',8000,'SECRET-API-TOKEN',api=api)),first)
        self.assertEqual(sum(c[0]=='POST' for c in fake.calls),2)

    def test_refuse_foreign_dns_and_tunnel(self):
        # Foreign records of every common type prevent all provisioning writes.
        for typ in ('A','AAAA','CNAME'):
            other=FakeCloudflare(); other.dns.append({'id':'foreign','type':typ,'name':'herdr.example.com','content':'foreign'})
            with self.assertRaises(Rejected): asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=other.api()))
            self.assertFalse(any(c[0]=='POST' for c in other.calls))
        foreign=FakeCloudflare(); foreign.tunnels.append({'id':'foreign','name':'dot-herdr-'+__import__('hashlib').sha256(str(self.config.absolute()).encode()).hexdigest()[:16]})
        with self.assertRaises(Rejected): asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=foreign.api()))
    def test_remove_preserves_foreign_and_changed_records(self):
        fake=FakeCloudflare(); api=fake.api()
        asyncio.run(expose_api(self.config,'herdr.example.com',8000,'SECRET-API-TOKEN',api=api))
        root=self.base/'cloudflare'; token=root/'tunnel.token'
        # A changed owned record and unrelated hostname survive removal.
        fake.dns.append({'id':'other','type':'A','name':'other.example.com','content':'1.2.3.4'})
        fake.dns[0]['content']='changed'
        messages=[]; asyncio.run(remove(self.config,api=api,say=messages.append))
        self.assertEqual(len(fake.dns),2); self.assertTrue(messages)
        self.assertFalse(token.exists()); self.assertFalse((root/'journal.json').exists())
        self.assertEqual(fake.dns[0]['content'],'changed')

    def test_remove_missing_record_completes(self):
        fake=FakeCloudflare(); api=fake.api()
        asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=api))
        fake.dns.clear()
        asyncio.run(remove(self.config,api=api,say=lambda _:None))
        self.assertEqual(fake.tunnels,[]); self.assertFalse((self.base/'cloudflare'/'journal.json').exists())

    def test_failed_token_fetch_rolls_back_dns_and_tunnel_then_retry(self):
        fake=FakeCloudflare(); api=fake.api(); fake.fail_token=True
        with self.assertRaises(Rejected) as raised: asyncio.run(expose_api(self.config,'herdr.example.com',8000,'API-SECRET',api=api))
        self.assertNotIn('API-SECRET',str(raised.exception)); self.assertNotIn('RUN-SECRET',str(raised.exception))
        self.assertEqual(fake.dns,[]); self.assertEqual(fake.tunnels,[])
        fake.fail_token=False
        self.assertEqual(asyncio.run(expose_api(self.config,'herdr.example.com',8000,'API-SECRET',api=api))['mode'],'api')

    def test_partial_tunnel_journal_resumes(self):
        fake=FakeCloudflare(); api=fake.api(); tunnel={'id':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','name':'dot-herdr-'+__import__('hashlib').sha256(str(self.config.absolute()).encode()).hexdigest()[:16]}
        fake.tunnels.append(tunnel)
        from dot_herdr.cloudflare import Journal
        Journal(self.config).write(self.journal_value())
        self.assertEqual(asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=api))['tunnel_id'],'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')

    def test_partial_tunnel_journal_rejects_missing_or_renamed_tunnel(self):
        from dot_herdr.cloudflare import Journal
        fake=FakeCloudflare(); api=fake.api(); tunnel={'id':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','name':'dot-herdr-'+__import__('hashlib').sha256(str(self.config.absolute()).encode()).hexdigest()[:16]}
        Journal(self.config).write(self.journal_value())
        with self.assertRaises(Rejected) as caught: asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=api))
        self.assertEqual(str(caught.exception),'cloudflare_owned_tunnel_missing')
        fake.tunnels.append({'id':tunnel['id'],'name':'foreign-name'})
        with self.assertRaises(Rejected) as caught: asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=api))
        self.assertEqual(str(caught.exception),'cloudflare_owned_tunnel_missing')

    def test_refuse_mode_or_hostname_confusion_before_network(self):
        j=cloudflare.Journal(self.config)
        j.write(self.journal_value('login'))
        fake=FakeCloudflare()
        with self.assertRaisesRegex(Rejected,'cloudflare_other_exposure_requires_remove'):
            asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=fake.api()))
        self.assertEqual(fake.calls,[])
        with self.assertRaisesRegex(Rejected,'cloudflare_other_exposure_requires_remove'):
            expose_login(self.config,'different.example.com',8000,cloudflared=str(self.binary),home=self.home)
        j.write(self.journal_value())
        with self.assertRaisesRegex(Rejected,'cloudflare_other_exposure_requires_remove'):
            expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),home=self.home)
        with self.assertRaisesRegex(Rejected,'cloudflare_other_exposure_requires_remove'):
            asyncio.run(expose_api(self.config,'different.example.com',8000,'x',api=fake.api()))

    def test_api_remove_delete_failure_keeps_ownership_and_retry_finishes(self):
        fake=FakeCloudflare(); api=fake.api(); asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=api)); fake.fail_delete=True
        with self.assertRaises(Rejected) as caught: asyncio.run(remove(self.config,api=api))
        self.assertEqual(str(caught.exception),'cloudflare_tunnel_delete_failed_stop_dot_herdr_first')
        from dot_herdr.cloudflare import Journal
        self.assertIsNotNone(Journal(self.config).read()); self.assertIsNotNone(Journal(self.config).read()['tunnel'])
        fake.fail_delete=False; asyncio.run(remove(self.config,api=api)); self.assertIsNone(Journal(self.config).read())

    def test_login_notice_config_remove_and_command(self):
        home=self.base/'home'; cfdir=home/'.cloudflared'; cfdir.mkdir(parents=True)
        cert=cfdir/'cert.pem'; creds=cfdir/('12345678-1234-1234-1234-123456789abc.json')
        events=[]
        def fake_run(args,**kwargs):
            events.append(('call',list(args)))
            if args[-1]=='login':
                self.assertNotIn('capture_output',kwargs); self.assertNotIn('stdout',kwargs); self.assertNotIn('stderr',kwargs); self.assertEqual(kwargs['timeout'],900)
            if args[-1]=='login': cert.write_text('certificate')
            elif args[-2:] == ['create','dot-herdr-'+__import__('hashlib').sha256(str(self.config.absolute()).encode()).hexdigest()[:16]]:
                creds.write_text('{}')
                return type('R',(),{'returncode':0,'stdout':'Created tunnel 12345678-1234-1234-1234-123456789abc'})()
            return type('R',(),{'returncode':0,'stdout':self.ownership() if 'list' in args else ''})()
        def say(text): events.append(('say',text))
        rec=expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=fake_run,say=say,home=home)
        self.assertEqual(events[0][0],'say'); self.assertIn(str(cert),events[0][1]); self.assertEqual(events[1][1][-1],'login')
        config=self.base/'cloudflare'/'config.yml'; self.assertEqual(stat.S_IMODE(config.stat().st_mode),0o600)
        cfg=json.loads(config.read_text()); self.assertEqual(cfg['ingress'][0]['originRequest']['httpHostHeader'],'herdr.example.com'); self.assertEqual(cfg['ingress'][-1]['service'],'http_status:404')
        self.assertEqual(expose_login(self.config,'herdr.example.com',8123,cloudflared=str(self.binary),run=fake_run,say=say,home=home),rec)
        cfg=json.loads(config.read_text()); self.assertEqual(cfg['ingress'][0]['service'],'http://127.0.0.1:8123')
        args,env=run_command(self.config,rec,str(self.binary)); self.assertEqual(args,[str(self.binary),'tunnel','--no-autoupdate','--config',str(config),'run',rec['tunnel_id']]); self.assertIn('PATH',env)
        asyncio.run(remove(self.config,cloudflared=str(self.binary),run=fake_run,say=say,home=home))
        self.assertTrue(cert.exists()); self.assertFalse(creds.exists()); self.assertFalse(config.exists())
        self.assertTrue(any(kind=='say' and 'Partial removal' in text for kind,text in events)); self.assertIsNotNone(cloudflare.Journal(self.config).read())
        self.assertIn(('say','Leaving Cloudflare account certificate in place: '+str(cert)),events)

    def test_login_remove_with_token_deletes_only_our_cname(self):
        from dot_herdr.cloudflare import Journal
        tunnel_id='12345678-1234-1234-1234-123456789abc'
        target=tunnel_id+'.cfargotunnel.com'
        for typ,content in [('CNAME',target),('CNAME','foreign.cfargotunnel.com'),
                            ('A','192.0.2.1'),('AAAA','2001:db8::1'),('CNAME',target+'.'),('A',target)]:
            with self.subTest(type=typ,content=content):
                home=self.base/'home'; cfdir=home/'.cloudflared'; cfdir.mkdir(parents=True,exist_ok=True)
                cert=cfdir/'cert.pem'; cert.write_text('certificate')
                creds=cfdir/(tunnel_id+'.json')
                calls=[]
                def fake_run(args,**kwargs):
                    calls.append(list(args))
                    if 'create' in args:
                        creds.write_text('{}')
                        return type('R',(),{'returncode':0,'stdout':'Created tunnel '+tunnel_id})()
                    if 'delete' in args:
                        self.assertIsNone(Journal(self.config).read()['dns'])
                        self.assertEqual(Journal(self.config).read()['tunnel']['id'],tunnel_id)
                    return type('R',(),{'returncode':0,'stdout':self.ownership() if 'list' in args else ''})()
                expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=fake_run,say=lambda _:None,home=home)
                fake=FakeCloudflare()
                record={'id':'route-dns','type':typ,'name':'herdr.example.com','content':content}
                unrelated={'id':'foreign','type':'CNAME','name':'other.example.com','content':target}
                fake.dns=[record,unrelated]
                notices=[]
                with patch('dot_herdr.cloudflare.CloudflareAPI',return_value=fake.api()) as factory:
                    asyncio.run(remove(self.config,token='API-SECRET',cloudflared=str(self.binary),run=fake_run,say=notices.append,home=home))
                factory.assert_called_once_with('API-SECRET')
                owned=typ=='CNAME' and content==target
                self.assertEqual(fake.dns,[unrelated] if owned else [record,unrelated])
                self.assertEqual([c[1] for c in fake.calls if c[0]=='DELETE'],
                                 ['/zones/zone1/dns_records/route-dns'] if owned else [])
                if not owned:
                    self.assertIn(f'Cloudflare DNS record herdr.example.com is now {typ} {content}; preserved it.',notices)
                self.assertFalse(any('Delete this CNAME manually' in line for line in notices))
                self.assertEqual(calls[-1],[str(self.binary),'tunnel','delete','-f',tunnel_id])
                self.assertTrue(cert.exists()); self.assertFalse(creds.exists())
                self.assertFalse((self.base/'cloudflare'/'config.yml').exists())
                self.assertIsNone(Journal(self.config).read())

    def test_login_remove_dns_journal_survives_tunnel_failure(self):
        from dot_herdr.cloudflare import Journal
        journal=Journal(self.config); tunnel_id='12345678-1234-1234-1234-123456789abc'
        value=self.journal_value('login',tid=tunnel_id); value['dns']={'id':None,'name':'herdr.example.com','content':tunnel_id+'.cfargotunnel.com'}; journal.write(value)
        fake=FakeCloudflare(); fake.dns=[{'id':'owned','type':'CNAME','name':'herdr.example.com','content':tunnel_id+'.cfargotunnel.com'}]
        def fail(args,**kwargs): return type('R',(),{'returncode':0 if 'list' in args else 1,'stdout':self.ownership() if 'list' in args else ''})()
        with self.assertRaises(Rejected):
            asyncio.run(remove(self.config,api=fake.api(),cloudflared=str(self.binary),run=fail,say=lambda _:None,home=self.home))
        self.assertEqual(fake.dns,[]); self.assertIsNone(journal.read()['dns'])
        self.assertEqual(journal.read()['tunnel']['id'],tunnel_id)
        calls=len(fake.calls)
        def succeed(args,**kwargs): return type('R',(),{'returncode':0,'stdout':self.ownership() if 'list' in args else ''})()
        asyncio.run(remove(self.config,api=fake.api(),cloudflared=str(self.binary),run=succeed,say=lambda _:None,home=self.home))
        self.assertEqual(len(fake.calls),calls); self.assertIsNone(journal.read())

    def test_login_route_failure_cleans_only_new_tunnel(self):
        home=self.base/'home'; (home/'.cloudflared').mkdir(parents=True)
        events=[]
        def failing(args,**kwargs):
            events.append(list(args))
            if 'create' in args:
                return type('R',(),{'returncode':0,'stdout':'Created tunnel aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'})()
            return type('R',(),{'returncode':1 if 'route' in args else 0,'stdout':''})()
        with self.assertRaises(Rejected) as raised: expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=failing,say=lambda _:None,home=home)
        self.assertNotIn('API-SECRET',str(raised.exception)); self.assertNotIn('RUN-SECRET',str(raised.exception))
        self.assertEqual(events[-1],[str(self.binary),'tunnel','delete','-f','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'])
        self.assertFalse((self.base/'cloudflare'/'journal.json').exists())

    def test_login_rollback_retains_journal_on_delete_failure_and_cleans_credentials_on_success(self):
        from dot_herdr.cloudflare import Journal
        home=self.base/'home'; cfdir=home/'.cloudflared'; cfdir.mkdir(parents=True)
        creds=cfdir/'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.json'
        def failed_delete(args,**kwargs):
            if 'create' in args:
                creds.write_text('{}')
                return type('R',(),{'returncode':0,'stdout':'Created tunnel aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'})()
            if 'route' in args: return type('R',(),{'returncode':1,'stdout':''})()
            if 'delete' in args: return type('R',(),{'returncode':1,'stdout':''})()
            return type('R',(),{'returncode':0,'stdout':self.ownership() if 'list' in args else ''})()
        with self.assertRaises(Rejected): expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=failed_delete,say=lambda _:None,home=home)
        retained=Journal(self.config).read()
        self.assertEqual(retained['tunnel']['id'],'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
        self.assertEqual(retained['credentials'],str(creds)); self.assertEqual(retained['phase'],'tunnel_created')
        self.assertTrue(creds.exists())
        Journal(self.config).remove()
        def successful_delete(args,**kwargs):
            if 'create' in args:
                creds.write_text('{}')
                return type('R',(),{'returncode':0,'stdout':'Created tunnel aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'})()
            if 'route' in args: return type('R',(),{'returncode':1,'stdout':''})()
            return type('R',(),{'returncode':0,'stdout':self.ownership() if 'list' in args else ''})()
        with self.assertRaises(Rejected): expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=successful_delete,say=lambda _:None,home=home)
        self.assertIsNone(Journal(self.config).read())
        self.assertFalse(creds.exists())

    def test_fake_cloudflared_executable_and_child_launch(self):
        home=self.home; cfdir=home/'.cloudflared'; cfdir.mkdir(parents=True)
        binary=self.base/'cloudflared'; log=self.base/'argv.log'
        script='''#!/bin/sh
printf '%s\\n' "$*" >> "ARGV_LOG"
case "$2" in
  list) echo '[{"id":"12345678-1234-1234-1234-123456789abc","name":"dot-herdr-INSTALL_ID"}]' ;;
  login) mkdir -p "$HOME/.cloudflared"; : > "$HOME/.cloudflared/cert.pem" ;;
  create) echo '{}' > "$HOME/.cloudflared/12345678-1234-1234-1234-123456789abc.json"; echo 'Created tunnel 12345678-1234-1234-1234-123456789abc' ;;
esac
if [ "$5" = run ]; then sleep 30; fi
'''
        binary.write_text(script.replace('INSTALL_ID',cloudflare.install_id(self.config)).replace('ARGV_LOG',str(log))); binary.chmod(0o700)
        def isolated_run(args,**kwargs):
            return subprocess.run(args,**kwargs)
        rec=expose_login(self.config,'herdr.example.com',8123,cloudflared=str(binary),run=isolated_run,say=lambda _:None,home=home)
        self.assertIn('tunnel login',log.read_text())
        args,env=run_command(self.config,rec,str(binary))
        child=subprocess.Popen(args,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            self.assertIsNone(child.poll())
        finally:
            child.terminate(); child.wait(timeout=5)
        asyncio.run(remove(self.config,cloudflared=str(binary),run=isolated_run,say=lambda _:None,home=home))
        self.assertTrue((cfdir/'cert.pem').exists())

    def test_run_command_api_shape(self):
        fake=FakeCloudflare()
        rec=asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=fake.api()))
        with patch.dict(os.environ,{'TUNNEL_TOKEN':'PARENT-SECRET'},clear=False):
            args,env=run_command(self.config,rec,str(self.binary))
        self.assertEqual(args,[str(self.binary),'tunnel','--no-autoupdate','run','--token-file',str(self.base/'cloudflare/tunnel.token')])
        self.assertIn('PATH',env); self.assertNotIn('TUNNEL_TOKEN',env)
        self.binary.write_text('#!/bin/sh\nexec sleep 30\n')
        child=subprocess.Popen(args,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            self.assertIsNone(child.poll())
        finally:
            child.terminate(); child.wait(timeout=5)

    def test_login_existing_cert_skips_login_and_discloses_path(self):
        home=self.base/'home'; cfdir=home/'.cloudflared'; cfdir.mkdir(parents=True); cert=cfdir/'cert.pem'; cert.write_text('cert')
        creds=cfdir/'12345678-1234-1234-1234-123456789abc.json'
        calls=[]
        def run(args,**kwargs):
            calls.append((args,kwargs))
            if 'create' in args:
                creds.write_text('{}')
                return type('R',(),{'returncode':0,'stdout':'Created tunnel 12345678-1234-1234-1234-123456789abc'})()
            return type('R',(),{'returncode':0,'stdout':self.ownership() if 'list' in args else ''})()
        notices=[]; expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=run,say=notices.append,home=home)
        self.assertEqual(calls[0][0],[str(self.binary),'tunnel','create','dot-herdr-'+__import__('hashlib').sha256(str(self.config.absolute()).encode()).hexdigest()[:16]])
        self.assertIn(str(cert),notices[0])

    def test_secret_hygiene_logs_errors_and_journal(self):
        fake=FakeCloudflare(); api=fake.api('API-SECRET'); records=[]
        class Capture(logging.Handler):
            def emit(self, record): records.append(record.getMessage())
        handler=Capture(); root=logging.getLogger(); root.addHandler(handler)
        try:
            asyncio.run(expose_api(self.config,'herdr.example.com',8000,'API-SECRET',api=api))
            asyncio.run(remove(self.config,api=api))
        finally: root.removeHandler(handler)
        self.assertFalse(any('API-SECRET' in line or 'run-token' in line for line in records))
        journal=self.base/'cloudflare'/'journal.json'
        self.assertNotIn('run-token',journal.read_text() if journal.exists() else '')


class CloudflareEvidence(unittest.TestCase):
    journal_value=CloudflareTests.journal_value
    ownership=CloudflareTests.ownership
    def setUp(self):
        CloudflareTests.setUp(self)
        (self.home / '.cloudflared').mkdir(parents=True)
        (self.home / '.cloudflared/cert.pem').write_text('fake-cert')
        self.tid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.creds = self.home / '.cloudflared' / (self.tid + '.json')

    def result(self, output='', returncode=0):
        return type('Result', (), {'stdout':output,'returncode':returncode})()

    def test_rejected_external_credentials_never_deleted(self):
        victim = self.base / 'unrelated.json'
        victim.write_text('unrelated file')
        def run(args, **kwargs):
            if 'create' in args:
                return self.result(f'Created tunnel {self.tid}\nTunnel credentials written to {victim}')
            return self.result(self.ownership() if 'list' in args else '')
        with self.assertRaises(Rejected):
            cloudflare.expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=run,home=self.home,say=lambda _:None)
        self.assertTrue(victim.exists(), 'rollback deleted the very path rejected as outside .cloudflared')

    def test_journal_cannot_delete_unrelated_local_files(self):
        victim = self.base / 'unrelated.txt'
        victim.write_text('preserve')
        j=cloudflare.Journal(self.config)
        cloudflare.cloudflare_root(self.config)
        value=self.journal_value(); value['files']=[str(victim)]
        j.path.write_text(json.dumps({'owner':'dot-herdr','version':2,**value})); j.path.chmod(0o600)
        fake=FakeCloudflare()
        with self.assertRaisesRegex(Rejected,'cloudflare_journal_untrusted'):
            asyncio.run(cloudflare.remove(self.config,api=fake.api()))
        self.assertEqual(fake.calls,[])
        self.assertTrue(victim.exists(), 'schema-unvalidated files list authorizes arbitrary unlink')

    def test_rerun_credentials_confined_and_private(self):
        victim = self.base / 'unrelated.json'
        victim.write_text('not tunnel credentials')
        cfg = cloudflare.cloudflare_root(self.config) / 'config.yml'
        j=cloudflare.Journal(self.config); cloudflare.cloudflare_root(self.config)
        value=self.journal_value('login'); value['credentials']=str(victim)
        j.path.write_text(json.dumps({'owner':'dot-herdr','version':2,**value})); j.path.chmod(0o600)
        try:
            cloudflare.expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=lambda *a,**k:self.result(),home=self.home)
        except Rejected:
            return
        self.fail('rerun accepted non-private credentials outside .cloudflared')

    def test_partial_login_journal_can_resume(self):
        self.creds.write_text('{}'); self.creds.chmod(0o600)
        cloudflare.Journal(self.config).write(self.journal_value('login'))
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            return self.result(self.ownership() if 'list' in args else '')
        try:
            cloudflare.expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=run,home=self.home)
        except Rejected as error:
            self.fail(f'valid partial journal cannot resume: {error}')

        self.assertEqual([args[-2] for args in calls if 'route' in args], [self.tid])
        self.assertEqual(cloudflare.Journal(self.config).read()['phase'],'complete')
        self.assertTrue((self.base/'cloudflare/config.yml').exists())

    def test_login_remove_deletes_owned_dns(self):
        calls, notices = [], []
        def run(args, **kwargs):
            calls.append(args)
            if 'create' in args:
                self.creds.write_text('{}'); self.creds.chmod(0o600)
                return self.result(f'Created tunnel {self.tid}')
            return self.result(self.ownership() if 'list' in args else '')
        cloudflare.expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=run,home=self.home,say=notices.append)
        asyncio.run(cloudflare.remove(self.config,cloudflared=str(self.binary),run=run,home=self.home,say=notices.append))
        value=cloudflare.Journal(self.config).read()
        self.assertIsNotNone(value)
        self.assertTrue(value['tunnel_removed']); self.assertIsNotNone(value['dns'])
        self.assertTrue(any('Partial removal' in text and self.tid+'.cfargotunnel.com' in text for text in notices))
        self.assertFalse(self.creds.exists())
        calls.clear()
        fake=FakeCloudflare(); fake.dns=[{'id':'route','type':'CNAME','name':'herdr.example.com','content':self.tid+'.cfargotunnel.com'}]
        asyncio.run(cloudflare.remove(self.config,api=fake.api(),run=run,home=self.home,say=notices.append))
        self.assertEqual(fake.dns,[]); self.assertIsNone(cloudflare.Journal(self.config).read()); self.assertEqual(calls,[])

    def test_login_creation_requires_private_credentials(self):
        def run(args, **kwargs):
            if 'create' in args:
                self.creds.write_text('{}'); self.creds.chmod(0o644)
                return self.result(f'Created tunnel {self.tid}')
            return self.result(self.ownership() if 'list' in args else '')
        try:
            cloudflare.expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=run,home=self.home,say=lambda _:None)
        except Rejected:
            return
        self.assertEqual(stat.S_IMODE(self.creds.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(self.creds.parent.stat().st_mode),0o700)


    def test_api_pagination_does_not_abandon_owned_tunnel(self):
        fake = FakeCloudflare()
        api = fake.api()
        asyncio.run(cloudflare.expose_api(self.config,'herdr.example.com',8000,'fake-token',api=api))
        owned = fake.tunnels.pop()
        fake.tunnels.extend({'id':f'foreign{i}','name':f'foreign{i}'} for i in range(100))
        fake.tunnels.append(owned)
        # ASGI wrapper models Cloudflare's paginated list without live requests.
        from starlette.responses import JSONResponse
        async def paginated(scope, receive, send):
            if scope['path'] == '/accounts/acct1/cfd_tunnels':
                params = parse_qs(scope.get('query_string',b'').decode())
                page = int(params.get('page',['1'])[0]); size = int(params.get('per_page',['100'])[0])
                response = JSONResponse({'success':True,'result':fake.tunnels[(page-1)*size:page*size],
                    'result_info':{'page':page,'per_page':size,'total_count':len(fake.tunnels),'total_pages':2}})
                await response(scope, receive, send)
            else:
                await fake.app(scope, receive, send)
        api = cloudflare.CloudflareAPI('fake-token',transport=httpx2.ASGITransport(app=paginated),base_url='http://test')
        asyncio.run(cloudflare.remove(self.config,api=api,say=lambda _:None))
        self.assertFalse(any(t['id'] == owned['id'] for t in fake.tunnels),
                         'first-page-only lookup abandoned owned live tunnel and erased journal')

    def test_run_command_rejects_option_as_tunnel_id(self):
        root = cloudflare.cloudflare_root(self.config)
        cfg = root / 'config.yml'; cfg.write_text('{}'); cfg.chmod(0o600)
        try:
            cloudflare.run_command(self.config,{'mode':'login','tunnel_id':'--token=untrusted-value'},'fake')
        except Rejected:
            return
        self.fail('unvalidated tunnel_id forwarded to cloudflared as an option')

    def test_login_removal_checks_current_tunnel_ownership(self):
        calls = []
        current_name = 'dot-herdr-' + cloudflare.install_id(self.config)
        def run(args, **kwargs):
            calls.append(args)
            if 'create' in args:
                self.creds.write_text('{}'); self.creds.chmod(0o600)
                return self.result(f'Created tunnel {self.tid}')
            if 'list' in args or 'info' in args:
                return self.result(json.dumps([{'id':self.tid,'name':current_name}]))
            return self.result(self.ownership() if 'list' in args else '')
        cloudflare.expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=run,home=self.home,say=lambda _:None)
        current_name = 'repurposed-by-owner'
        calls.clear()
        try:
            asyncio.run(cloudflare.remove(self.config,cloudflared=str(self.binary),run=run,home=self.home,say=lambda _:None))
        except Rejected:
            pass
        self.assertFalse(any('delete' in args for args in calls), 'renamed tunnel forcibly deleted without an ownership read')
        self.assertIsNotNone(cloudflare.Journal(self.config).read())
        self.assertTrue(self.creds.exists())


class CloudflareHardeningTests(unittest.TestCase):
    setUp = CloudflareEvidence.setUp
    journal_value = CloudflareTests.journal_value
    ownership = CloudflareTests.ownership
    result = CloudflareEvidence.result

    def provision(self):
        def run(args, **kwargs):
            if 'create' in args:
                self.creds.write_text('{}'); self.creds.chmod(0o600)
                return self.result('Created tunnel '+self.tid)
            return self.result(self.ownership() if 'list' in args else '')
        return expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),run=run,home=self.home,say=lambda _:None)

    def test_schema_rejects_each_invalid_field_before_mutation(self):
        j=cloudflare.Journal(self.config); j.write(self.journal_value())
        base=j.read()
        variants=[('version',1),('version',True),('mode','unknown'),('hostname','--bad'),
                  ('phase','anything'),('tunnel',None),('tunnel',{'id':self.tid,'name':'foreign'}),
                  ('tunnel',{'id':'--token=bad','name':'dot-herdr-'+cloudflare.install_id(self.config)}),
                  ('account','../acct'),('zone',{'id':'../zone','name':'example.com','account_id':'acct1'}),
                  ('token_file',str(self.base/'victim')),('cloudflared','cf'),('cloudflared','/tmp/bad\npath'),
                  ('cloudflared','/'+'x'*4096),('tunnel_removed',1),
                  ('dns',{'id':'dns','name':'other.example.com','content':self.tid+'.cfargotunnel.com'}),
                  ('dns',{'id':'dns','name':'herdr.example.com','content':'foreign.cfargotunnel.com'})]
        self.creds.write_text('not executable')
        fake=FakeCloudflare()
        for key,value in variants:
            with self.subTest(key=key,value=value):
                invalid={**base,key:value}; j.path.write_text(json.dumps(invalid)); before=j.path.read_bytes()
                with self.assertRaises(Rejected):
                    asyncio.run(remove(self.config,api=fake.api()))
                self.assertEqual(j.path.read_bytes(),before); self.assertEqual(fake.calls,[])
        for key in base:
            invalid=dict(base); del invalid[key]; j.path.write_text(json.dumps(invalid))
            with self.subTest(missing=key), self.assertRaises(Rejected): j.read()
        # Login paths must be exact even if another private owned file exists.
        base={'owner':'dot-herdr','version':2,**self.journal_value('login')}
        for key in ('credentials','config','home'):
            j.path.write_text(json.dumps({**base,key:str(self.base/'unrelated')}))
            with self.subTest(key=key), self.assertRaises(Rejected): j.read()

    def test_recorded_binary_is_validated_on_every_read(self):
        self.assertIsNone(cloudflare.recorded_cloudflared(self.config))
        j=cloudflare.Journal(self.config); j.write(self.journal_value())
        self.assertEqual(cloudflare.recorded_cloudflared(self.config),str(self.binary))
        self.binary.chmod(0o600)
        self.assertIsNone(cloudflare.recorded_cloudflared(self.config))
        self.binary.unlink()
        self.assertEqual(j.read()['cloudflared'],str(self.binary))

    def test_journal_survives_moved_cloudflared_and_remove_uses_new_path(self):
        fake=FakeCloudflare(); api=fake.api()
        rec=asyncio.run(expose_api(self.config,'herdr.example.com',8000,'SECRET-API-TOKEN',api=api))
        run_command(self.config,rec,str(self.binary))
        moved=self.base/'cloudflared-new'
        self.binary.rename(moved); moved.chmod(0o700)
        journal=cloudflare.Journal(self.config)
        self.assertIsNotNone(journal.read())
        self.assertIsNone(cloudflare.recorded_cloudflared(self.config))
        asyncio.run(expose_api(self.config,'herdr.example.com',8000,'SECRET-API-TOKEN',api=api,cloudflared=str(moved)))
        self.assertEqual(journal.read()['cloudflared'],str(moved))
        # The explicit path takes precedence even though the old journal path is gone.
        asyncio.run(remove(self.config,api=api,cloudflared=str(moved)))
        self.assertIsNone(journal.read())

    def test_rerun_and_launch_repair_credentials_and_reject_symlinks(self):
        rec=self.provision()
        self.creds.chmod(0o644)
        run_command(self.config,rec,str(self.binary))
        self.assertEqual(stat.S_IMODE(self.creds.stat().st_mode),0o600)
        self.creds.chmod(0o640)
        expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),home=self.home,run=lambda *a,**k:self.result(self.ownership()))
        self.assertEqual(stat.S_IMODE(self.creds.stat().st_mode),0o600)
        victim=self.base/'victim'; victim.write_text('preserved'); victim.chmod(0o644)
        self.creds.unlink(); self.creds.symlink_to(victim)
        for operation in (lambda:run_command(self.config,rec,str(self.binary)),
                          lambda:expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),home=self.home,run=lambda *a,**k:self.result(self.ownership()))):
            with self.assertRaises(Rejected): operation()
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode),0o644)
        self.creds.unlink(); self.creds.write_text('{}'); self.creds.chmod(0o600)
        directory=self.creds.parent; target=self.home/'real-cloudflared'; directory.rename(target); directory.symlink_to(target)
        with self.assertRaises(Rejected): run_command(self.config,rec,str(self.binary))
        with self.assertRaises(Rejected): expose_login(self.config,'herdr.example.com',8000,cloudflared=str(self.binary),home=self.home,run=lambda *a,**k:self.result(self.ownership()))

    def test_credentials_reject_nonregular_foreign_owner_and_failed_repair(self):
        rec=self.provision()
        self.creds.unlink(); os.mkfifo(self.creds)
        with self.assertRaises(Rejected): run_command(self.config,rec,str(self.binary))
        self.creds.unlink(); self.creds.write_text('{}'); self.creds.chmod(0o644)
        real_fchmod=os.fchmod
        def fail_repair(fd, mode):
            if mode == 0o600: raise OSError('repair refused')
            return real_fchmod(fd,mode)
        with patch('dot_herdr.cloudflare.os.fchmod',side_effect=fail_repair):
            with self.assertRaises(Rejected): run_command(self.config,rec,str(self.binary))
        real_fstat=os.fstat
        def other_owner(fd):
            st=real_fstat(fd)
            if stat.S_ISREG(st.st_mode):
                fields=list(st); fields[4]=os.getuid()+1; return os.stat_result(fields)
            return st
        with patch('dot_herdr.cloudflare.os.fstat',side_effect=other_owner):
            with self.assertRaises(Rejected): cloudflare._credentials(self.creds,self.home)
        # A symlink in HOME's ancestors is rejected as well.
        alias=self.base/'alias'; alias.symlink_to(self.home,target_is_directory=True)
        with self.assertRaises(Rejected): cloudflare._credentials(alias/'.cloudflared'/self.creds.name,alias)

    def test_run_requires_matching_canonical_uuid_mode_and_complete_journal(self):
        rec=self.provision()
        for change in ({'tunnel_id':'--token=untrusted-value'}, {'tunnel_id':self.tid.upper()},
                       {'tunnel_id':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}, {'mode':'api'}, {'mode':'unknown'}):
            with self.subTest(change=change),self.assertRaises(Rejected): run_command(self.config,{**rec,**change},str(self.binary))
        j=cloudflare.Journal(self.config); value=j.read(); value['phase']='tunnel_created'; j.write(value)
        with self.assertRaises(Rejected): run_command(self.config,rec,str(self.binary))

    def test_lookup_failure_retains_journal_and_404_is_authoritative(self):
        fake=FakeCloudflare(); rec=asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=fake.api()))
        j=cloudflare.Journal(self.config); before=j.path.read_bytes()
        async def unavailable(scope,receive,send):
            if scope['path'].endswith('/'+rec['tunnel_id']):
                await JSONResponse({'success':False},status_code=503)(scope,receive,send)
            else: await fake.app(scope,receive,send)
        api=CloudflareAPI('x',transport=httpx2.ASGITransport(app=unavailable),base_url='http://test')
        with self.assertRaises(Rejected): asyncio.run(remove(self.config,api=api))
        self.assertEqual(j.path.read_bytes(),before)
        self.assertFalse(any(method=='DELETE' for method,path,body in fake.calls))
        with self.assertRaises(Rejected): asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=api))
        async def malformed(req):
            return JSONResponse({'success':True,'result':None})
        bad=CloudflareAPI('x',transport=httpx2.ASGITransport(app=Starlette(routes=[Route('/{path:path}',malformed)])),base_url='http://test')
        with self.assertRaises(Rejected): asyncio.run(remove(self.config,api=bad))
        self.assertEqual(j.path.read_bytes(),before)
        fake.tunnels.clear()
        asyncio.run(remove(self.config,api=fake.api()))
        self.assertIsNone(j.read()); self.assertEqual(fake.dns,[])

    def test_paginated_conflict_detection_and_incomplete_enumeration(self):
        fake=FakeCloudflare()
        fake.tunnels=[{'id':str(uuid.UUID(int=i+1)),'name':'foreign'} for i in range(100)]
        fake.tunnels.append({'id':self.tid,'name':'dot-herdr-'+cloudflare.install_id(self.config)})
        pages=[]
        async def paginated(scope,receive,send):
            if scope['path']=='/accounts/acct1/cfd_tunnels':
                page=int(parse_qs(scope['query_string'].decode())['page'][0]); pages.append(page)
                await JSONResponse({'success':True,'result':fake.tunnels[(page-1)*100:page*100],
                    'result_info':{'page':page,'total_pages':2,'total_count':101}})(scope,receive,send)
            else: await fake.app(scope,receive,send)
        api=CloudflareAPI('x',transport=httpx2.ASGITransport(app=paginated),base_url='http://test')
        with self.assertRaisesRegex(Rejected,'cloudflare_foreign_tunnel_exists'):
            asyncio.run(expose_api(self.config,'herdr.example.com',8000,'x',api=api))
        self.assertEqual(pages,[1,2]); self.assertFalse(any(c[0]=='POST' for c in fake.calls))
        for metadata,result in [({'page':1,'total_pages':2,'total_count':101},[]),
                                 ({'page':1,'total_pages':1,'total_count':101},fake.tunnels[:100]),
                                 ({'page':2,'total_pages':2,'total_count':101},[]),
                                 ({'page':1},[])]:
            async def incomplete(req):
                return JSONResponse({'success':True,'result':result,'result_info':metadata})
            api=CloudflareAPI('x',transport=httpx2.ASGITransport(app=Starlette(routes=[Route('/{path:path}',incomplete)])),base_url='http://test')
            with self.subTest(metadata=metadata),self.assertRaisesRegex(Rejected,'cloudflare_incomplete_enumeration'):
                asyncio.run(api.list_tunnels('acct1'))

    def test_login_ownership_read_failure_and_oversized_output_keep_journal(self):
        self.provision(); j=cloudflare.Journal(self.config); before=j.path.read_bytes()
        for result in (self.result('not json'),self.result('[]'),self.result('',1),self.result('x'*(cloudflare.MAX_RESPONSE+1))):
            calls=[]
            def run(args,**kwargs): calls.append(args); return result
            with self.assertRaises(Rejected): asyncio.run(remove(self.config,run=run,home=self.home))
            self.assertFalse(any('delete' in args for args in calls)); self.assertEqual(j.path.read_bytes(),before)


class CloudflareBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = self.base / 'config.json'
        self.home = self.base / 'home'
        self.binary = self.base / 'cloudflared'
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        self.binary.chmod(0o700)

    def test_all_cloudflared_launches_scrub_credential_environment(self):
        names = ('CLOUDFLARE_API_TOKEN', 'CF_API_TOKEN', 'TUNNEL_TOKEN',
                 'TUNNEL_TOKEN_FILE', 'TUNNEL_ORIGIN_CERT',
                 'CONTROL_PLANE_API_KEY', 'CONTROL_PLANE_ADMIN_API_KEY')
        observed = {}
        def fake_run(args, **kwargs):
            # This is exactly subprocess inheritance when env is omitted.
            effective = kwargs.get('env', os.environ)
            observed[tuple(args)] = sorted(k for k in names if k in effective)
            return subprocess.CompletedProcess(args, 0, stdout='cloudflared version synthetic', stderr='')
        with patch.dict(os.environ, {k: 'synthetic-secret' for k in names}):
            cloudflare.detect_cloudflared(which=lambda _: str(self.binary), run=fake_run)
            cloudflare._command(fake_run, [str(self.binary), 'tunnel', 'list', '-o', 'json'])
            supervised = sorted(k for k in names if k in cloudflare._child_env())
        leaks = {str(k): v for k, v in observed.items() if v}
        if supervised:
            leaks['supervised run'] = supervised
        self.assertFalse(leaks, 'credential variable names inherited by cloudflared: ' + repr(leaks))

    def test_partial_login_resume_refuses_repurposed_tunnel_before_dns_write(self):
        directory = self.home / '.cloudflared'
        directory.mkdir(parents=True, mode=0o700)
        (directory / ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' + '.json')).write_text('{}')
        (directory / ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' + '.json')).chmod(0o600)
        journal = cloudflare.Journal(self.config, home=self.home)
        value = cloudflare._record(journal, 'login', 'herdr.example.com', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', str(self.binary))
        journal.write(value)
        before = journal.path.read_bytes()
        name = value['tunnel']['name']
        # The old tunnel is renamed; a foreign tunnel now uses the expected name.
        tunnels = [{'id': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'name': 'repurposed'}, {'id': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'name': name}]
        writes = []
        def fake_run(args, **kwargs):
            if 'list' in args:
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(tunnels))
            if 'route' in args:
                chosen = next(t for t in tunnels if t['name'] == args[-2])
                writes.append((args[-1], chosen['id']))
            return subprocess.CompletedProcess(args, 0, stdout='')
        rejected = False
        try:
            cloudflare.expose_login(self.config, 'herdr.example.com', 8000, cloudflared=str(self.binary),
                                    run=fake_run, say=lambda _: None, home=self.home)
        except Rejected:
            rejected = True
        self.assertEqual(writes, [], 'resume routed DNS to a foreign tunnel selected by name')
        self.assertTrue(rejected, 'resume must reject changed tunnel ownership')
        self.assertEqual(journal.path.read_bytes(), before)


    def test_allowlist_applies_to_login_lifecycle_and_run_command(self):
        tid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        hostname = 'herdr.example.com'
        preserved = {key: 'synthetic-setting' for key in (
            'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TMPDIR',
            'XDG_CONFIG_HOME', 'XDG_RUNTIME_DIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
            'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy')}
        preserved.update(HOME=str(self.home), PATH=os.environ.get('PATH', '/usr/bin:/bin'))
        ambient = dict(preserved, UNREVIEWED='drop', LC_SECRET='drop',
                       LC_API_KEY='drop', LC_TOKEN='drop', lc_secret='drop',
                       CONTROL_PLANE_ADMIN_API_KEY='drop', TUNNEL_ORIGIN_CERT='drop')
        calls = []
        def fake_run(args, **kwargs):
            self.assertEqual(kwargs.get('env'), preserved)
            calls.append(args)
            output = ''
            if 'login' in args:
                directory = self.home / '.cloudflared'
                directory.mkdir(parents=True, mode=0o700)
                (directory / 'cert.pem').write_text('synthetic-cert')
            if 'create' in args:
                credentials = self.home / '.cloudflared' / (tid + '.json')
                credentials.write_text('{}')
                credentials.chmod(0o600)
                output = 'Created tunnel ' + tid
            if 'list' in args:
                output = json.dumps([{'id': tid, 'name': 'dot-herdr-' + cloudflare.install_id(self.config)}])
            if 'route' in args:
                self.assertEqual(args[-2], tid)
                self.assertIsNone(cloudflare.Journal(self.config).read()['dns'])
            return subprocess.CompletedProcess(args, 0, stdout=output)
        with patch.dict(os.environ, ambient, clear=True):
            cloudflare.detect_cloudflared(which=lambda _: str(self.binary), run=fake_run)
            record = expose_login(self.config, hostname, 8000, cloudflared=str(self.binary),
                                  run=fake_run, say=lambda _: None, home=self.home)
            self.assertEqual(run_command(self.config, record, str(self.binary))[1], preserved)
            expose_login(self.config, hostname, 8001, cloudflared=str(self.binary),
                         run=fake_run, say=lambda _: None, home=self.home)
            cloudflare._command(fake_run, [str(self.binary), 'tunnel', 'info', tid])
            asyncio.run(remove(self.config, cloudflared=str(self.binary), run=fake_run,
                               say=lambda _: None, home=self.home))
        for command in ('--version', 'login', 'create', 'route', 'list', 'info', 'delete'):
            self.assertTrue(any(command in args for args in calls), command)

    def test_resume_all_phases_refuse_missing_renamed_or_unverified_tunnel(self):
        tid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        journal = cloudflare.Journal(self.config, home=self.home)
        value = cloudflare._record(journal, 'login', 'herdr.example.com', tid, str(self.binary))
        credentials = self.home / '.cloudflared' / (tid + '.json')
        credentials.parent.mkdir(parents=True, mode=0o700)
        credentials.write_text('{}')
        credentials.chmod(0o644)
        config = cloudflare.cloudflare_root(self.config) / 'config.yml'
        config.write_text('preserve existing config')
        config.chmod(0o600)
        for phase in ('tunnel_created', 'dns_routed', 'complete'):
            value['phase'] = phase
            if phase != 'tunnel_created':
                value['dns'] = {'id': None, 'name': value['hostname'], 'content': tid + '.cfargotunnel.com'}
            journal.write(value)
            before = journal.path.read_bytes()
            for output, rc in (('[]', 0), ('not json', 0), ('', 1),
                               (json.dumps([{'id': tid, 'name': 'repurposed'}]), 0)):
                with self.subTest(phase=phase, output=output):
                    calls = []
                    def fake_run(args, **kwargs):
                        calls.append(args)
                        return subprocess.CompletedProcess(args, rc, stdout=output)
                    with self.assertRaises(Rejected):
                        expose_login(self.config, value['hostname'], 8001,
                                     cloudflared=str(self.binary), run=fake_run,
                                     home=self.home, say=lambda _: None)
                    self.assertEqual([args[2] for args in calls], ['list'])
                    self.assertEqual(journal.path.read_bytes(), before)
                    self.assertEqual(config.read_text(), 'preserve existing config')
                    self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o644)


if __name__=='__main__': unittest.main()
