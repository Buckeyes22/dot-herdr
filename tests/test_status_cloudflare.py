"""Cloudflare status and live advice use local fakes only."""
import asyncio
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from dot_herdr.login import public_metadata_status
from dot_herdr.status import cloudflared_observation, overall, render
from dot_herdr.cloudflare import expose_api, expose_login
from dot_herdr import cloudflare
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_cloudflare import FakeCloudflare


class CloudflareStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=self.root/'config.json'
        self.exposure={'provider':'cloudflare','hostname':'chat.example.test','tunnel_id':'12345678-1234-1234-1234-123456789abc','mode':'api'}

    def _api_exposure(self):
        fake=FakeCloudflare()
        binary=self.root/'cloudflared';binary.write_text('#!/bin/sh\nexit 0\n');binary.chmod(0o700)
        with patch('dot_herdr.cloudflare.shutil.which',return_value=str(binary)):
            return asyncio.run(expose_api(self.config,'chat.example.test',8000,'synthetic-token',api=fake.api()))

    def _login_exposure(self):
        login_root=self.root/'login';login_root.mkdir()
        config=login_root/'config.json'
        home=self.root/'home';cfdir=home/'.cloudflared';cfdir.mkdir(parents=True)
        binary=self.root/'cloudflared';binary.write_text('#!/bin/sh\nexit 0\n');binary.chmod(0o700)
        tid='12345678-1234-1234-1234-123456789abc'
        def run(args,**kwargs):
            if 'create' in args:
                (cfdir/(tid+'.json')).write_text('{}');(cfdir/(tid+'.json')).chmod(0o600)
                return subprocess.CompletedProcess(args,0,'Created tunnel '+tid,'')
            return subprocess.CompletedProcess(args,0,'','')
        return config,expose_login(config,'chat.example.test',8000,cloudflared=str(binary),run=run,home=home)

    def test_exposure_controls_applicability_and_child_unknown_is_explicit(self):
        self.assertEqual(cloudflared_observation(self.config,{},{} )['state'],'not_applicable')
        self.assertNotIn('cloudflared:',render({'mode':'offline_read_only','overall':{},'observations':{'cloudflared':{'state':'not_applicable'}}}))
        self._api_exposure()
        with patch('shutil.which',return_value='/bin/sh'):
            value=cloudflared_observation(self.config,{'exposure':self.exposure},{})
        self.assertEqual(value['child'],'unknown')
        self.assertEqual(value['credential'],'present_private')
        self.assertEqual(value['binary'],'found')

    def test_api_and_login_credentials_require_private_mode_and_runtime_child(self):
        self._api_exposure()
        token=self.root/'cloudflare'/'tunnel.token';token.chmod(0o644)
        journal=cloudflare.Journal(self.config).read()
        (self.root/'cloudflared').unlink()
        with patch.object(cloudflare.Journal,'read',return_value=journal), patch('shutil.which',return_value=None):
            value=cloudflared_observation(self.config,{'exposure':self.exposure},{'cloudflared':'running'})
        self.assertEqual((value['binary'],value['credential'],value['child']),('missing','missing_or_not_private','running'))
        config,record=self._login_exposure()
        with patch.dict(os.environ,{'HOME':str(self.root/'home')}), patch('shutil.which',return_value='/bin/sh'):
            value=cloudflared_observation(config,{'exposure':record},{'cloudflared':'running'})
        self.assertEqual(value['credential'],'present_private')
        self.assertEqual(set(value['credential_files']),{'config','credentials'})
        self.assertEqual(value['state'],'ready')

    def test_journal_recorded_binary_precedes_path_lookup(self):
        record=self._api_exposure()
        with patch('shutil.which',side_effect=AssertionError('PATH must not be queried')):
            value=cloudflared_observation(self.config,{'exposure':record},{'cloudflared':'running'})
        self.assertEqual(value['binary_path'],str(self.root/'cloudflared'))

    def test_moved_binary_reports_missing_and_install_docs_action(self):
        self._api_exposure()
        journal=cloudflare.Journal(self.config).read()
        (self.root/'cloudflared').unlink()
        # The merged base's round 4 journal behavior treats this still-valid
        # record as readable and recorded_cloudflared() then returns None.
        with patch.object(cloudflare.Journal,'read',return_value=journal):
            with patch('shutil.which',return_value=None):
                value=cloudflared_observation(self.config,{'exposure':self.exposure},{'cloudflared':'stopped'})
        self.assertEqual(value['binary'],'missing')
        self.assertIn('https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/',value['next_action'])

    def test_untrusted_journal_is_reported(self):
        self._api_exposure()
        journal=self.root/'cloudflare'/'journal.json'
        journal.write_text('{}');journal.chmod(0o600)
        value=cloudflared_observation(self.config,{'exposure':self.exposure},{})
        self.assertEqual(value['state'],'journal_invalid')
        self.assertTrue(value['next_action'])

    def _cfg(self):
        return {'resource':'https://chat.example.test/mcp','issuer':'https://auth.example.test'}

    def _probe(self, code, headers, body):
        class Response:
            def __init__(self):self.status=code;self.headers=headers
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):self.n=n;return body
        response=Response()
        with patch('dot_herdr.login.build_opener') as make:
            make.return_value.open.return_value=response
            return public_metadata_status(self._cfg(),'https://chat.example.test/mcp',details=True),response

    def test_cloudflare_challenge_header_and_page_marker_advice(self):
        status,_=self._probe(403,{'cf-mitigated':'challenge'},b'')
        self.assertEqual(status[0:2],('reachable (HTTP 403)',False))
        self.assertIn('Cloudflare\'s bot protection is blocking requests to chat.example.test',status[2])
        status,_=self._probe(403,{'server':'cloudflare'},b'<html>Just a moment...</html>')
        self.assertIn('dot-herdr never changes zone security settings',status[2])

    def test_530_1033_524_and_bounded_error_body(self):
        for code,body,phrase in ((530,b'', 'tunnel is down'),(200,b'Error code: 1033','tunnel is down'),(524,b'', 'HTTP 524')):
            status,response=self._probe(code,{},body)
            self.assertIn(phrase,status[2])
            self.assertLessEqual(response.n,65537)
        self.assertEqual(len(self._probe(200,{},b'x'*65537)[0]),3)

    def test_http_error_body_classifies_and_legacy_shape_is_unchanged(self):
        error=HTTPError('https://chat.example.test/meta',524,'timeout',{},None)
        error.read=lambda size:b''
        with patch('dot_herdr.login.build_opener') as make:
            make.return_value.open.side_effect=error
            self.assertEqual(public_metadata_status(self._cfg(),'https://chat.example.test/mcp'),('unreachable (HTTP 524)',False))
        error.close()

    def test_r2_1_http_error_body_timeout_returns_failure(self):
        cfg=self._cfg()
        error=HTTPError(cfg['resource'],524,'timeout',{},io.BytesIO(b''))
        with patch('dot_herdr.login.build_opener') as make, patch.object(error,'read',side_effect=TimeoutError('synthetic body timeout')):
            make.return_value.open.side_effect=error
            result=public_metadata_status(cfg,cfg['resource'],details=True)
        self.assertEqual(result,('unreachable (HTTP 524)',False,None))
        self.assertTrue(error.fp.closed)

    def test_advice_is_overall_action_and_rendered(self):
        checks={'configuration':{'state':'valid_shape'},'runtime':{'state':'running'},'listener':{'state':'managed'},
                'source':{'state':'compatible'},
                'route':{'public_reachability':'unreachable (HTTP 403)','url':'https://chat.example.test/mcp',
                         'cloudflare_advice':'Cloudflare advice for this hostname.'},
                'discovery':{'state':'unavailable'},'authentication':{'account_access':'unknown'}}
        with patch('dot_herdr.status.placeholders',return_value=False):
            verdict=overall(checks,{'local_port':8000},True)
        self.assertEqual(verdict['next_action'],'Cloudflare advice for this hostname.')
        self.assertIn('Overall: ',render({'mode':'live_read_only','overall':verdict,'observations':{}}))
