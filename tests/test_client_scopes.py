"""Verified scope evidence belongs to the approved OAuth client."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.auth import record_verified_scopes
from dot_herdr.connection_check import check_connection
from dot_herdr.connections import connection_record,save_connection
from dot_herdr.endpoint import PairingSession,principal_key
from dot_herdr.onboarding import save_config
from dot_herdr.status import account_access,status,render


class ClientScopeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.config=self.root/'config.json'
        self.cfg={'store':str(self.root/'store.sqlite'),'socket':str(self.root/'source.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(self.root/'key.pem'),'subjects':[],'session_users':['user']}
        save_config(self.config,self.cfg)
        record=connection_record(self.config);record.update(identity=principal_key(self.cfg['issuer'],'user'),approved_client_id='approved-client');save_connection(self.config,record)
    def tearDown(self):self.temp.cleanup()
    def token(self,client,scopes,expiry=None):
        return type('Token',(),{'subject':'user','claims':{'iss':self.cfg['issuer']},'client_id':client,'scopes':scopes,'expires_at':expiry or time.time()+120})()
    def test_pairing_confirmation_carries_verified_client(self):
        pairing=PairingSession(self.cfg['issuer'])
        pairing.observe(self.token('approved-client',['herdr:observe','herdr:control']))
        approved=pairing.confirm(principal_key(self.cfg['issuer'],'user'))
        self.assertEqual(approved['client_id'],'approved-client')
        self.assertEqual(approved['scopes'],['herdr:control','herdr:observe'])
    async def test_newest_client_controls_gate_and_each_client_remains_labelled(self):
        record_verified_scopes(self.config,self.token('approved-client',['herdr:observe','herdr:control']))
        record_verified_scopes(self.config,self.token('other-client',['herdr:observe']))
        record=connection_record(self.config)
        self.assertEqual(record['verified_client_scopes']['approved-client']['scopes'],['herdr:control','herdr:observe'])
        self.assertEqual(record['verified_client_scopes']['other-client']['scopes'],['herdr:observe'])
        self.assertIn(account_access(self.cfg,record),('observe+control','observe only (control selected but not granted at sign-in)'))
        with patch('dot_herdr.status.port_in_use',return_value=False):report=await status(self.config)
        observed=report['observations']['authentication']
        self.assertEqual(observed['approved_client_id'],'approved-client')
        self.assertEqual(len(observed['scope_clients']),2)
        self.assertEqual({e['client_id']:e['scopes'] for e in observed['scope_clients']},{'approved-client':['herdr:control','herdr:observe'],'other-client':['herdr:observe']})
        self.assertLess(observed['scope_verified_at'],observed['scope_expires_at'])
        with patch('dot_herdr.connection_check.status',return_value={}):result=await check_connection(self.config,interactive=False,say=lambda _:None)
        self.assertEqual(result['phase'],'control_scope' if observed['scope_client_id']=='other-client' else 'test_target')
    async def test_expired_or_missing_approved_evidence_uses_newest_current_client(self):
        record_verified_scopes(self.config,self.token('other-client',['herdr:observe']))
        record=connection_record(self.config)
        self.assertEqual(account_access(self.cfg,record),'observe only (control selected but not granted at sign-in)')
        messages=[]
        with patch('dot_herdr.connection_check.status',return_value={}):result=await check_connection(self.config,interactive=False,say=messages.append)
        self.assertEqual(result['phase'],'control_scope')
        record_verified_scopes(self.config,self.token('approved-client',['herdr:observe'],time.time()-1))
        self.assertEqual(account_access(self.cfg,connection_record(self.config)),'observe only (control selected but not granted at sign-in)')
    async def test_legacy_approval_without_client_id_displays_current_identity_clients(self):
        record=connection_record(self.config);record.pop('approved_client_id');save_connection(self.config,record)
        record_verified_scopes(self.config,self.token('first-client',['herdr:observe']))
        record_verified_scopes(self.config,self.token('new-client',['herdr:observe','herdr:control']))
        with patch('dot_herdr.status.port_in_use',return_value=False):report=await status(self.config)
        line=render(report)
        self.assertIn('approved client scopes: herdr:control, herdr:observe (client new-clie…)',line)
        self.assertIn('herdr:observe (client first-cl…)',line)
        self.assertEqual(report['observations']['authentication']['scope_client_id'],'new-client')
