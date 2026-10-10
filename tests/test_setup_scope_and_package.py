import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.connections import connection_record,save_connection
from dot_herdr.onboarding import confirm_candidate,save_config
from dot_herdr.connection_check import check_connection
from dot_herdr.status import status,render
from dot_herdr.auth import record_verified_scopes
from dot_herdr.endpoint import principal_key


class SetupScopeAndPackageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=self.root/'config.json'
        self.cfg={'store':str(self.root/'state.sqlite'),'socket':str(self.root/'source.sock'),
                  'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp',
                  'public_key':str(self.root/'key.pem'),'subjects':[], 'session_users':['user']}
        save_config(self.config,self.cfg)

    async def test_approval_explains_missing_control_scope(self):
        lines=[]
        selected=await confirm_candidate([{'subject':'user','principal':'principal','scopes':['herdr:observe']}],
            self.cfg['issuer'],lambda _: 'y',lines.append,control_selected=True)
        self.assertEqual(selected,'principal')
        self.assertEqual(len([line for line in lines if 'This sign-in allows observation only.' in line]),1)

    async def test_status_shows_last_verified_scopes(self):
        now=__import__('time').time();record=connection_record(self.config);record.update(approved_client_id='approved',verified_client_scopes={'approved':{'scopes':['herdr:observe'],'verified_at':now,'expires_at':now+120}},identity='principal');save_connection(self.config,record)
        with patch('dot_herdr.status.port_in_use',return_value=False):report=await status(self.config)
        self.assertIn('account access: observe only (control selected but not granted at sign-in)',render(report))

    async def test_check_connection_stops_before_target_without_control_scope(self):
        now=__import__('time').time();record=connection_record(self.config);record.update(approved_client_id='approved',verified_client_scopes={'approved':{'scopes':['herdr:observe'],'verified_at':now,'expires_at':now+120}});save_connection(self.config,record)
        lines=[]
        with patch('dot_herdr.connection_check.status',return_value={'mode':'offline_read_only','observations':{}}):
            result=await check_connection(self.config,ask=lambda _:self.fail('prompted'),say=lines.append)
        self.assertEqual(result['phase'],'control_scope')
        self.assertEqual(len(lines),1)
        self.assertIn('Also allow Herdr control',lines[0])

    async def test_authenticated_request_refreshes_only_approved_account_scope_names(self):
        principal=principal_key(self.cfg['issuer'],'user')
        record=connection_record(self.config);record.update(identity=principal,approved_client_id='approved');save_connection(self.config,record)
        class Token:
            subject='user';claims={'iss':self.cfg['issuer']};scopes=['herdr:observe','herdr:control']
            token='secret-token-bytes';client_id='approved';expires_at=__import__('time').time()+120
        record_verified_scopes(self.config,Token())
        self.assertEqual(connection_record(self.config)['verified_client_scopes']['approved']['scopes'],['herdr:control','herdr:observe'])
        self.assertNotIn('secret-token-bytes',self.config.with_name(self.config.name+'.connection.json').read_text())
        with patch('dot_herdr.status.port_in_use',return_value=False):report=await status(self.config)
        self.assertIn('account access: observe+control',render(report))
        Token.subject='different-user';Token.scopes=['herdr:observe']
        record_verified_scopes(self.config,Token())
        self.assertEqual(connection_record(self.config)['verified_client_scopes']['approved']['scopes'],['herdr:control','herdr:observe'])
