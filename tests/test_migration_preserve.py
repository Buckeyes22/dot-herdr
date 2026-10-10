"""Migration receipt and replacement regressions."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.connections import NAME,connection_record,migrate_connection,prepare_connections,save_connection
from dot_herdr.core import Rejected
from dot_herdr.onboarding import save_config


class MigrationPreserveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name);self.home.chmod(0o700)
        self.config=self.home/'config.json';self.cfg={'store':str(self.home/'store.sqlite'),'socket':str(self.home/'source.sock'),'issuer':'https://auth.example.test','resource':'https://connector.example.test/mcp','public_key':str(self.home/'key.pem'),'subjects':[],'session_users':['user']}
        save_config(self.config,self.cfg)
        initial=prepare_connections(self.cfg,home=self.home,codex_home=self.home/'.codex',wiring='plugin-http',launch=False,say=lambda _:None)
        record=connection_record(self.config);record.update(route='https',wiring='plugin-http',client_app='desktop',endpoint=self.cfg['resource'],owned=initial['owned']);save_connection(self.config,record)
        self.skill=self.home/'.codex/plugins'/NAME/'skills/herdr-connector/SKILL.md'
    def tearDown(self):self.temp.cleanup()
    def migrate(self):return migrate_connection(self.config,'https','registered-plugin',app_id='plugin_asdk_app_fixture',client_app='desktop',home=self.home,codex_home=self.home/'.codex',launch=False,say=lambda _:None)
    def test_unreceipted_payload_file_remains_byte_identical(self):
        record=connection_record(self.config);del record['owned']['plugin_files'][str(self.skill)];save_connection(self.config,record)
        self.skill.write_bytes(b'USER CONTENT THAT MUST BE PRESERVED\n')
        try:result=self.migrate()
        except Rejected as error:
            self.assertIn(str(self.skill),str(error));self.assertEqual(self.skill.read_bytes(),b'USER CONTENT THAT MUST BE PRESERVED\n');return
        self.assertIn(str(self.skill),result['preserved']);self.assertEqual(self.skill.read_bytes(),b'USER CONTENT THAT MUST BE PRESERVED\n')

    def test_receipted_file_changed_during_preparation_is_not_replaced(self):
        from dot_herdr import connections
        original=connections.write_file;changed=False
        def race(path,body,previous=None,backup=True):
            nonlocal changed
            if Path(path)==self.skill and not changed:
                self.skill.write_bytes(b'RACE CONTENT\n');changed=True
            return original(path,body,previous,backup)
        with patch('dot_herdr.connections.write_file',side_effect=race):
            with self.assertRaises(Rejected):self.migrate()
        self.assertTrue(changed);self.assertEqual(self.skill.read_bytes(),b'RACE CONTENT\n')
