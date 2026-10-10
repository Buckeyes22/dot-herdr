"""Route migration keeps user edits and can resume after a partial local handoff."""
import json
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr.connections import NAME,connection_record,migrate_connection,migration_entries,prepare_connections,save_connection
from dot_herdr.core import Rejected
from dot_herdr.onboarding import save_config


class RouteMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name);self.home.chmod(0o700)
        self.config=self.home/'config.json';self.resource='https://connector.example.test/mcp'
        self.cfg={'store':str(self.home/'store.sqlite'),'socket':str(self.home/'source.sock'),'issuer':'https://auth.example.test','resource':self.resource,'public_key':str(self.home/'key.pem'),'subjects':[{'key':'agent','user_subject':'user','owner':'operator','pane':'pane','terminal':'terminal','native':None,'content':False,'control':False}],'session_users':[]}
        save_config(self.config,self.cfg)
        plugin=prepare_connections(self.cfg,home=self.home,codex_home=self.home/'.codex',wiring='plugin-http',launch=False,say=lambda _:None)
        standalone=prepare_connections(self.cfg,home=self.home,codex_home=self.home/'.codex',wiring='standalone',launch=False,say=lambda _:None)
        record=connection_record(self.config);record.update(route='https',wiring='plugin-http',client_app='desktop',endpoint=self.resource,owned={**plugin['owned'],**standalone['owned']});save_connection(self.config,record)
    def tearDown(self):self.temp.cleanup()
    def migrate(self,**kwargs):return migrate_connection(self.config,'https','registered-plugin',home=self.home,codex_home=self.home/'.codex',launch=False,say=lambda _:None,**kwargs)
    def test_dual_installation_preserves_modified_and_unrelated_entries(self):
        plugin=self.home/'.codex/plugins'/NAME
        modified=plugin/'LICENSE';modified.write_text('user modification')
        unrelated=plugin/'notes.txt';unrelated.write_text('keep')
        catalog=self.home/'.agents/plugins/marketplace.json';value=json.loads(catalog.read_text());value['plugins'].append({'name':'other','source':'./other'});catalog.write_text(json.dumps(value))
        result=self.migrate(app_id='plugin_asdk_app_fixture')
        classified={(e['kind'],e['classification']) for e in result['entries']}
        self.assertIn(('plugin_file','owned-modified'),classified);self.assertIn(('plugin_file','unrelated'),classified)
        self.assertIn(('standalone','owned-unchanged'),classified);self.assertIn(('marketplace','unrelated'),classified)
        self.assertTrue(result['backups']);self.assertTrue(all(Path(p).exists() for p in result['backups']))
        self.assertIn(str(modified),result['preserved']);self.assertIn(str(unrelated),result['preserved'])
        self.assertIn(str(self.home/'.codex/config.toml')+'#'+NAME,result['removed'])
        self.assertNotIn(NAME,__import__('tomllib').loads((self.home/'.codex/config.toml').read_text()).get('mcp_servers',{}))
        self.assertEqual(modified.read_text(),'user modification');self.assertEqual(unrelated.read_text(),'keep')
        self.assertEqual(connection_record(self.config)['wiring'],'registered-plugin')
        self.assertFalse((plugin/'mcp.json').exists());self.assertTrue((plugin/'.app.json').exists())

    def test_target_collision_rejects_before_cleanup(self):
        plugin=self.home/'.codex/plugins'/NAME;(plugin/'mcp.json').write_text('user modified')
        old=(self.home/'.codex/config.toml').read_bytes()
        with self.assertRaisesRegex(Rejected,'migration_target_conflicts'):self.migrate(app_id='plugin_asdk_app_fixture')
        self.assertEqual((self.home/'.codex/config.toml').read_bytes(),old)
        self.assertNotIn('migration',connection_record(self.config))

    def test_modified_standalone_table_survives_other_route(self):
        path=self.home/'.codex/config.toml';path.write_text(path.read_text().replace('oauth_resource = ', 'custom = "keep"\noauth_resource = ')+'\n[mcp_servers.other]\nurl = "https://other.example.test/mcp"\n')
        result=self.migrate(app_id='plugin_asdk_app_fixture')
        self.assertIn(('standalone','owned-modified'),{(e['kind'],e['classification']) for e in result['entries']})
        self.assertIn(str(path)+'#'+NAME,result['preserved'])
        body=path.read_text();self.assertIn('custom = "keep"',body);self.assertIn('[mcp_servers.other]',body)

    def test_previous_registered_plugin_and_standalone_dual_installation(self):
        plugin=self.home/'.codex/plugins'/NAME
        (plugin/'mcp.json').unlink()
        result=prepare_connections(self.cfg,home=self.home,codex_home=self.home/'.codex',wiring='registered-plugin',app_id='plugin_asdk_app_fixture',launch=False,say=lambda _:None)
        record=connection_record(self.config);record.update(wiring='standalone',owned={**record['owned'],**result['owned']});save_connection(self.config,record)
        migrated=self.migrate(app_id='plugin_asdk_app_fixture')
        self.assertEqual(migrated['saved_wiring'],'registered-plugin')
        self.assertIn(str(self.home/'.codex/config.toml')+'#'+NAME,migrated['removed'])
        self.assertTrue((plugin/'.app.json').exists())

    def test_migrating_away_from_registered_plugin_clears_saved_mapping(self):
        plugin=self.home/'.codex/plugins'/NAME;(plugin/'mcp.json').unlink()
        result=prepare_connections(self.cfg,home=self.home,codex_home=self.home/'.codex',wiring='registered-plugin',app_id='plugin_asdk_app_fixture',launch=False,say=lambda _:None)
        record=connection_record(self.config);record.update(wiring='registered-plugin',app_id='plugin_asdk_app_fixture',owned={**record['owned'],**result['owned']});save_connection(self.config,record)
        migrate_connection(self.config,'https','plugin-http',home=self.home,codex_home=self.home/'.codex',launch=False,say=lambda _:None)
        self.assertNotIn('app_id',connection_record(self.config))
        self.assertFalse((plugin/'.app.json').exists());self.assertTrue((plugin/'mcp.json').exists())

    def test_resumes_after_interrupted_preparation(self):
        prepare=prepare_connections;calls=0
        def interrupt(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==2:raise Rejected('synthetic_interruption')
            return prepare(*args,**kwargs)
        with patch('dot_herdr.connections.prepare_connections',side_effect=interrupt):
            with self.assertRaisesRegex(Rejected,'synthetic_interruption'):self.migrate(app_id='plugin_asdk_app_fixture')
        self.assertIn('migration',connection_record(self.config))
        result=self.migrate(app_id='plugin_asdk_app_fixture')
        self.assertEqual(result['registration']['status'],'cloud_mapping_prepared')
        self.assertNotIn('migration',connection_record(self.config))

    def test_resumes_after_preparation_before_final_record_write(self):
        saved=save_connection;calls=0
        def interrupt(config,record):
            nonlocal calls
            calls+=1
            if calls==2:raise Rejected('synthetic_final_write_interruption')
            return saved(config,record)
        with patch('dot_herdr.connections.save_connection',side_effect=interrupt):
            with self.assertRaisesRegex(Rejected,'synthetic_final_write_interruption'):self.migrate(app_id='plugin_asdk_app_fixture')
        self.assertIn('migration',connection_record(self.config))
        self.migrate(app_id='plugin_asdk_app_fixture')
        self.assertEqual(connection_record(self.config)['wiring'],'registered-plugin')

    def test_connect_default_and_rejection_name_migration(self):
        from dot_herdr.cli import main
        record=connection_record(self.config);record.pop('route');record.pop('wiring');record.pop('endpoint');record.pop('owned');save_connection(self.config,record)
        args=['dot-herdr','connect','--config',str(self.config),'--no-open']
        with patch.object(sys,'argv',args),patch('dot_herdr.connections.Path.home',return_value=self.home),patch.dict(os.environ,{'CODEX_HOME':str(self.home/'.codex')}),patch('sys.stdout',new_callable=io.StringIO):main()
        self.assertEqual(connection_record(self.config)['wiring'],'registered-plugin')
        args+=['--wiring','standalone']
        with patch.object(sys,'argv',args),patch('sys.stderr',new_callable=io.StringIO) as error:
            with self.assertRaises(SystemExit):main()
        self.assertIn('dot-herdr migrate-route',error.getvalue())

    def test_noninteractive_migration_requires_full_selection_and_confirmation(self):
        from dot_herdr.cli import main
        args=['dot-herdr','migrate-route','--config',str(self.config),'--route','https','--wiring','registered-plugin']
        with patch.object(sys,'argv',args),patch('sys.stdin.isatty',return_value=False),patch('sys.stdout',new_callable=io.StringIO),patch('sys.stderr',new_callable=io.StringIO) as error:
            with self.assertRaises(SystemExit):main()
        self.assertIn('migration_requires_explicit_route_wiring_and_confirm',error.getvalue())
