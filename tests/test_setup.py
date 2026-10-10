import asyncio
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dot_herdr.setup import TEMPLATE,write_template,load_config,doctor,public_key
from dot_herdr.core import Rejected
from dot_herdr.demo import demo

class SetupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def config(self,value=None):
        p=self.directory/'config.json';p.write_text(json.dumps(value if value is not None else TEMPLATE));p.chmod(0o600);return p
    async def test_template_private_and_no_overwrite_or_symlink(self):
        p=self.directory/'new.json';write_template(p)
        self.assertEqual(p.stat().st_mode & 0o777,0o600);body=p.read_bytes()
        with self.assertRaises(FileExistsError):write_template(p)
        self.assertEqual(p.read_bytes(),body)
        link=self.directory/'link.json';link.symlink_to(p)
        with self.assertRaises(FileExistsError):write_template(link)
        self.assertEqual(p.read_bytes(),body)
        public=self.directory/'public';public.mkdir(mode=0o755);public.chmod(0o755)
        with self.assertRaisesRegex(Rejected,'private_output_parent_required'):write_template(public/'config.json')
        self.assertFalse((public/'config.json').exists())
    async def test_configuration_types_and_content_fail_closed(self):
        bads=[{**TEMPLATE,'subjects':'not-a-roster'},{**TEMPLATE,'store':3},{**TEMPLATE,'socket':'relative.sock'},
              {**TEMPLATE,'issuer':'http://auth.example.invalid'},{**TEMPLATE,'subjects':[{**TEMPLATE['subjects'][0],'content':'false'}]},
              {**TEMPLATE,'subjects':[{**TEMPLATE['subjects'][0],'control':'true'}]},
              {**TEMPLATE,'session_users':['user','user']},{**TEMPLATE,'session_users':[False]},
              {**TEMPLATE,'subjects':[{**TEMPLATE['subjects'][0],'native':{'value':'missing-fields'}}]}]
        for bad in bads:
            with self.assertRaises(Rejected):load_config(self.config(bad))
    async def test_session_only_and_existing_observation_configuration(self):
        session={**TEMPLATE,'subjects':[],'session_users':['user-demo']}
        self.assertEqual(load_config(self.config(session))['subjects'],[])
        with self.assertRaises(Rejected):load_config(self.config({**session,'session_users':[]}))
        old={k:v for k,v in TEMPLATE.items() if k!='session_users'}
        old['subjects']=[{k:v for k,v in TEMPLATE['subjects'][0].items() if k!='control'}]
        self.assertNotIn('control',load_config(self.config(old))['subjects'][0])
    async def test_doctor_never_opens_store_source_or_network(self):
        config=self.config()
        with patch('socket.create_connection',side_effect=AssertionError('network forbidden')),patch('asyncio.open_unix_connection',side_effect=AssertionError('source forbidden')),patch('dot_herdr.core.Store',side_effect=AssertionError('store forbidden')):
            report=doctor(config)
        self.assertFalse(report['live_ready']);self.assertEqual(report['mode'],'offline_only')
        self.assertEqual(next(c['status'] for c in report['checks'] if c['name']=='operator_placeholders'),'blocked')
    async def test_doctor_supported_python_versions(self):
        for version in ((3,10),(3,11),(3,12),(3,13),(3,14),(3,15)):
            with self.subTest(version=version),patch('dot_herdr.setup.sys.version_info',version):
                report=doctor()
                self.assertEqual(report['checks'][0]['status'],'pass' if version in ((3,11),(3,12),(3,13),(3,14)) else 'blocked')
    async def test_configured_source_independent_of_runner_context(self):
        import socket
        socket_path=self.directory/'source.sock'
        config=self.config({**TEMPLATE,'socket':str(socket_path)})
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as source:
            source.bind(str(socket_path))
            contexts=[{}, {'HERDR_ENV':'1','HERDR_PANE_ID':'w9:p9','HERDR_SOCKET_PATH':str(self.directory/'wrong.sock')}]
            for context in contexts:
                with self.subTest(context=context),patch.dict(os.environ,context,clear=True),patch('socket.create_connection',side_effect=AssertionError('network forbidden')),patch('asyncio.open_unix_connection',side_effect=AssertionError('source forbidden')),patch('subprocess.run',side_effect=AssertionError('process inspection forbidden')):
                    report=doctor(config)
                    selected=load_config(config)
                self.assertEqual(selected['socket'],str(socket_path))
                self.assertEqual(selected['subjects'],TEMPLATE['subjects'])
                self.assertEqual(next(c['status'] for c in report['checks'] if c['name']=='source_socket_file'),'present_not_connected')
                self.assertEqual(report['herdr_context']['environment_marker_present'],bool(context))
                self.assertEqual(report['herdr_context']['source_selection'],'explicit_configuration')
                self.assertFalse(report['live_ready'])
    async def test_demo_sdk_vertical_without_network_or_source_and_cleans_store(self):
        created=[];original=tempfile.TemporaryDirectory
        class TrackedTemporary(original):
            def __enter__(self):
                value=super().__enter__();created.append(Path(value));return value
        with patch('socket.create_connection',side_effect=AssertionError('network forbidden')),patch('asyncio.open_unix_connection',side_effect=AssertionError('source forbidden')),patch('dot_herdr.demo.tempfile.TemporaryDirectory',TrackedTemporary):
            result=await demo()
        self.assertEqual(result['demo'],'passed');self.assertEqual(result['signed_application_callbacks'],1)
        self.assertEqual(result['goal_status'],'unknown');self.assertEqual(result['receipt'],'detail_reviewed')
        self.assertEqual(result['interactive_reply'],'submitted');self.assertEqual(result['follow_up_message'],'submitted')
        self.assertEqual(result['duplicate_reply'],'not_resubmitted');self.assertEqual(result['source_actions'],2)
        self.assertEqual(result['state_after_reply'],'idle')
        self.assertTrue(created);self.assertTrue(all(not p.exists() for p in created))
    async def test_demo_resolves_symlinked_default_temp_root_without_weakening_store(self):
        root=self.directory/'actual';root.mkdir(mode=0o700);link=self.directory/'alias';link.symlink_to(root,target_is_directory=True)
        with patch('dot_herdr.demo.tempfile.tempdir',str(link)):
            result=await demo()
        self.assertEqual(result['demo'],'passed')
        from dot_herdr.core import Store
        with self.assertRaisesRegex(Rejected,'private_store_required'):Store(link/'user-selected.sqlite')
        self.assertEqual(list(root.iterdir()),[])
    async def test_cli_template_cannot_run_before_setup(self):
        import sys
        from dot_herdr.cli import main
        config=self.config()
        with patch.object(sys,'argv',['dot-herdr','run','--config',str(config)]),patch('dot_herdr.cli.Store') as opened,contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as exit:main()
        self.assertEqual(exit.exception.code,2);opened.assert_not_called();self.assertIn('operator_placeholders_remaining',stderr.getvalue())
    async def test_public_key_rejects_private_key_invalid_and_small_keys(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        p=self.directory/'key.pem'
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        p.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        with self.assertRaises(Rejected):public_key(p)
        p.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.assertTrue(public_key(p).startswith('-----BEGIN PUBLIC KEY-----'))
        p.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.PKCS1))
        self.assertTrue(public_key(p).startswith('-----BEGIN PUBLIC KEY-----'))
        from dot_herdr.endpoint import JWTVerifier
        JWTVerifier('https://auth.example.test','https://connector.example.test/mcp',public_key(p))
        from cryptography.hazmat.primitives.asymmetric import ec
        p.write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaises(Rejected):public_key(p)
        small=rsa.generate_private_key(public_exponent=65537,key_size=1024)
        p.write_bytes(small.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaises(Rejected):public_key(p)
        p.write_text('invalid')
        with self.assertRaises(Rejected):public_key(p)

class BackupTests(unittest.TestCase):
    def test_private_consistent_backup_includes_wal_and_never_overwrites(self):
        import sqlite3
        from dot_herdr.core import Store
        from dot_herdr.maintenance import backup
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source.sqlite';output=root/'backup.sqlite'
            store=Store(source);store.close()
            writer=sqlite3.connect(source)
            writer.execute('PRAGMA journal_mode=WAL');writer.execute('CREATE TABLE synthetic_fixture(value TEXT)');writer.execute("INSERT INTO synthetic_fixture VALUES ('committed WAL fixture')");writer.commit()
            self.assertTrue(Path(str(source)+'-wal').exists())
            backup(source,output)
            reader=sqlite3.connect(output);self.assertEqual(reader.execute('SELECT value FROM synthetic_fixture').fetchone()[0],'committed WAL fixture');reader.close()
            original=output.read_bytes()
            with self.assertRaises(FileExistsError):backup(source,output)
            self.assertEqual(output.read_bytes(),original);self.assertEqual(output.stat().st_mode & 0o777,0o600)
            link=root/'link.sqlite';link.symlink_to(output)
            with self.assertRaises(FileExistsError):backup(source,link)
            writer.close()
    def test_sqlite_special_relative_destination_cannot_report_success(self):
        from dot_herdr.core import Store
        from dot_herdr.maintenance import backup
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);store=Store(root/'source.sqlite');store.close()
            with self.assertRaisesRegex(Rejected,'absolute_backup_paths_required'):backup(root/'source.sqlite',':memory:')
            output=root/':memory:';backup(root/'source.sqlite',output)
            self.assertGreaterEqual(output.stat().st_size,100);self.assertEqual(output.read_bytes()[:16],b'SQLite format 3\x00')
    def test_active_owner_backup_refused_without_output(self):
        from dot_herdr.core import Store
        from dot_herdr.maintenance import backup
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);store=Store(root/'source.sqlite')
            try:
                with self.assertRaisesRegex(Rejected,'stop_store_owner_before_backup'):backup(root/'source.sqlite',root/'backup.sqlite')
                self.assertFalse((root/'backup.sqlite').exists())
            finally:store.close()
