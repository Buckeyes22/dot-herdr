"""Selected ChatGPT client wording and saved choice use synthetic resources."""
import os
import subprocess
import sys
import unittest
from pathlib import Path

from dot_herdr.connections import connection_record,migrate_connection,save_connection
from dot_herdr.core import Rejected
from dot_herdr.onboarding import save_config


class ClientAppWordingTests(unittest.TestCase):
    def test_full_routine_transcripts_use_only_the_selected_app(self):
        script=Path(__file__).resolve().parent/'client_app_transcript.py'
        for app in ('chatgpt-web','desktop'):
            with self.subTest(app=app):
                run=subprocess.run([sys.executable,str(script),app],capture_output=True,text=True,env=os.environ.copy(),timeout=30)
                self.assertEqual(run.returncode,0,run.stderr)
                transcript=run.stdout.lower()
                self.assertIn('switch tool access from low-risk only to allow all tools',transcript)
                if app=='chatgpt-web':
                    self.assertIn('chatgpt.com',transcript)
                    for forbidden in ('codex://','restart the app','desktop','computer permission','marketplace'):
                        self.assertNotIn(forbidden,transcript)
                else:
                    self.assertIn('desktop app',transcript)
                    self.assertNotIn('chatgpt.com',transcript)
                    self.assertNotIn('codex://',transcript)
                    self.assertNotIn('marketplace',transcript)
                observe=subprocess.run([sys.executable,str(script),app,'observe-only'],capture_output=True,text=True,env=os.environ.copy(),timeout=30)
                self.assertEqual(observe.returncode,0,observe.stderr)
                self.assertNotIn('switch tool access from low-risk only to allow all tools',observe.stdout.lower())

    def test_client_choice_migrates_without_local_package_write(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700);config=root/'config.json'
            resource='https://mcp.example.com/mcp'
            save_config(config,{'store':str(root/'store.sqlite'),'socket':str(root/'source.sock'),'issuer':'https://auth.example.com','resource':resource,'public_key':str(root/'key.pem'),'subjects':[],'session_users':['user']})
            record=connection_record(config);record.update(route='https',wiring='registered-plugin',client_app='chatgpt-web',endpoint=resource);save_connection(config,record)
            result=migrate_connection(config,'https','registered-plugin',client_app='desktop',launch=False,say=lambda _:None)
            self.assertEqual(result['client_app'],'desktop')
            self.assertEqual(connection_record(config)['client_app'],'desktop')
            self.assertFalse((root/'.codex').exists())
            self.assertFalse((root/'.agents').exists())
            with self.assertRaisesRegex(Rejected,'migration_selection_unchanged'):
                migrate_connection(config,'https','registered-plugin',client_app='desktop',launch=False,say=lambda _:None)
