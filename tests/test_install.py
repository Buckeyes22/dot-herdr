import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from dot_herdr import installation
from dot_herdr.core import Store,Rejected
from dot_herdr.maintenance import update,uninstall as uninstall_runtime


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.prefix=self.root/'owned';self.bin=self.root/'commands';self.source=self.root/'fixture.whl'
        with zipfile.ZipFile(self.source,'w') as wheel:wheel.writestr('dot_herdr.data/data/share/dot-herdr/requirements.lock','mcp==2.3.0\n')
    def tearDown(self):self.tmp.cleanup()
    def build(self,path):
        (path/'bin').mkdir();(path/'bin/python').write_text('fixture')
        entry=path/'bin/dot-herdr';entry.write_text('fixture');entry.chmod(0o700)
    def execute(self,args,**kwargs):
        output=json.dumps({'demo':'passed'}) if args[-1]=='demo' else json.dumps({'checks':[{'status':'pass'}]})
        return subprocess.CompletedProcess(args,0,stdout=output,stderr='')
    def stage(self):
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=self.execute):
            return installation.stage(self.source,self.prefix,self.bin)
    def install(self):
        result=self.stage();installation.activate(result);return result
    def test_failed_stage_leaves_current_and_history_untouched(self):
        initial=self.install();before=(self.prefix/installation.MARKER).read_bytes();config=self.root/'config.json';config.write_text('retained')
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['demo'])):
            with self.assertRaises(subprocess.CalledProcessError):installation.stage(self.source,self.prefix,self.bin)
        self.assertEqual(os.readlink(self.prefix/'venv'),initial['release']);self.assertEqual((self.prefix/installation.MARKER).read_bytes(),before);self.assertEqual(config.read_text(),'retained')
    def test_stage_check_failure_reports_redacted_output_and_cleans_partial_release(self):
        def fail(args,**kwargs):
            if args[-1]=='demo':raise subprocess.CalledProcessError(2,args,output='demo failed token=abcdef',stderr='private_store_required Authorization: Bearer hidden')
            return self.execute(args,**kwargs)
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=fail):
            with self.assertRaisesRegex(ValueError,'private_store_required') as caught:installation.stage(self.source,self.prefix,self.bin)
        self.assertNotIn('abcdef',str(caught.exception));self.assertNotIn('hidden',str(caught.exception))
        self.assertFalse(list((self.prefix/'releases').iterdir()))
    def test_stage_demo_uses_resolved_private_temp(self):
        seen=[]
        def execute(args,**kwargs):
            if args[-1]=='demo':seen.append(kwargs.get('env',{}).get('TMPDIR'))
            return self.execute(args,**kwargs)
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=execute):installation.stage(self.source,self.prefix,self.bin)
        self.assertEqual(len(seen),1);self.assertTrue(Path(seen[0]).is_absolute());self.assertFalse(any(p.is_symlink() for p in (Path(seen[0]),*Path(seen[0]).parents)))
    def test_source_bootstrap_launches_setup_only_on_tty(self):
        script=Path(__file__).resolve().parents[1]/'scripts/install.py'
        spec=importlib.util.spec_from_file_location('source_bootstrap',script)
        bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
        args=['install.py','--source',str(self.source),'--prefix',str(self.prefix),'--bin-dir',str(self.bin)]
        for interactive in (True,False):
            with self.subTest(interactive=interactive),patch.object(bootstrap,'install') as install,patch.object(bootstrap.sys,'argv',args),patch.object(bootstrap.sys,'stdin',types.SimpleNamespace(isatty=lambda:interactive)):
                bootstrap.main();self.assertEqual(install.call_args.kwargs['setup'],interactive)
    def test_activation_switch_and_rollback_preserve_both_runtimes(self):
        initial=self.install();next_release=self.stage();installation.activate(next_release)
        self.assertEqual(os.readlink(self.bin/'dot-herdr'),str(self.prefix/'venv/bin/dot-herdr'))
        self.assertEqual(os.readlink(self.prefix/'venv'),next_release['release'])
        installation.rollback(self.prefix,next_release['release'])
        self.assertEqual(os.readlink(self.prefix/'venv'),initial['release']);self.assertTrue(Path(next_release['release']).is_dir())
    def test_activation_final_record_failure_recovers_previous_pointer(self):
        initial=self.install();next_release=self.stage();writer=installation.write_record;calls=[]
        def fail_final(path,value):
            calls.append(value.copy())
            if len(calls)==2:raise OSError('disk unavailable')
            return writer(path,value)
        with patch.object(installation,'write_record',side_effect=fail_final):
            with self.assertRaises(OSError):installation.activate(next_release)
        self.assertEqual(os.readlink(self.prefix/'venv'),initial['release'])
        repaired=installation.recover(self.prefix);self.assertEqual(repaired['current'],initial['release']);self.assertNotIn('pending',repaired)
        installation.activate(next_release);self.assertEqual(os.readlink(self.prefix/'venv'),next_release['release'])
    def test_interrupted_activation_journal_recovers_new_pointer(self):
        initial=self.install();candidate=self.stage();record=installation.inventory(self.prefix)
        record['pending']={'from':initial['release'],'to':candidate['release']};installation.write_record(self.prefix/installation.MARKER,record)
        pointer=self.prefix/'venv';pointer.unlink();pointer.symlink_to(candidate['release'])
        recovered=installation.recover(self.prefix);self.assertEqual(recovered['current'],candidate['release']);self.assertEqual(recovered['previous'],initial['release'])
    def test_final_record_fsync_failure_keeps_consistent_committed_switch(self):
        self.install();candidate=self.stage();writer=installation.write_record;calls=[]
        def fail_after_commit(path,value):
            calls.append(value.copy());writer(path,value)
            if len(calls)==2:raise OSError('directory fsync unavailable after replace')
        with patch.object(installation,'write_record',side_effect=fail_after_commit):installation.activate(candidate)
        self.assertEqual(installation.inventory(self.prefix)['current'],candidate['release'])
        self.assertEqual(os.readlink(self.prefix/'venv'),candidate['release'])
    def test_legacy_in_place_environment_is_preserved_until_validated_activation(self):
        self.prefix.mkdir(mode=0o700);(self.prefix/installation.MARKER).touch();old=self.prefix/'venv';old.mkdir();self.build(old)
        self.bin.mkdir();(self.bin/'dot-herdr').symlink_to(old/'bin/dot-herdr')
        candidate=self.stage();self.assertFalse(old.is_symlink());self.assertEqual((old/'bin/dot-herdr').read_text(),'fixture')
        installed=installation.activate(candidate);self.assertTrue(old.is_symlink());self.assertTrue(Path(installed['previous']).is_dir())
        installation.rollback(self.prefix,candidate['release']);self.assertEqual((old/'bin/dot-herdr').read_text(),'fixture')
    def test_hash_and_unsafe_archive_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'mismatch'):installation.artifact(self.source,self.root,'0'*64)
        with self.assertRaisesRegex(ValueError,'published SHA'):installation.artifact('https://release.example.test/connector.whl',self.root)
        archive=self.root/'fixture.tar.gz'
        with tarfile.open(archive,'w:gz') as output:
            member=tarfile.TarInfo('../escape');member.size=1;output.addfile(member,io.BytesIO(b'x'))
        with self.assertRaisesRegex(ValueError,'Unsafe'):installation.artifact(archive,self.root,hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertFalse((self.root.parent/'escape').exists())
    def test_uninstall_preserves_modified_command_and_unrelated_files(self):
        self.install();command=self.bin/'dot-herdr';command.unlink();command.write_text('user replacement')
        unrelated=self.prefix/'user-notes';unrelated.write_text('keep');config=self.root/'config.json';config.write_text('private history')
        result=installation.uninstall(self.prefix)
        self.assertEqual(command.read_text(),'user replacement');self.assertEqual(unrelated.read_text(),'keep');self.assertEqual(config.read_text(),'private history')
        self.assertIn(str(command),result['preserved']);self.assertFalse((self.prefix/'venv').exists())
    def test_purge_refuses_unassociated_same_named_private_directory_and_ancestors(self):
        self.install();unrelated=self.root/'dot-herdr';unrelated.mkdir(mode=0o700);(unrelated/'keep').write_text('retain')
        with self.assertRaisesRegex(ValueError,'not associated'):installation.uninstall(self.prefix,purge_paths=[unrelated],confirm_purge=True)
        self.assertTrue((unrelated/'keep').exists());self.assertTrue((self.prefix/'venv').exists())
        link=self.root/'ancestor';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'Symlink'):installation.uninstall(self.prefix,purge_paths=[link/'dot-herdr'],confirm_purge=True)


class UpdateTests(InstallationTests):
    def config(self):
        private=self.root/'dot-herdr';private.mkdir(mode=0o700);state=private/'state';state.mkdir(mode=0o700)
        cfg={'store':str(state/'connector.sqlite'),'socket':str(private/'source.sock'),'issuer':'https://issuer.example.test','resource':'https://resource.example.test/mcp','public_key':str(private/'public.pem'),
             'subjects':[],'session_users':[],'inactive':True,'access_accounts':['account']}
        path=private/'config.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
        store=Store(cfg['store']);store.begin_action('principal','request',{'method':'send'});store.close()
        return path,cfg
    def test_update_runtime_failure_rolls_back_executable_retains_dedupe(self):
        initial=self.install();path,cfg=self.config()
        class Service:
            calls=[]
            def status(self):return {'owned':True,'active':True}
            def stop(self):self.calls.append('stop')
            def start(self):
                self.calls.append('start')
                if self.calls.count('start')==1:raise ValueError('runtime failed')
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=self.execute):
            with self.assertRaisesRegex(Rejected,'previous_executable_restored'):update(self.source,path,prefix=self.prefix,service=Service())
        self.assertEqual(os.readlink(self.prefix/'venv'),initial['release'])
        store=Store(cfg['store'])
        try:self.assertEqual(store.begin_action('principal','request',{'method':'send'})['outcome'],'unknown')
        finally:store.close()
    def test_update_migration_failure_never_starts_older_schema(self):
        initial=self.install();path,cfg=self.config()
        class Service:
            calls=[]
            def status(self):return {'owned':True,'active':True}
            def stop(self):self.calls.append('stop')
            def start(self):
                import sqlite3
                db=sqlite3.connect(cfg['store']);db.execute('PRAGMA user_version=3');db.close();self.calls.append('start');raise ValueError('migration failure')
        service=Service()
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=self.execute):
            with self.assertRaisesRegex(Rejected,'schema_changed'):update(self.source,path,prefix=self.prefix,service=service)
        self.assertNotEqual(os.readlink(self.prefix/'venv'),initial['release']);self.assertEqual(service.calls.count('start'),1)
    def test_uninstall_refuses_foreground_owner_and_retains_config(self):
        self.install();path,cfg=self.config();store=Store(cfg['store'])
        try:
            with self.assertRaisesRegex(Rejected,'stop_foreground_owner'):uninstall_runtime(path,prefix=self.prefix)
            self.assertTrue((self.prefix/'venv').exists());self.assertTrue(path.exists())
        finally:store.close()
    def test_uninstall_before_setup_requires_no_configuration(self):
        self.install();missing=self.root/'not-configured/config.json'
        result=uninstall_runtime(missing,prefix=self.prefix)
        self.assertEqual(result['status'],'uninstalled');self.assertFalse((self.bin/'dot-herdr').exists());self.assertFalse(missing.exists())
    def test_uninstall_continues_runtime_removal_when_shared_cleanup_cannot_be_verified(self):
        self.install();path,cfg=self.config()
        with patch('dot_herdr.connections.remove_owned_connections',side_effect=ValueError('user modified marketplace')):
            result=uninstall_runtime(path,prefix=self.prefix)
        self.assertEqual(result['status'],'uninstalled');self.assertEqual(result['connections']['status'],'cleanup_incomplete')
        self.assertFalse((self.bin/'dot-herdr').exists());self.assertTrue(path.exists());self.assertTrue(Path(cfg['store']).exists())
