import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dot_herdr import service
from dot_herdr.core import Rejected


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='herdr service space ')
        self.root = Path(self.temp.name)
        self.config = self.root / 'private config.json'
        self.config.write_text('{}')
        self.config.chmod(0o600)
        self.binary = self.root / 'installed command'
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        self.binary.chmod(0o700)
        self.calls = []
        self.patches = [patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.root)}),
                        patch('dot_herdr.service.load_config', return_value={}),
                        patch('dot_herdr.service._manager', return_value='/usr/bin/manager'),
                        patch('dot_herdr.service._call', side_effect=self.call)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def call(self, args):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, b'ActiveState=inactive\nSubState=dead\nMainPID=0\nUnitFileState=disabled\n', b'')

    def install(self, **kwargs):
        return service.install(self.config, executable=self.binary, platform_name='Linux', **kwargs)

    def test_systemd_paths_spaces_and_bounded_restart(self):
        receipt = self.install(login_start=True)
        body = Path(receipt['path']).read_text()
        self.assertIn('"' + str(self.binary) + '" "run" "--config" "' + str(self.config) + '"', body)
        self.assertIn('RestartPreventExitStatus=2', body)
        self.assertIn('StartLimitBurst=3', body)
        self.assertIn(['enable', receipt['label']], [args[-2:] for args in self.calls])
        self.assertEqual(Path(receipt['path']).stat().st_mode & 0o777, 0o600)

    def test_private_key_not_in_manager_files_or_args(self):
        key = self.root / 'launch key'
        key.write_text('secret-value-never-unit')
        key.chmod(0o600)
        receipt = self.install(tunnel=True, credential_file=key)
        self.assertNotIn('secret-value-never-unit', Path(receipt['path']).read_text())
        self.assertNotIn('secret-value-never-unit', service.receipt_path(self.config).read_text())
        self.assertNotIn('secret-value-never-unit', repr(self.calls))
        with self.assertRaisesRegex(Rejected, 'private_credential_file_required'):
            self.install(tunnel=True)

    def test_unowned_and_modified_service_rejected(self):
        label, path = service._location(self.config, 'Linux')
        path.parent.mkdir(parents=True)
        path.write_text('unrelated unit')
        with self.assertRaisesRegex(Rejected, 'unowned_existing'):
            self.install()
        path.unlink()
        receipt = self.install()
        path.write_text('changed unit')
        with self.assertRaisesRegex(Rejected, 'not_owned_or_changed'):
            service.manage(self.config, 'remove')
        self.assertTrue(path.exists())

    def test_remove_owned_only_and_retain_state_logs(self):
        receipt = self.install()
        result = service.manage(self.config, 'remove')
        self.assertEqual(result['state'], 'removed')
        self.assertFalse(Path(receipt['path']).exists())
        self.assertTrue(self.config.exists())
        self.assertTrue((self.root / 'logs').exists())

    def test_missing_manager_has_actionable_foreground_result(self):
        with patch('dot_herdr.service._manager', side_effect=Rejected('user_service_manager_unavailable_use_foreground')):
            with self.assertRaisesRegex(Rejected, 'use_foreground'):
                self.install()
        self.assertFalse(service.receipt_path(self.config).exists())

    def test_launchagent_uses_array_login_choice_and_no_restart_loop(self):
        with patch('pathlib.Path.home', return_value=self.root):
            receipt = service.install(self.config, executable=self.binary, platform_name='Darwin', login_start=True)
            value = plistlib.loads(Path(receipt['path']).read_bytes())
            self.assertEqual(value['ProgramArguments'], [str(self.binary), 'run', '--config', str(self.config)])
            self.assertTrue(value['RunAtLoad'])
            self.assertFalse(value['KeepAlive'])
            self.assertEqual(value['Umask'], 0o077)

    def test_launchagent_restart_waits_for_job_and_prior_process(self):
        with patch('pathlib.Path.home', return_value=self.root):
            receipt = service.install(self.config, executable=self.binary, platform_name='Darwin')
            self.calls.clear()
            states = iter([{'state': 'running', 'pid': 901},
                           {'state': 'exiting', 'pid': 901},
                           {'state': 'stopped', 'pid': 0},
                           {'state': 'stopped', 'pid': 0},
                           {'state': 'running', 'pid': 902}])
            def status(config):
                state = next(states)
                if state['state'] == 'exiting':
                    self.assertEqual([args[1] for args in self.calls], ['bootout'])
                return state
            def identity(pid):
                self.assertEqual(pid, 901)
                # The first stopped observation must still wait for the process.
                return next(identities)
            identities = iter(['old-start', 'old-start', 'old-start', None])
            with patch('dot_herdr.service.service_status', side_effect=status), \
                    patch('dot_herdr.service.process_identity', side_effect=identity), \
                    patch('dot_herdr.service.time.sleep') as sleep:
                result = service.manage(self.config, 'restart')
            self.assertEqual(result['pid'], 902)
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual([args[1] for args in self.calls], ['bootout', 'bootstrap', 'kickstart'])
            self.assertEqual(self.calls[1][-1], receipt['path'])

    def test_launchagent_stop_fences_reused_pid_without_signalling_it(self):
        with patch('pathlib.Path.home', return_value=self.root):
            service.install(self.config, executable=self.binary, platform_name='Darwin')
            self.calls.clear()
            with patch('dot_herdr.service.service_status', side_effect=[
                    {'state': 'running', 'pid': 901}, {'state': 'stopped', 'pid': 0},
                    {'state': 'stopped', 'pid': 0}]), \
                    patch('dot_herdr.service.process_identity', side_effect=['old-start', 'new-start']):
                self.assertEqual(service.manage(self.config, 'stop')['state'], 'stopped')
            self.assertEqual([args[1] for args in self.calls], ['bootout'])

    def test_launchagent_shutdown_timeout_preserves_owned_files_and_prevents_restart(self):
        for action in ('remove', 'restart'):
            with self.subTest(action=action), patch('pathlib.Path.home', return_value=self.root):
                receipt = service.install(self.config, executable=self.binary, platform_name='Darwin')
                before = service.receipt_path(self.config).read_bytes()
                self.calls.clear()
                with patch('dot_herdr.service.service_status', return_value={'state': 'running', 'pid': 901}), \
                        patch('dot_herdr.service.process_identity', return_value='old-start'), \
                        patch('dot_herdr.service.time.monotonic', side_effect=[0, 21]):
                    with self.assertRaisesRegex(Rejected, 'shutdown_timed_out'):
                        service.manage(self.config, action)
                self.assertEqual(service.receipt_path(self.config).read_bytes(), before)
                self.assertTrue(Path(receipt['path']).exists())
                self.assertEqual([args[1] for args in self.calls], ['bootout'])

    def test_launchagent_retry_waits_for_private_runtime_after_job_disappears(self):
        with patch('pathlib.Path.home', return_value=self.root):
            service.install(self.config, executable=self.binary, platform_name='Darwin')
            self.calls.clear()
            service.status_path(self.config).write_text(json.dumps({
                'config': str(self.config), 'pid': 901, 'process_start': 'old-start'}))
            service.status_path(self.config).chmod(0o600)
            def identity(pid):
                self.assertEqual(pid, 901)
                value = next(identities)
                if value == 'old-start':
                    self.assertEqual(self.calls, [])
                return value
            identities = iter(['old-start', 'old-start', None])
            with patch('dot_herdr.service.service_status', return_value={'state': 'stopped', 'pid': 0}), \
                    patch('dot_herdr.service.process_identity', side_effect=identity), \
                    patch('dot_herdr.service.time.sleep') as sleep:
                service.manage(self.config, 'start')
            self.assertEqual(sleep.call_count, 1)
            self.assertEqual([args[1] for args in self.calls], ['bootstrap', 'kickstart'])

    def test_status_read_only_and_receipt_cannot_redirect(self):
        receipt = self.install()
        before = Path(receipt['path']).read_bytes()
        self.assertEqual(service.service_status(self.config)['state'], 'inactive')
        self.assertEqual(Path(receipt['path']).read_bytes(), before)
        value = json.loads(service.receipt_path(self.config).read_bytes())
        value['label'] = 'unrelated.service'
        service.receipt_path(self.config).write_text(json.dumps(value))
        with self.assertRaisesRegex(Rejected, 'not_owned_or_changed'):
            service.manage(self.config, 'stop')

    def test_systemd_escapes_specifiers_and_environment(self):
        self.assertEqual(service._quote('/tmp/50%/$KEY'), '"/tmp/50%%/$$KEY"')

    def test_owned_install_command_and_version_pointer_are_preserved(self):
        prefix = self.root / 'owned install'
        release = prefix / 'releases' / 'v1' / 'bin'
        release.mkdir(parents=True)
        prefix.chmod(0o700)
        (prefix / '.dot-herdr-install').write_text('')
        binary = release / 'dot-herdr'
        binary.write_text('#!/bin/sh\nexit 0\n')
        binary.chmod(0o700)
        (prefix / 'venv').symlink_to(release.parent)
        command = self.root / 'dot-herdr'
        command.symlink_to(prefix / 'venv' / 'bin' / 'dot-herdr')
        receipt = service.install(self.config, executable=command, platform_name='Linux')
        self.assertIn(service._quote(command), Path(receipt['path']).read_text())
        (prefix / '.dot-herdr-install').unlink()
        with self.assertRaisesRegex(Rejected, 'unowned_executable_symlink'):
            service.install(self.config, executable=command, platform_name='Linux')

    def interrupt_receipt(self, **kwargs):
        write = service.write_file
        def interrupted(path, *args, **options):
            if Path(path) == service.receipt_path(self.config):
                raise OSError('simulated interruption before receipt commit')
            return write(path, *args, **options)
        with patch('dot_herdr.service.write_file', side_effect=interrupted):
            with self.assertRaises(OSError):
                self.install(**kwargs)

    def test_interrupted_first_install_is_reported_read_only_and_resumes(self):
        self.interrupt_receipt(login_start=True)
        _, generated = service._location(self.config, 'Linux')
        journal = service.pending_path(self.config)
        before = (generated.read_bytes(), journal.read_bytes())
        self.assertFalse(service.receipt_path(self.config).exists())
        self.assertEqual(service.service_status(self.config)['state'], 'interrupted_install')
        self.assertEqual((generated.read_bytes(), journal.read_bytes()), before)
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        receipt = self.install(login_start=True)
        self.assertFalse(journal.exists())
        self.assertEqual(service.service_record(self.config), receipt)

    def test_interrupted_reinstall_recovers_previous_receipt_and_new_unit(self):
        old = self.install(login_start=False)
        old_receipt = service.receipt_path(self.config).read_bytes()
        old_unit = Path(old['path']).read_bytes()
        self.binary = self.root / 'new installed command'
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        self.binary.chmod(0o700)
        self.interrupt_receipt(login_start=True)
        self.assertNotEqual(Path(old['path']).read_bytes(), old_unit)
        self.assertEqual(service.receipt_path(self.config).read_bytes(), old_receipt)
        self.assertEqual(service.service_status(self.config)['state'], 'interrupted_install')
        service.manage(self.config, 'start')
        self.assertTrue(service.service_record(self.config)['login_start'])
        self.assertFalse(service.pending_path(self.config).exists())
        self.assertIn(['enable', old['label']], [args[-2:] for args in self.calls])

    def test_recovery_refuses_user_modified_generated_file(self):
        self.interrupt_receipt()
        _, generated = service._location(self.config, 'Linux')
        generated.write_text('operator changed this file')
        journal = service.pending_path(self.config).read_bytes()
        with self.assertRaisesRegex(Rejected, 'interrupted_install_changed_preserved'):
            self.install()
        self.assertEqual(generated.read_text(), 'operator changed this file')
        self.assertEqual(service.pending_path(self.config).read_bytes(), journal)
        self.assertFalse(service.receipt_path(self.config).exists())

    def test_recovery_refuses_journal_redirect_and_can_remove_owned_interruption(self):
        self.interrupt_receipt()
        journal = service.pending_path(self.config)
        original = journal.read_bytes()
        value = json.loads(original)
        value['config'] = str(self.root / 'unrelated.json')
        journal.write_text(json.dumps(value))
        with self.assertRaisesRegex(Rejected, 'interrupted_install_changed_preserved'):
            service.manage(self.config, 'remove')
        journal.write_bytes(original)
        result = service.manage(self.config, 'remove')
        self.assertEqual(result['state'], 'removed')
        self.assertFalse(journal.exists())
        self.assertTrue(self.config.exists())

    def test_service_mutation_lock_does_not_block_read_only_status(self):
        self.install()
        with service._ServiceLock(self.config):
            self.assertEqual(service.service_status(self.config)['state'], 'inactive')
            with self.assertRaisesRegex(Rejected, 'service_operation_already_running'):
                service.manage(self.config, 'start')

    def test_recovery_before_unit_replace_and_after_receipt_commit(self):
        sync = service._sync_parent
        for point in (service.pending_path(self.config), service.receipt_path(self.config)):
            with self.subTest(point=point):
                def interrupted(path):
                    if Path(path) == point:
                        raise OSError('simulated process interruption at durable boundary')
                    sync(path)
                with patch('dot_herdr.service._sync_parent', side_effect=interrupted):
                    with self.assertRaises(OSError):
                        self.install()
                self.assertTrue(service.pending_path(self.config).exists())
                self.install()
                self.assertFalse(service.pending_path(self.config).exists())
                self.assertEqual(service.service_record(self.config)['owner'], 'dot-herdr')
