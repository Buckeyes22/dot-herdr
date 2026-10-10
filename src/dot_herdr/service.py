"""Connector-owned systemd user units and login-session LaunchAgents only."""
import hashlib
import base64
import fcntl
import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .connections import encoded, read_file, safe_path, write_file
from .core import Rejected
from .onboarding import private_directory
from .runtime import credential_environment, process_identity, status_path
from .setup import load_config


def receipt_path(config):
    path = Path(config).expanduser().absolute()
    return path.with_name(path.name + '.service.json')


def pending_path(config):
    return receipt_path(config).with_suffix('.pending.json')


def _sync_parent(path):
    fd = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _ServiceLock:
    def __init__(self, config):
        self.path = _absolute(receipt_path(config).with_suffix('.lock'))

    def __enter__(self):
        private_directory(self.path.parent)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(self.fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise Rejected('private_service_lock_required')
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Rejected('service_operation_already_running') from None
            return self
        except BaseException:
            os.close(self.fd)
            raise

    def __exit__(self, *args):
        os.close(self.fd)


def _recover_install(config):
    """Finish only a journaled pair of unchanged owned files; never infer ownership."""
    journal = _absolute(pending_path(config))
    raw = read_file(journal, 262144)
    if raw is None:
        return False
    try:
        if journal.stat().st_uid != os.getuid() or journal.stat().st_mode & 0o077:
            raise ValueError
        value = json.loads(raw)
        if value['version'] != 1 or value['owner'] != 'dot-herdr' or value['config'] != str(_absolute(config)):
            raise ValueError
        system = value['system']
        if system not in ('Linux', 'Darwin'):
            raise ValueError
        label, generated = _location(config, system)
        receipt = _absolute(receipt_path(config))
        decoded = {}
        for name, limit in (('previous_body', 65536), ('next_body', 65536),
                            ('previous_receipt', 16384), ('next_receipt', 16384)):
            item = value[name]
            decoded[name] = None if item is None else base64.b64decode(item, validate=True)
            if decoded[name] is not None and len(decoded[name]) > limit:
                raise ValueError
        for prefix in ('previous', 'next'):
            body, record = decoded[prefix + '_body'], decoded[prefix + '_receipt']
            if prefix == 'previous' and body is None and record is None:
                continue
            if body is None or record is None:
                raise ValueError
            record = json.loads(record)
            if (record['owner'] != 'dot-herdr' or record['config'] != str(_absolute(config))
                    or record['system'] != system or record['path'] != str(generated) or record['label'] != label
                    or record['sha256'] != hashlib.sha256(body).hexdigest()):
                raise ValueError
        current_body, current_receipt = read_file(generated, 65536), read_file(receipt, 16384)
        for path, current, kind in ((generated, current_body, 'body'), (receipt, current_receipt, 'receipt')):
            if current not in (decoded['previous_' + kind], decoded['next_' + kind]):
                raise ValueError
            if current is not None and (path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
                raise ValueError
    except (KeyError, TypeError, ValueError, OSError):
        raise Rejected('service_interrupted_install_changed_preserved') from None
    write_file(generated, decoded['next_body'], current_body, backup=False)
    _sync_parent(generated)
    write_file(receipt, decoded['next_receipt'], current_receipt, backup=False)
    _sync_parent(receipt)
    if read_file(journal, 262144) != raw:
        raise Rejected('service_interrupted_install_changed_preserved')
    journal.unlink()
    _sync_parent(journal)
    return True


def _absolute(path):
    path = safe_path(path)
    if any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise Rejected('invalid_service_path')
    return path


def _executable(path):
    """Preserve an owned install's stable pointer across atomic version updates."""
    path = Path(path).expanduser().absolute()
    if any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise Rejected('invalid_service_path')
    links = [part for part in (path, *path.parents) if part.is_symlink()]
    if not links:
        return _absolute(path)
    target = path.resolve(strict=True)
    prefixes = [parent for parent in (*path.parents, *target.parents)
                if (parent / '.dot-herdr-install').is_file()]
    for prefix in prefixes:
        try:
            safe_path(prefix)
            marker = prefix / '.dot-herdr-install'
            safe_path(marker)
            if marker.stat().st_uid != os.getuid() or prefix.stat().st_mode & 0o022:
                continue
            target.relative_to(prefix)
            safe_path(target)
            for link in links:
                if link.lstat().st_uid != os.getuid():
                    raise ValueError
                link.resolve(strict=True).relative_to(prefix)
                if link == path and not link.is_relative_to(prefix):
                    safe_path(link.parent)
                elif not link.is_relative_to(prefix):
                    raise ValueError
            return path
        except (Rejected, ValueError, OSError):
            continue
    raise Rejected('service_unowned_executable_symlink')


def _manager(system):
    name = 'systemctl' if system == 'Linux' else 'launchctl' if system == 'Darwin' else None
    binary = shutil.which(name) if name else None
    if binary is None:
        raise Rejected('user_service_manager_unavailable_use_foreground')
    return binary


def _call(args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        raise Rejected('user_service_manager_unavailable_use_foreground') from None
    if result.returncode:
        # No manager diagnostics are surfaced: they can include unrelated env values.
        raise Rejected('user_service_operation_failed_use_service_status')
    return result


def _quote(value):
    # systemd ExecStart is parsed by systemd, never by a shell. %% suppresses
    # specifiers and $$ suppresses environment expansion inside every argument.
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def _owned(config):
    path = _absolute(receipt_path(config))
    raw = read_file(path, 16384)
    try:
        value = json.loads(raw)
        if path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid():
            raise ValueError
        if value['owner'] != 'dot-herdr' or value['config'] != str(_absolute(config)):
            raise ValueError
        if value['system'] not in ('Linux', 'Darwin'):
            raise ValueError
        generated = _absolute(value['path'])
        body = read_file(generated, 65536)
        if body is None or hashlib.sha256(body).hexdigest() != value['sha256']:
            raise ValueError
        if generated.stat().st_uid != os.getuid() or generated.stat().st_mode & 0o077:
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError):
        raise Rejected('service_not_owned_or_changed') from None
    # Recompute the allowed path/label instead of accepting receipt-controlled targets.
    label, expected = _location(config, value['system'])
    if generated != expected or value['label'] != label:
        raise Rejected('service_not_owned_or_changed')
    return value, raw



def service_record(config):
    return _owned(config)[0]


def _location(config, system):
    identity = hashlib.sha256(str(_absolute(config)).encode()).hexdigest()[:16]
    label = 'com.herdr.dot.' + identity if system == 'Darwin' else 'dot-herdr-' + identity + '.service'
    if system == 'Linux':
        root = Path(os.environ.get('XDG_CONFIG_HOME', ''))
        if not root.is_absolute():
            root = Path.home() / '.config'
        destination = root / 'systemd' / 'user' / label
    else:
        destination = Path.home() / 'Library' / 'LaunchAgents' / (label + '.plist')
    return label, _absolute(destination)


def install(config, *, executable=None, tunnel=False, credential_file=None, login_start=False, platform_name=None):
    with _ServiceLock(config):
        _recover_install(config)
        return _install(config, executable=executable, tunnel=tunnel, credential_file=credential_file,
                        login_start=login_start, platform_name=platform_name)


def _install(config, *, executable=None, tunnel=False, credential_file=None, login_start=False, platform_name=None):
    """Prepare only owned private files; optional login startup is explicit."""
    config = _absolute(config)
    cfg = load_config(config)
    if cfg.get('inactive'):
        raise Rejected('inactive_configuration_select_access')
    system = platform_name or platform.system()
    manager = _manager(system)
    if system == 'Linux':
        _call([manager, '--user', 'show-environment'])
    else:
        _call([manager, 'print', 'gui/' + str(os.getuid())])
    binary = executable or shutil.which('dot-herdr') or str(Path(sys.executable).parent / 'dot-herdr')
    executable = _executable(binary)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise Rejected('installed_service_executable_required')
    arguments = [str(executable), 'run', '--config', str(config)]
    if tunnel:
        arguments.append('--tunnel')
        if credential_file is None:
            raise Rejected('service_tunnel_private_credential_file_required')
    if credential_file:
        if not tunnel:
            raise Rejected('service_credential_requires_tunnel')
        credential_file = _absolute(credential_file)
        credential_environment(credential_file)
        arguments += ['--credential-file', str(credential_file)]
    label, path = _location(config, system)
    logs = _absolute(config.parent / 'logs')
    private_directory(logs)
    for filename in ('service.stdout.log', 'service.stderr.log'):
        target = logs / filename
        safe_path(target)
        if target.exists():
            if target.stat().st_mode & 0o077 or target.stat().st_uid != os.getuid():
                raise Rejected('private_service_logs_required')
        else:
            write_file(target, b'')
    if system == 'Linux':
        body = ('# Owned by dot-herdr\n[Unit]\nDescription=dot-herdr\n'
                'StartLimitIntervalSec=120\nStartLimitBurst=3\n[Service]\nType=simple\n'
                'ExecStart=' + ' '.join(_quote(x) for x in arguments) + '\n'
                'UMask=0077\nRestart=on-failure\nRestartSec=10\nRestartPreventExitStatus=2\n'
                'TimeoutStopSec=15\nKillMode=control-group\n'
                'StandardOutput=append:' + _quote(logs / 'service.stdout.log') + '\n'
                'StandardError=append:' + _quote(logs / 'service.stderr.log') + '\n'
                '[Install]\nWantedBy=default.target\n').encode()
    else:
        body = plistlib.dumps({'Label': label, 'ProgramArguments': arguments,
                               'RunAtLoad': bool(login_start), 'KeepAlive': False,
                               'ExitTimeOut': 15, 'Umask': 0o077,
                               'StandardOutPath': str(logs / 'service.stdout.log'),
                               'StandardErrorPath': str(logs / 'service.stderr.log')}, sort_keys=True)
    receipt = receipt_path(config)
    before_receipt = read_file(receipt, 16384)
    previous = read_file(path, 65536)
    if before_receipt is not None:
        old, _ = _owned(config)
        if old['system'] != system:
            raise Rejected('service_platform_changed')
    elif previous is not None:
        raise Rejected('service_unowned_existing_file')
    value = {'owner': 'dot-herdr', 'version': 1, 'system': system,
             'config': str(config), 'path': str(path), 'label': label,
             'sha256': hashlib.sha256(body).hexdigest(), 'login_start': bool(login_start),
             'tunnel': bool(tunnel), 'credential_file': str(credential_file) if credential_file else None}
    # Persist ownership of both possible states before replacing either file.
    # Recovery finishes this exact transaction and refuses edited/unrelated bytes.
    transaction = {'version': 1, 'owner': 'dot-herdr', 'config': str(config), 'system': system}
    for name, data in (('previous_body', previous), ('next_body', body),
                       ('previous_receipt', before_receipt), ('next_receipt', encoded(value))):
        transaction[name] = None if data is None else base64.b64encode(data).decode('ascii')
    write_file(pending_path(config), encoded(transaction), backup=False)
    _sync_parent(pending_path(config))
    _recover_install(config)
    if system == 'Linux':
        _call([manager, '--user', 'daemon-reload'])
        _call([manager, '--user', 'enable' if login_start else 'disable', label])
    return value


def service_status(config):
    """Read service-manager facts without starting or changing the service."""
    if _absolute(pending_path(config)).exists():
        return {'installed': receipt_path(config).exists(), 'state': 'interrupted_install',
                'next_action': 'Repeat service install or a service management action to recover unchanged owned files.'}
    if not receipt_path(config).exists():
        return {'installed': False, 'state': 'not_installed'}
    value, _ = _owned(config)
    try:
        manager = _manager(value['system'])
        if value['system'] == 'Linux':
            result = _call([manager, '--user', 'show', value['label'],
                            '--property=ActiveState,SubState,MainPID,UnitFileState'])
            fields = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
            return {'installed': True, 'state': fields.get('ActiveState', 'unknown'),
                    'substate': fields.get('SubState', 'unknown'),
                    'pid': int(fields.get('MainPID', '0')), 'login_start': fields.get('UnitFileState') == 'enabled'}
        result = subprocess.run([manager, 'print', f"gui/{os.getuid()}/{value['label']}"],
                                capture_output=True, timeout=20)
        # launchctl print is not a stable machine JSON contract. Restrict extraction
        # to its explicit state and pid fields; unloaded means stopped, not missing manager.
        if result.returncode:
            _call([manager, 'print', f'gui/{os.getuid()}'])
            return {'installed': True, 'state': 'stopped', 'pid': 0, 'login_start': value['login_start']}
        fields = {}
        for line in result.stdout.decode().splitlines():
            key, sep, item = line.strip().partition(' = ')
            if sep and key in ('state', 'pid'):
                fields[key] = item
        return {'installed': True, 'state': fields.get('state', 'unknown'),
                'pid': int(fields.get('pid', '0')), 'login_start': value['login_start']}
    except (Rejected, ValueError, OSError, subprocess.SubprocessError):
        return {'installed': True, 'state': 'manager_unavailable', 'login_start': value['login_start']}


def manage(config, action):
    if action == 'status':
        return service_status(config)
    if action not in ('start', 'stop', 'restart', 'remove'):
        raise Rejected('invalid_service_action')
    with _ServiceLock(config):
        recovered = _recover_install(config)
        if recovered:
            value, _ = _owned(config)
            if value['system'] == 'Linux':
                manager = _manager(value['system'])
                _call([manager, '--user', 'daemon-reload'])
                _call([manager, '--user', 'enable' if value['login_start'] else 'disable', value['label']])
        return _manage(config, action)


def _launchagent_process(config, state):
    pid = state.get('pid', 0)
    if pid:
        return pid, process_identity(pid)
    # A previous bootout may already have removed the job while the runtime is
    # still cleaning up. Its private identity record lets a retry wait safely.
    path = status_path(config)
    try:
        raw = read_file(path, 16384)
        if raw is None or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
            return 0, None
        value = json.loads(raw)
        pid = value['pid']
        if (value.get('config') != str(_absolute(config)) or isinstance(pid, bool)
                or not isinstance(pid, int) or pid < 1):
            return 0, None
        identity = process_identity(pid)
        if identity is not None and identity == value.get('process_start'):
            return pid, identity
    except (Rejected, KeyError, TypeError, ValueError, OSError):
        pass
    return 0, None


def _await_launchagent_stopped(config, pid, identity, timeout=20):
    """bootout is asynchronous: wait before replacing or deleting the owned job.

    launchd can stop reporting the job before its former process exits. Retain
    its start identity so a reused PID never causes us to wait for another job.
    A timeout leaves the ownership receipt and plist available for recovery.
    """
    deadline = time.monotonic() + timeout
    while True:
        state = service_status(config)
        if state['state'] == 'manager_unavailable':
            raise Rejected('user_service_manager_unavailable_use_foreground')
        prior_running = identity is not None and process_identity(pid) == identity
        if state['state'] == 'stopped' and not prior_running:
            return
        if time.monotonic() >= deadline:
            raise Rejected('service_shutdown_timed_out_use_service_status')
        time.sleep(.1)


def _manage(config, action):
    value, raw = _owned(config)
    manager = _manager(value['system'])
    if value['system'] == 'Linux':
        _call([manager, '--user', 'stop' if action == 'remove' else action, value['label']])
        if action == 'remove':
            _call([manager, '--user', 'disable', value['label']])
    else:
        domain = f'gui/{os.getuid()}'
        target = domain + '/' + value['label']
        state = service_status(config)
        if state['state'] == 'manager_unavailable':
            raise Rejected('user_service_manager_unavailable_use_foreground')
        pid, identity = _launchagent_process(config, state)
        if action in ('stop', 'restart', 'remove'):
            if state['state'] != 'stopped':
                _call([manager, 'bootout', target])
            _await_launchagent_stopped(config, pid, identity)
        if action in ('start', 'restart'):
            if state['state'] == 'stopped' or action == 'restart':
                if action == 'start':
                    _await_launchagent_stopped(config, pid, identity)
                _call([manager, 'bootstrap', domain, value['path']])
            _call([manager, 'kickstart', target])
    if action == 'remove':
        # Recheck both the ownership receipt and generated bytes after manager calls.
        _, current = _owned(config)
        if current != raw:
            raise Rejected('service_not_owned_or_changed')
        Path(value['path']).unlink()
        receipt_path(config).unlink()
        if value['system'] == 'Linux':
            _call([manager, '--user', 'daemon-reload'])
        return {'installed': False, 'state': 'removed', 'logs_retained': True}
    return service_status(config)
