"""One foreground/service runtime, with bounded child and worker cleanup."""
import asyncio
import os
import platform
import sys
import subprocess
import time
import uuid
import shutil
from dataclasses import dataclass
from typing import Callable
from pathlib import Path

from .connections import encoded, read_file, safe_path, write_file
from .core import Rejected, Store
from .onboarding import private_directory
from .setup import load_config, placeholders


class TunnelRuntimeFailure(Rejected):
    """An exited tunnel child requires a service restart, not configuration repair."""


def status_path(config):
    path = Path(config).expanduser().absolute()
    return path.with_name(path.name + '.runtime.json')


def process_start(pid=None):
    """PID-reuse fence. None means process identity could not be verified."""
    pid = os.getpid() if pid is None else pid
    if not isinstance(pid, int) or pid < 1:
        return None
    try:
        if platform.system() == 'Linux':
            # comm may contain spaces or parentheses; fields after its last ')' are fixed.
            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] == 'Z':
                return None
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            return boot + ':' + fields[19]
        result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart='], capture_output=True, timeout=2)
        value = result.stdout.decode().strip()
        return value if result.returncode == 0 and value else None
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


process_identity = process_start


class RuntimeStatus:
    def __init__(self, config):
        self.path = safe_path(status_path(config))
        private_directory(self.path.parent)
        self.previous = read_file(self.path, 16384)
        if self.previous is not None and self.path.stat().st_mode & 0o077:
            raise Rejected('private_runtime_status_required')
        self.value = {'version': 1, 'instance': uuid.uuid4().hex,
                      'config': str(Path(config).absolute()), 'pid': os.getpid(),
                      'runtime_prefix': str(Path(sys.prefix).resolve()),
                      'process_start': process_start(), 'state': 'starting',
                      'http_started': False, 'workers': {'observer': 'starting', 'delivery': 'starting'},
                      'tunnel': 'disabled', 'cloudflared': 'disabled', 'error': None}

    def update(self, **changes):
        self.value.update(changes)
        self.value['updated_at'] = time.time()
        raw = encoded(self.value)
        write_file(self.path, raw, self.previous, backup=False)
        self.previous = raw


def credential_environment(path):
    """Read an explicitly selected launch key; never persist or present its value."""
    path = safe_path(path)
    if not path.is_file() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise Rejected('private_service_credential_required')
    raw = read_file(path, 8192)
    try:
        key = raw.decode('utf-8').removesuffix('\n')
    except (UnicodeDecodeError, AttributeError):
        raise Rejected('invalid_service_credential') from None
    if not key or any(ord(c) < 33 or ord(c) == 127 for c in key):
        raise Rejected('invalid_service_credential')
    return key


def tunnel_arguments(config, cfg, credential_file=None):
    from .tunnel import runtime_command
    if credential_file is None:
        return runtime_command(config, cfg=cfg)
    # runtime_command builds a restricted child environment. Restore the parent env
    # immediately; no key is retained in service-manager files or command arguments.
    key = credential_environment(credential_file)
    old = os.environ.get('CONTROL_PLANE_API_KEY')
    try:
        os.environ['CONTROL_PLANE_API_KEY'] = key
        return runtime_command(config, cfg=cfg)
    finally:
        if old is None:
            os.environ.pop('CONTROL_PLANE_API_KEY', None)
        else:
            os.environ['CONTROL_PLANE_API_KEY'] = old


@dataclass(frozen=True)
class TunnelProvider:
    name: str
    record_field: str
    command: Callable[[], tuple[list[str], dict[str, str]]]
    launch_failed: str
    stopped: str
    failed: str
    cleanup_timeout: str


def openai_provider(command):
    return TunnelProvider('openai', 'tunnel', lambda: command,
        'tunnel_runtime_launch_failed', 'tunnel_runtime_stopped',
        'tunnel_runtime_failed_run_tunnel_check', 'tunnel_runtime_cleanup_timeout')


def tunnel_provider(config, cfg, *, tunnel=False, credential_file=None, exposure=None):
    from .connections import exposure_for
    exposure = exposure_for(config) if exposure is None else exposure
    if tunnel and exposure:
        raise Rejected('openai_tunnel_and_cloudflare_exposure_conflict')
    if exposure:
        from .cloudflare import recorded_cloudflared, run_command
        binary = recorded_cloudflared(config) or shutil.which('cloudflared')
        if not binary:
            raise Rejected('cloudflared_not_found_install_it_see_docs_reachability')
        return TunnelProvider('cloudflare', 'cloudflared',
            lambda: run_command(config, exposure, binary),
            'cloudflared_runtime_launch_failed', 'cloudflared_runtime_stopped',
            'cloudflared_runtime_failed_check_status', 'cloudflared_runtime_cleanup_timeout')
    if tunnel:
        return openai_provider(tunnel_arguments(config, cfg, credential_file))
    return None


def builtin_signin_routes(config, cfg):
    if cfg.get('signin') != 'builtin':
        return None
    from . import signin
    root = signin.signin_root(config)
    signin.initialize(root)
    if not signin.has_password(root):
        raise Rejected('builtin_signin_password_not_set_run_dot_herdr_signin_set_password')
    return signin.routes(root, issuer=cfg['issuer'], resource=cfg['resource'])


async def launch_tunnel(provider):
    try:
        args, env = provider.command()
        setpriv = shutil.which('setpriv') if provider.name == 'cloudflare' and platform.system() == 'Linux' else None
        if setpriv:
            # setpriv execs cloudflared in place with a parent-death signal, so it stops with this process.
            args = [setpriv, '--pdeathsig', 'KILL', '--', *args]
        return await asyncio.create_subprocess_exec(*args, env=env,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise Rejected(provider.launch_failed) from None


async def reap_tunnel(child, provider):
    if child is None:
        return
    if child.returncode is None:
        try:
            child.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(child.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                child.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(child.wait(), timeout=5)
            except asyncio.TimeoutError:
                raise Rejected(provider.cleanup_timeout) from None
    else:
        await child.wait()


async def supervise(config, cfg, store, source, transport, http, *, tunnel_command=None, login=False, verifier=None, provider=None):
    """Run workers under HTTP lifetime; any fatal worker/child exit shuts it down."""
    from .herdr import watch
    from .webhooks import deliver_one
    provider = provider or (openai_provider(tunnel_command) if tunnel_command else None)
    record = RuntimeStatus(config)
    tasks = {}
    child = None
    failure = None
    login_task = None

    async def deliveries():
        while True:
            await deliver_one(store, transport)
            await asyncio.sleep(0.5)

    async def serve():
        try:
            await http.serve()
        except SystemExit:
            raise Rejected('runtime_listener_failed') from None

    async def ready():
        while not http.started:
            await asyncio.sleep(0.05)

    async def sign_in():
        await ready()
        from .login import login_mcp
        from .connections import connection_record
        selection=connection_record(config)
        if selection.get('wiring') in ('registered-plugin','plugin-http'):
            record.update(login='pending_app_authentication');return
        try:
            result = await login_mcp(cfg)
            if result.get('status') != 'authenticated':
                record.update(login='pending')
            else:
                record.update(login='client_login_completed')
        except (Rejected, OSError):
            record.update(login='pending')

    async def tunnel():
        nonlocal child
        await ready()
        child = await launch_tunnel(provider)
        record.update(**{provider.record_field: 'running'})
        code = await child.wait()
        raise Rejected(provider.failed if code else provider.stopped)

    async def heartbeat():
        while True:
            record.update(state='running' if http.started else 'starting', http_started=http.started,
                          last_verified_authentication=getattr(verifier, 'last_verified_at', None))
            await asyncio.sleep(2)

    try:
        record.update(workers={'observer': 'running', 'delivery': 'running'},
                      **({provider.record_field: 'starting'} if provider else {}))
        tasks = {'observer': asyncio.create_task(watch(store, source)),
                 'delivery': asyncio.create_task(deliveries()),
                 'http': asyncio.create_task(serve()),
                 'status': asyncio.create_task(heartbeat())}
        if provider:
            if provider.name == 'openai':
                from .tunnel import profile_paths
                health = profile_paths(config)[0] / 'health.url'
                if health.exists():
                    safe_path(health).unlink()
            tasks['tunnel'] = asyncio.create_task(tunnel())
        if login:
            login_task = asyncio.create_task(sign_in())
        done, _ = await asyncio.wait(tasks.values(), return_when=asyncio.FIRST_COMPLETED)
        # Worker failure wins over an HTTP stop occurring in the same scheduler turn.
        for name in ('observer', 'delivery', 'tunnel', 'status', 'http'):
            task = tasks.get(name)
            if task not in done:
                continue
            error = None if task.cancelled() else task.exception()
            if name == 'http' and error is None:
                continue
            if name in ('observer', 'delivery'):
                failure = 'runtime_' + name + '_failed'
            elif isinstance(error, Rejected):
                failure = str(error)
            else:
                failure = 'runtime_' + name + '_failed'
            break
        if failure:
            if provider and failure in (provider.failed, provider.stopped):
                raise TunnelRuntimeFailure(failure)
            raise Rejected(failure)
    finally:
        http.should_exit = True
        if login_task:
            login_task.cancel()
            await asyncio.gather(login_task, return_exceptions=True)
        # Cancel tunnel readiness/wait task before reaping its owned child.
        for name, task in tasks.items():
            if name != 'http':
                task.cancel()
        await asyncio.gather(*(task for name, task in tasks.items() if name != 'http'), return_exceptions=True)
        try:
            await reap_tunnel(child, provider)
        except Rejected as error:
            failure = str(error)
        http_task = tasks.get('http')
        if http_task and not http_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(http_task), timeout=5)
            except asyncio.TimeoutError:
                http_task.cancel()
        if http_task:
            await asyncio.gather(http_task, return_exceptions=True)
        record.update(state='failed' if failure else 'stopped', http_started=False,
                      error=failure, last_verified_authentication=getattr(verifier, 'last_verified_at', None), workers={name: 'failed' if failure == 'runtime_' + name + '_failed' else 'stopped'
                                              for name in ('observer', 'delivery')},
                      **({provider.record_field: 'stopped'} if provider else {}))
        if provider and failure == provider.cleanup_timeout:
            raise Rejected(failure)


async def run(config, *, cfg=None, tunnel=False, login=False, credential_file=None):
    """Shared entry point. Store ownership is acquired once and always released."""
    cfg = load_config(config) if cfg is None else cfg
    if placeholders(cfg):
        raise Rejected('operator_placeholders_remaining')
    if cfg.get('inactive') or not cfg['subjects'] and not cfg.get('session_users'):
        raise Rejected('inactive_configuration_select_access')
    from .endpoint import principal_key, build
    from .herdr import HerdrClient
    from .webhooks import PublicTransport
    from .auth import verifier_from_config
    from .auth import record_verified_scopes
    verifier = verifier_from_config(cfg,on_verified=lambda token:record_verified_scopes(config,token))
    provider = tunnel_provider(config, cfg, tunnel=tunnel, credential_file=credential_file)
    signin_routes = builtin_signin_routes(config, cfg)
    if credential_file and not tunnel:
        raise Rejected('service_credential_requires_tunnel')
    def approved_configuration():
        # The owner lock fences access changes before schema/roster/grant startup.
        if load_config(config)!=cfg:
            raise Rejected('configuration_changed_before_startup')
    store = Store(Path(cfg['store']),preflight=approved_configuration)
    try:
        store.apply_roster([{**subject, 'principal': principal_key(cfg['issuer'], subject['user_subject'])}
                            for subject in cfg['subjects']])
        source = HerdrClient(cfg['socket'])
        transport = PublicTransport()
        controls = {s['key'] for s in cfg['subjects'] if s.get('control', False)}
        users = {principal_key(cfg['issuer'], u) for u in cfg.get('session_users', [])}
        server = build(store, source, transport, verifier, cfg['issuer'], cfg['resource'],
                       controls=controls, session_users=users, local_port=cfg.get('local_port',8000),
                       **({'signin_routes': signin_routes} if signin_routes is not None else {}))
        app = server.streamable_http_app(json_response=True, stateless_http=True,
                                        max_request_body_size=65536, host='127.0.0.1')
        import uvicorn
        http = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=cfg.get('local_port',8000),
                              log_level='warning', access_log=False, proxy_headers=False))
        await supervise(config, cfg, store, source, transport, http, provider=provider, login=login, verifier=verifier)
    finally:
        store.close()
