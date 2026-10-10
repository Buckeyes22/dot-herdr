"""Opt-in Cloudflare tunnel provisioning with an explicit ownership journal."""
import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path

import httpx2

from .core import Rejected

INSTALL_DOCS = 'https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/'
API = 'https://api.cloudflare.com/client/v4'
MAX_RESPONSE = 65536


def cloudflare_root(config):
    root = Path(config).expanduser().absolute().parent / 'cloudflare'
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid():
        raise Rejected('private_cloudflare_directory_required')
    os.chmod(root, 0o700)
    return root


def install_id(config):
    return hashlib.sha256(str(Path(config).expanduser().absolute()).encode()).hexdigest()[:16]


def detect_cloudflared(*, which=shutil.which, run=subprocess.run):
    path = which('cloudflared')
    if not path:
        return None
    try:
        result = run([path, '--version'], capture_output=True, text=True, timeout=3, env=_child_env())
    except (OSError, subprocess.SubprocessError):
        return {'path': path, 'version': 'unavailable'}
    output = (result.stdout or result.stderr or '').strip()[:512]
    return {'path': path, 'version': output or 'unknown'}


def ingress_rules(hostname, local_port):
    if not isinstance(hostname, str) or not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', hostname):
        raise Rejected('invalid_cloudflare_hostname')
    if not isinstance(local_port, int) or isinstance(local_port, bool) or not 1 <= local_port <= 65535:
        raise Rejected('invalid_cloudflare_local_port')
    return [{'hostname': hostname, 'service': f'http://127.0.0.1:{local_port}', 'originRequest': {'httpHostHeader': hostname}}, {'service': 'http_status:404'}]


class CloudflareAPI:
    def __init__(self, token, *, transport=None, base_url=API):
        if not isinstance(token, str) or not token:
            raise Rejected('cloudflare_api_token_required')
        self._token = token
        self._base_url = base_url.rstrip('/')
        self._transport = transport

    async def _request(self, method, path, *, params=None, payload=None, envelope=False, missing_ok=False):
        try:
            async with asyncio.timeout(12):
                async with httpx2.AsyncClient(trust_env=False, follow_redirects=False, timeout=8, transport=self._transport) as client:
                    async with client.stream(method, self._base_url + path, params=params,
                        headers={'Authorization': 'Bearer ' + self._token, 'Accept': 'application/json', 'Accept-Encoding': 'identity'}, json=payload) as response:
                        if response.headers.get('content-encoding', 'identity').lower() != 'identity':
                            raise Rejected('cloudflare_encoded_response_not_allowed')
                        if response.status_code == 404 and missing_ok:
                            return None
                        data = bytearray()
                        async for chunk in response.aiter_bytes():
                            data.extend(chunk)
                            if len(data) > MAX_RESPONSE:
                                raise Rejected('cloudflare_response_too_large')
                        try:
                            body = json.loads(data)
                        except (ValueError, UnicodeDecodeError):
                            raise Rejected('cloudflare_invalid_response') from None
                        if response.status_code >= 400 or not isinstance(body, dict) or body.get('success') is False:
                            raise Rejected('cloudflare_api_operation_failed')
                        if missing_ok and not isinstance(body.get('result'), dict):
                            raise Rejected('cloudflare_invalid_response')
                        return body if envelope else body.get('result')
        except Rejected:
            raise
        except (httpx2.HTTPError, TimeoutError, OSError):
            raise Rejected('cloudflare_api_unavailable') from None

    async def zone_for_hostname(self, hostname):
        labels = hostname.rstrip('.').split('.')
        for i in range(len(labels)-1):
            result = await self._request('GET', '/zones', params={'name': '.'.join(labels[i:]), 'per_page': 1})
            if result:
                zone = result[0]
                return {'id': zone['id'], 'name': zone['name'], 'account_id': zone['account']['id']}
        raise Rejected('cloudflare_zone_not_found')

    async def list_tunnels(self, account):
        return await self._list(f'/accounts/{account}/cfd_tunnels', {'is_deleted': 'false'})

    async def _list(self, path, params):
        rows = []
        total = None
        seen = set()
        for page in range(1, 1001):
            body = await self._request('GET', path, params={**params, 'page': page, 'per_page': 100}, envelope=True)
            result, info = body.get('result'), body.get('result_info')
            if not isinstance(result, list) or any(not isinstance(r, dict) or not isinstance(r.get('id'), str) for r in result):
                raise Rejected('cloudflare_incomplete_enumeration')
            ids = [r['id'] for r in result]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise Rejected('cloudflare_incomplete_enumeration')
            seen.update(ids)
            rows.extend(result)
            if info is None:
                # A short page proves completion when pagination metadata is absent.
                if len(result) < 100:
                    return rows
                continue
            if not isinstance(info, dict) or any(type(info.get(k)) is not int for k in ('page', 'total_pages', 'total_count')):
                raise Rejected('cloudflare_incomplete_enumeration')
            if page == 1 and info['page'] == 1 and info['total_pages'] == 0 and info['total_count'] == 0 and not result:
                return []
            if info['page'] != page or info['total_pages'] < page or info['total_count'] < len(rows):
                raise Rejected('cloudflare_incomplete_enumeration')
            if total is not None and total != (info['total_pages'], info['total_count']):
                raise Rejected('cloudflare_incomplete_enumeration')
            total = (info['total_pages'], info['total_count'])
            if page == info['total_pages']:
                if len(rows) != info['total_count']:
                    raise Rejected('cloudflare_incomplete_enumeration')
                return rows
            if not result:
                raise Rejected('cloudflare_incomplete_enumeration')
        raise Rejected('cloudflare_incomplete_enumeration')

    async def create_tunnel(self, account, name):
        return await self._request('POST', f'/accounts/{account}/cfd_tunnel', payload={'name': name, 'config_src': 'cloudflare'})

    async def get_tunnel(self, account, tunnel):
        return await self._request('GET', f'/accounts/{account}/cfd_tunnel/{tunnel}', missing_ok=True)

    async def tunnel_token(self, account, tunnel):
        return await self._request('GET', f'/accounts/{account}/cfd_tunnel/{tunnel}/token')

    async def configure_tunnel(self, account, tunnel, ingress):
        return await self._request('PUT', f'/accounts/{account}/cfd_tunnel/{tunnel}/configurations', payload={'config': {'ingress': ingress}})

    async def list_dns(self, zone, name):
        return await self._list(f'/zones/{zone}/dns_records', {'name': name})

    async def create_dns(self, zone, hostname, tunnel):
        return await self._request('POST', f'/zones/{zone}/dns_records', payload={'type': 'CNAME', 'name': hostname, 'content': tunnel + '.cfargotunnel.com', 'proxied': True})

    async def delete_dns(self, zone, record):
        return await self._request('DELETE', f'/zones/{zone}/dns_records/{record}')

    async def delete_tunnel(self, account, tunnel):
        return await self._request('DELETE', f'/accounts/{account}/cfd_tunnel/{tunnel}')

    async def cleanup_connections(self, account, tunnel):
        return await self._request('DELETE', f'/accounts/{account}/cfd_tunnel/{tunnel}/connections')


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise Rejected('invalid_cloudflare_tunnel_id') from None
    return value


def _executable(path):
    if not isinstance(path, str) or not Path(path).is_absolute() or not Path(path).is_file() or not os.access(path, os.X_OK):
        raise Rejected('cloudflared_executable_required')
    return path


def _recorded_path(path):
    if (not isinstance(path, str) or len(path) > 4096 or not Path(path).is_absolute()
            or any(ord(char) < 32 or ord(char) == 127 for char in path)):
        raise Rejected('cloudflare_journal_untrusted')
    return path


def _binary(path=None):
    found = path or shutil.which('cloudflared')
    if found and not Path(found).is_absolute():
        found = shutil.which(found)
    return _executable(found)


def _select_binary_optional(config, explicit=None, *, home=None):
    value = Journal(config, home=home).read()
    recorded = value['cloudflared'] if value else None
    if explicit is not None:
        try:
            return _binary(explicit)
        except Rejected:
            return recorded
    if recorded and Path(recorded).is_file() and os.access(recorded, os.X_OK):
        return recorded
    try:
        return _binary()
    except Rejected:
        return recorded


def _select_binary(config, explicit=None, *, home=None):
    if explicit is not None:
        return _binary(explicit)
    value = Journal(config, home=home).read()
    recorded = value['cloudflared'] if value else None
    if recorded and Path(recorded).is_file() and os.access(recorded, os.X_OK):
        return recorded
    try:
        return _binary()
    except Rejected:
        raise Rejected('cloudflared_not_found_install_it_see_docs_reachability') from None


class Journal:
    """Version 2: explicit derived paths and durable provisioning/cleanup state."""
    def __init__(self, config, *, home=None):
        self.config = config
        self.root = Path(config).expanduser().absolute().parent / 'cloudflare'
        self.path = self.root / 'journal.json'
        self.home = Path(home or Path.home()).expanduser().absolute()

    def _validate(self, value):
        try:
            if not isinstance(value, dict):
                raise ValueError
            common = {'owner', 'version', 'mode', 'hostname', 'phase', 'tunnel', 'dns', 'cloudflared', 'tunnel_removed'}
            mode = value.get('mode')
            fields = common | ({'account', 'zone', 'token_file'} if mode == 'api' else {'home', 'credentials', 'config'})
            if mode not in ('api', 'login') or set(value) - {'deletion_pending'} != fields:
                raise ValueError
            if value['owner'] != 'dot-herdr' or type(value['version']) is not int or value['version'] != 2:
                raise ValueError
            ingress_rules(value['hostname'], 8000)
            if value['phase'] not in ('tunnel_pending', 'tunnel_created', 'dns_pending', 'dns_routed', 'complete') or type(value['tunnel_removed']) is not bool:
                raise ValueError
            if 'deletion_pending' in value and type(value['deletion_pending']) is not bool:
                raise ValueError
            tunnel = value['tunnel']
            if not isinstance(tunnel, dict) or set(tunnel) != {'id', 'name'}:
                raise ValueError
            tid = None if value['phase'] == 'tunnel_pending' and tunnel['id'] is None else _uuid(tunnel['id'])
            if tunnel['name'] != 'dot-herdr-' + install_id(self.config):
                raise ValueError
            if value['cloudflared'] is not None:
                _recorded_path(value['cloudflared'])
            dns = value['dns']
            if dns is not None:
                if tid is None:
                    raise ValueError
                if not isinstance(dns, dict) or set(dns) != {'id', 'name', 'content'}:
                    raise ValueError
                if dns['name'] != value['hostname'] or dns['content'] != tid + '.cfargotunnel.com':
                    raise ValueError
                if dns['id'] is not None and (not isinstance(dns['id'], str) or not re.fullmatch(r'[A-Za-z0-9_-]+', dns['id'])):
                    raise ValueError
                if mode == 'api' and dns['id'] is None:
                    raise ValueError
            if mode == 'api':
                if not isinstance(value['account'], str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value['account']):
                    raise ValueError
                zone = value['zone']
                if not isinstance(zone, dict) or set(zone) != {'id', 'name', 'account_id'} or zone['account_id'] != value['account']:
                    raise ValueError
                if not isinstance(zone['id'], str) or not re.fullmatch(r'[A-Za-z0-9_-]+', zone['id']):
                    raise ValueError
                ingress_rules(zone['name'], 8000)
                if value['token_file'] != str(self.root / 'tunnel.token'):
                    raise ValueError
            else:
                if value['home'] != str(self.home) or value['credentials'] != (str(self.home / '.cloudflared' / (tid + '.json')) if tid else None) or value['config'] != str(self.root / 'config.yml'):
                    raise ValueError
            return value
        except (ValueError, TypeError, KeyError, Rejected):
            raise Rejected('cloudflare_journal_untrusted') from None

    def read(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError:
            raise Rejected('cloudflare_journal_untrusted') from None
        try:
            with os.fdopen(fd) as stream:
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
                    raise ValueError
                if self.root.is_symlink() or self.root.stat().st_uid != os.getuid():
                    raise ValueError
                return self._validate(json.loads(stream.read(MAX_RESPONSE + 1)))
        except (OSError, ValueError, TypeError):
            raise Rejected('cloudflare_journal_untrusted') from None

    def write(self, value):
        value = self._validate({'version': 2, 'owner': 'dot-herdr', **value})
        cloudflare_root(self.config)
        _private_write(self.path, json.dumps(value, sort_keys=True))

    def remove(self):
        self.read()
        self.path.unlink(missing_ok=True)


def recorded_cloudflared(config):
    value = Journal(config).read()
    path = value['cloudflared'] if value else None
    return path if path and Path(path).is_file() and os.access(path, os.X_OK) else None


def _record(journal, mode, hostname, tid, binary, *, zone=None):
    value = {'mode': mode, 'hostname': hostname, 'phase': 'tunnel_created' if tid else 'tunnel_pending',
             'tunnel': {'id': _uuid(tid) if tid else None, 'name': 'dot-herdr-' + install_id(journal.config)},
             'dns': None, 'cloudflared': binary, 'tunnel_removed': False}
    if mode == 'api':
        value.update(account=zone['account_id'], zone=zone, token_file=str(journal.root / 'tunnel.token'))
    else:
        value.update(home=str(journal.home), credentials=str(journal.home / '.cloudflared' / (tid + '.json')) if tid else None, config=str(journal.root / 'config.yml'))
    return value


def _pending_dns(value, records):
    target = value['tunnel']['id'] + '.cfargotunnel.com'
    matches = [r for r in records if r.get('name') == value['hostname']
               and r.get('type') == 'CNAME' and r.get('content') == target]
    if len(matches) > 1:
        raise Rejected('cloudflare_dns_ownership_unavailable')
    if matches:
        return {'id': matches[0]['id'], 'name': value['hostname'], 'content': target}
    return None


def _exposure(value):
    return {'provider': 'cloudflare', 'hostname': value['hostname'], 'tunnel_id': value['tunnel']['id'], 'mode': value['mode']}


async def expose_api(config, hostname, local_port, token, *, api=None, say=print, cloudflared=None):
    rules = ingress_rules(hostname, local_port)
    journal = Journal(config)
    old = journal.read()
    if old and (old['mode'] != 'api' or old['hostname'] != hostname or old['tunnel_removed'] or old.get('deletion_pending')):
        raise Rejected('cloudflare_other_exposure_requires_remove')
    binary = _select_binary_optional(config, cloudflared)
    if old and binary is not None:
        old['cloudflared'] = binary
    api = api or CloudflareAPI(token)
    created = old is None
    if old and old['phase'] != 'tunnel_pending':
        value = old
        current = await api.get_tunnel(value['account'], value['tunnel']['id'])
        if not isinstance(current, dict) or current.get('id') != value['tunnel']['id'] or current.get('name') != value['tunnel']['name']:
            raise Rejected('cloudflare_owned_tunnel_missing')
    else:
        if old:
            value = old
            zone = value['zone']
        else:
            zone = await api.zone_for_hostname(hostname)
            if any(t.get('name') == 'dot-herdr-' + install_id(config) for t in await api.list_tunnels(zone['account_id'])):
                raise Rejected('cloudflare_foreign_tunnel_exists')
            if await api.list_dns(zone['id'], hostname):
                raise Rejected('cloudflare_foreign_dns_record_exists')
            value = _record(journal, 'api', hostname, None, binary, zone=zone)
            journal.write(value)
        matches = [t for t in await api.list_tunnels(zone['account_id']) if t.get('name') == value['tunnel']['name']] if old else []
        if len(matches) > 1:
            raise Rejected('cloudflare_tunnel_ownership_unavailable')
        tunnel = matches[0] if matches else await api.create_tunnel(zone['account_id'], value['tunnel']['name'])
        value = _record(journal, 'api', hostname, tunnel['id'], binary, zone=zone)
        journal.write(value)
    account, tid = value['account'], value['tunnel']['id']
    try:
        records = await api.list_dns(value['zone']['id'], hostname)
        if value['phase'] == 'dns_pending':
            value['dns'] = _pending_dns(value, records)
            if value['dns']:
                value['phase'] = 'dns_routed'
                journal.write(value)
        dns = value['dns']
        rec = next((r for r in records if dns and r.get('id') == dns['id']), None)
        if any(not dns or r.get('id') != dns['id'] for r in records):
            raise Rejected('cloudflare_foreign_dns_record_exists')
        if rec and (rec.get('name') != hostname or rec.get('type') != 'CNAME' or rec.get('content') != dns['content']):
            raise Rejected('cloudflare_owned_dns_changed')
        await api.configure_tunnel(account, tid, rules)
        if not rec:
            value['phase'] = 'dns_pending'
            journal.write(value)
            rec = await api.create_dns(value['zone']['id'], hostname, tid)
            value['dns'] = {'id': rec['id'], 'name': hostname, 'content': tid + '.cfargotunnel.com'}
            value['phase'] = 'dns_routed'
            journal.write(value)
        _private_write(Path(value['token_file']), str(await api.tunnel_token(account, tid)))
        value['phase'] = 'complete'
        journal.write(value)
    except BaseException:
        if created:
            try:
                await remove(config, api=api, say=say)
            except Exception:
                pass  # Durable journal retains all remaining ownership.
        raise
    return _exposure(value)


def _private_write(path, text):
    path = Path(path)
    if path.exists() or path.is_symlink():
        _verify_private(path)
    fd, tmp = tempfile.mkstemp(prefix='.secret-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _command(run, args, *, on_failure=None):
    try:
        result = run(args, capture_output=True, text=True, timeout=30, env=_child_env())
    except (OSError, subprocess.SubprocessError):
        raise Rejected('cloudflared_command_failed') from None
    if result.returncode:
        if on_failure is not None:
            on_failure()
        raise Rejected('cloudflared_command_failed')
    output = result.stdout or ''
    if len(output.encode()) > MAX_RESPONSE:
        raise Rejected('cloudflared_response_too_large')
    return output


def _credentials(path, home):
    """Check ancestors and open the leaf relative to a nofollow directory fd."""
    home = Path(home)
    for parent in [home, *home.parents]:
        if parent.is_symlink():
            raise Rejected('cloudflare_login_credentials_path_rejected')
    directory = home / '.cloudflared'
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(dfd)
            if st.st_uid != os.getuid():
                raise ValueError
            os.fchmod(dfd, 0o700)
            fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                    raise ValueError
                if stat.S_IMODE(st.st_mode) != 0o600:
                    os.fchmod(fd, 0o600)
                if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                    raise ValueError
            finally:
                os.close(fd)
        finally:
            os.close(dfd)
    except (OSError, ValueError):
        raise Rejected('cloudflare_login_credentials_path_rejected') from None
    return Path(path)


def expose_login(config, hostname, local_port, *, cloudflared=None, run=subprocess.run, say=print, home=None):
    rules = ingress_rules(hostname, local_port)
    journal = Journal(config, home=home)
    value = journal.read()
    if value and (value['mode'] != 'login' or value['hostname'] != hostname or value['tunnel_removed'] or value.get('deletion_pending')):
        raise Rejected('cloudflare_other_exposure_requires_remove')
    binary = _select_binary(config, cloudflared)
    pending = value is not None and value['phase'] == 'tunnel_pending'
    if value and not pending:
        _login_ownership(value, binary, run, say)
        value['cloudflared'] = binary
    created = value is None
    validated_creds = None
    output = ''
    if created:
        cert = journal.home / '.cloudflared' / 'cert.pem'
        if cert.exists():
            say(f'Using existing Cloudflare certificate at {cert}.')
        else:
            say(f'cloudflared tunnel login leaves an account-wide certificate at {cert}; you can delete it afterwards.')
            try:
                result = run([binary, 'tunnel', 'login'], timeout=900, env=_child_env())
                if result.returncode:
                    raise Rejected('cloudflared_command_failed')
            except (OSError, subprocess.SubprocessError):
                raise Rejected('cloudflared_command_failed') from None
        value = _record(journal, 'login', hostname, None, binary)
        journal.write(value)
    if created or pending:
        matches = [r for r in _login_tunnels(binary, run) if r.get('name') == value['tunnel']['name']] if pending else []
        if len(matches) > 1:
            raise Rejected('cloudflare_tunnel_ownership_unavailable')
        if matches:
            tid = _uuid(matches[0]['id'])
        else:
            output = _command(run, [binary, 'tunnel', 'create', value['tunnel']['name']])
            match = re.search(r'\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b', output)
            if not match:
                raise Rejected('cloudflared_tunnel_id_missing')
            tid = _uuid(match.group(1))
        value = _record(journal, 'login', hostname, tid, binary)
        journal.write(value)
    try:
        if created:
            candidate = re.search(r'Tunnel credentials written to\s+(.+)', output, re.I)
            raw_path = candidate.group(1).strip() if candidate else value['credentials']
            if raw_path != value['credentials']:
                raise Rejected('cloudflare_login_credentials_path_rejected')
        validated_creds = _credentials(value['credentials'], journal.home)
        if value['phase'] in ('tunnel_created', 'dns_pending'):
            value['phase'] = 'dns_pending'
            journal.write(value)
            def route_rejected():
                if created:
                    value['phase'] = 'tunnel_created'
                    journal.write(value)
            _command(run, [binary, 'tunnel', 'route', 'dns', value['tunnel']['id'], hostname],
                     on_failure=route_rejected)
            value['dns'] = {'id': None, 'name': hostname, 'content': value['tunnel']['id'] + '.cfargotunnel.com'}
            value['phase'] = 'dns_routed'
            journal.write(value)
        cloudflare_root(config)
        _private_write(Path(value['config']), json.dumps({'tunnel': value['tunnel']['id'], 'credentials-file': value['credentials'], 'ingress': rules}, indent=2))
        value['phase'] = 'complete'
        journal.write(value)
    except BaseException:
        if created and value['phase'] == 'tunnel_created':
            try:
                _command(run, [binary, 'tunnel', 'delete', '-f', value['tunnel']['id']])
                if validated_creds is not None:
                    validated_creds.unlink(missing_ok=True)
                journal.remove()
            except Exception:
                pass
        raise
    return _exposure(value)


def _login_tunnels(binary, run):
    output = _command(run, [binary, 'tunnel', 'list', '-o', 'json'])
    try:
        rows = json.loads(output)
        if not isinstance(rows, list) or any(not isinstance(r, dict) or not isinstance(r.get('id'), str) or not isinstance(r.get('name'), str) for r in rows):
            raise ValueError
        return rows
    except (ValueError, TypeError):
        raise Rejected('cloudflare_tunnel_ownership_unavailable') from None


def _login_ownership(value, binary, run, say):
    rows = _login_tunnels(binary, run)
    current = next((r for r in rows if r.get('id') == value['tunnel']['id']), None)
    if current is None:
        if value.get('deletion_pending'):
            return False
        raise Rejected('cloudflare_owned_tunnel_missing')
    if current.get('name') != value['tunnel']['name']:
        say(f"Tunnel {value['tunnel']['id']} is no longer named {value['tunnel']['name']}; preserved the tunnel and ownership journal.")
        raise Rejected('cloudflare_tunnel_ownership_changed')
    return True


async def remove(config, *, token=None, api=None, cloudflared=None, run=subprocess.run, say=print, home=None):
    journal = Journal(config, home=home)
    value = journal.read()
    if not value:
        return None
    if value['mode'] == 'api':
        binary = _select_binary_optional(config, cloudflared)
        if binary is not None:
            value['cloudflared'] = binary
    else:
        binary = _select_binary(config, cloudflared, home=home)
        value['cloudflared'] = binary
    if value['phase'] == 'tunnel_pending':
        if value['mode'] == 'api':
            if api is None and not token:
                raise Rejected('cloudflare_api_token_required_for_remove')
            api = api or CloudflareAPI(token)
            rows = await api.list_tunnels(value['account'])
        else:
            rows = _login_tunnels(binary, run)
        matches = [r for r in rows if r.get('name') == value['tunnel']['name']]
        if len(matches) > 1:
            raise Rejected('cloudflare_tunnel_ownership_unavailable')
        if not matches:
            journal.remove()
            return None
        value = _record(journal, value['mode'], value['hostname'], matches[0]['id'], binary,
                        zone=value.get('zone'))
        journal.write(value)
    if value['mode'] == 'api':
        if api is None and not token:
            raise Rejected('cloudflare_api_token_required_for_remove')
        api = api or CloudflareAPI(token)
        if not value['tunnel_removed']:
            current = await api.get_tunnel(value['account'], value['tunnel']['id'])
            if current is not None and (not isinstance(current, dict) or current.get('id') != value['tunnel']['id'] or current.get('name') != value['tunnel']['name']):
                raise Rejected('cloudflare_tunnel_ownership_changed')
    elif not value['tunnel_removed']:
        if not _login_ownership(value, binary, run, say):
            value['tunnel_removed'] = True
            journal.write(value)
    if value['phase'] == 'dns_pending':
        if value['mode'] == 'api' or api is not None or token:
            api = api or CloudflareAPI(token)
            zone = value['zone'] if value['mode'] == 'api' else await api.zone_for_hostname(value['hostname'])
            value['dns'] = _pending_dns(value, await api.list_dns(zone['id'], value['hostname']))
            value['phase'] = 'dns_routed' if value['dns'] else 'tunnel_created'
        else:
            # cloudflared has no DNS read/delete command; retain the exact pending target.
            value['dns'] = {'id': None, 'name': value['hostname'],
                            'content': value['tunnel']['id'] + '.cfargotunnel.com'}
        journal.write(value)
    dns = value['dns']
    if dns and (value['mode'] == 'api' or api is not None or token):
        api = api or CloudflareAPI(token)
        zone = value['zone'] if value['mode'] == 'api' else await api.zone_for_hostname(value['hostname'])
        records = await api.list_dns(zone['id'], dns['name'])
        for record in records:
            if record.get('name') != dns['name'] or (dns['id'] is not None and record.get('id') != dns['id']):
                continue
            if record.get('type') == 'CNAME' and record.get('content') == dns['content']:
                await api.delete_dns(zone['id'], record['id'])
            else:
                say(f"Cloudflare DNS record {dns['name']} is now {record.get('type')} {record.get('content')}; preserved it.")
        value['dns'] = None
        journal.write(value)
    if not value['tunnel_removed']:
        if value['mode'] == 'api':
            if current is not None:
                try:
                    await api.cleanup_connections(value['account'], value['tunnel']['id'])
                    await api.delete_tunnel(value['account'], value['tunnel']['id'])
                except Rejected:
                    raise Rejected('cloudflare_tunnel_delete_failed_stop_dot_herdr_first') from None
        else:
            value['deletion_pending'] = True
            journal.write(value)
            _command(run, [binary, 'tunnel', 'delete', '-f', value['tunnel']['id']])
        value['tunnel_removed'] = True
        journal.write(value)
    paths = [value['token_file']] if value['mode'] == 'api' else [value['config'], value['credentials']]
    for path in paths:
        p = Path(path)
        if p.exists() or p.is_symlink():
            if value['mode'] == 'login' and path == value['credentials']:
                _credentials(path, journal.home)
            else:
                _verify_private(p)
            p.unlink()
    if value['mode'] == 'login':
        say('Leaving Cloudflare account certificate in place: ' + str(journal.home / '.cloudflared' / 'cert.pem'))
    if value['dns']:
        say('Partial removal; DNS cleanup pending. Delete this CNAME manually if it remains: ' + dns['name'] + ' → ' + dns['content'])
    else:
        journal.remove()
    return None


def run_command(config, exposure, cloudflared_path):
    value = Journal(config).read()
    if not isinstance(exposure, dict) or not value or exposure.get('mode') not in ('api', 'login'):
        raise Rejected('invalid_cloudflare_exposure')
    tid = _uuid(exposure.get('tunnel_id'))
    if exposure['mode'] != value['mode'] or tid != value['tunnel']['id'] or value['phase'] != 'complete' or value['tunnel_removed']:
        raise Rejected('invalid_cloudflare_exposure')
    binary = _binary(cloudflared_path)
    if value['mode'] == 'api':
        _verify_private(value['token_file'])
        return [binary, 'tunnel', '--no-autoupdate', 'run', '--token-file', value['token_file']], _child_env()
    _credentials(value['credentials'], Path(value['home']))
    _verify_private(value['config'])
    return [binary, 'tunnel', '--no-autoupdate', '--config', value['config'], 'run', tid], _child_env()


def _verify_private(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
                raise ValueError
        finally:
            os.close(fd)
    except (OSError, ValueError):
        raise Rejected('cloudflare_private_file_required') from None


def _child_env():
    allowed = {
        'HOME', 'PATH', 'USER', 'LOGNAME', 'LANG', 'TZ', 'TMPDIR',
        'XDG_CONFIG_HOME', 'XDG_RUNTIME_DIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
        'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY',
        'https_proxy', 'http_proxy', 'no_proxy',
    }
    return {key: value for key, value in os.environ.items()
            if (key in allowed or key.startswith('LC_'))
            and not any(secret in key.upper() for secret in ('TOKEN', 'KEY', 'SECRET'))}
