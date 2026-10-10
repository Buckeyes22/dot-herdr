"""Owned Secure MCP Tunnel profile and foreground supervision using OpenAI's client."""
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from .connections import LOCAL_URL, encoded, read_file, safe_path, write_file, local_url
from .core import Rejected
from .onboarding import private_directory

RELEASE_API = 'https://api.github.com/repos/openai/tunnel-client/releases/latest'
TUNNEL_SETTINGS = 'https://platform.openai.com/settings/organization/tunnels'
PROFILE = 'dot-herdr'


def fetch(url, limit):
    request = urllib.request.Request(url, headers={'User-Agent': 'dot-herdr'})
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.geturl().startswith('https://'):
            raise Rejected('tunnel_insecure_download')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise Rejected('tunnel_download_too_large')
    return data


def install_client(root):
    """Download the official platform bundle, verify its release digest, retain notices."""
    system = platform.system().lower()
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
    if system not in ('linux', 'darwin') or not arch:
        raise Rejected('tunnel_unsupported_platform')
    release = json.loads(fetch(RELEASE_API, 1048576))
    if not isinstance(release,dict) or not isinstance(release.get('assets'),list):
        raise Rejected('tunnel_invalid_release')
    tag = release.get('tag_name', '')
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise Rejected('tunnel_invalid_release')
    name = f'tunnel-client-{tag}-{system}-{arch}.zip'
    assets = [a for a in release['assets'] if isinstance(a,dict) and a.get('name') == name]
    if len(assets) != 1:
        raise Rejected('tunnel_release_asset_missing')
    asset = assets[0]
    expected_url = 'https://github.com/openai/tunnel-client/releases/download/' + tag + '/' + name
    digest = asset.get('digest') or ''
    if asset.get('browser_download_url') != expected_url or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise Rejected('tunnel_release_digest_missing')
    raw = fetch(expected_url, 104857600)
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
        raise Rejected('tunnel_download_digest_mismatch')
    try:bundle = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:raise Rejected('tunnel_invalid_bundle') from None
    wanted = ['tunnel-client', 'LICENSE', 'NOTICE', name.removesuffix('.zip') + '-licenses.txt', name.removesuffix('.zip') + '.spdx.json']
    payload = {}
    for filename in wanted:
        try:entry = bundle.getinfo(filename)
        except KeyError:raise Rejected('tunnel_invalid_bundle') from None
        if entry.file_size > 157286400 or (entry.external_attr >> 16) & 0o170000 == 0o120000:
            raise Rejected('tunnel_invalid_bundle')
        payload[filename] = bundle.read(entry)
    destination = safe_path(root / 'client' / tag)
    # No archive path is extracted; only these fixed basename entries are written.
    for filename, body in payload.items():
        path = destination / filename
        before = read_file(path, 157286400)
        if before is not None and before != body:
            raise Rejected('tunnel_existing_binary_changed')
        if before is None:
            write_file(path, body)
    binary = destination / 'tunnel-client'
    binary.chmod(0o700)
    return binary, {'release': tag, 'archive_sha256': digest.removeprefix('sha256:')}


def profile_paths(config):
    root = safe_path(Path(config).absolute().parent / 'tunnel')
    return root, root / 'settings.json', root / 'profiles' / (PROFILE + '.yaml')


def profile_settings(config):
    from .setup import load_config
    endpoint=local_url(load_config(config)) if Path(config).is_file() else LOCAL_URL
    root, settings, profile = profile_paths(config)
    body = read_file(settings)
    if body is None:
        raise Rejected('tunnel_not_configured_run_tunnel_setup')
    if settings.stat().st_mode & 0o077:
        raise Rejected('tunnel_private_settings_required')
    value = json.loads(body)
    required={'tunnel_id','binary','endpoint','profile_sha256','binary_sha256','release'}
    if not isinstance(value,dict) or not required<=set(value) or any(not isinstance(v,str) for v in value.values()):
        raise Rejected('tunnel_invalid_settings')
    if not re.fullmatch(r'tunnel_[A-Za-z0-9_-]{1,128}',value['tunnel_id']) or value['endpoint']!=endpoint or any(not re.fullmatch(r'[0-9a-f]{64}',value[k]) for k in ('profile_sha256','binary_sha256')):
        raise Rejected('tunnel_invalid_settings')
    binary = Path(value.get('binary', ''))
    if not binary.is_absolute() or not binary.is_file():
        raise Rejected('tunnel_client_missing')
    raw = read_file(profile)
    if raw is None or hashlib.sha256(raw).hexdigest() != value.get('profile_sha256') or profile.stat().st_mode & 0o077:
        raise Rejected('tunnel_profile_changed')
    actual = read_file(binary, 157286400)
    if actual is None or hashlib.sha256(actual).hexdigest() != value.get('binary_sha256'):
        raise Rejected('tunnel_client_changed')
    return value


def prepare_tunnel(config, tunnel_id, download=True, say=print):
    from .setup import load_config
    endpoint=local_url(load_config(config)) if Path(config).is_file() else LOCAL_URL
    if not re.fullmatch(r'tunnel_[A-Za-z0-9_-]{1,128}', tunnel_id):
        raise Rejected('tunnel_invalid_id')
    root, settings, profile = profile_paths(config)
    if settings.exists():
        existing = profile_settings(config)
        if existing['tunnel_id'] != tunnel_id:
            raise Rejected('tunnel_existing_id_mismatch')
        say('Existing tunnel profile retained: ' + str(profile))
        return existing
    if profile.exists():
        raise Rejected('tunnel_existing_profile_without_receipt')
    private_directory(root)
    private_directory(profile.parent)
    installed = shutil.which('tunnel-client')
    provenance = {'release': 'existing_client'}
    if installed:
        binary = Path(installed).resolve()
        safe_path(binary)
    elif download:
        say('Downloading the official OpenAI tunnel-client release and verifying its SHA256 digest.')
        binary, provenance = install_client(root)
    else:
        raise Rejected('tunnel_client_missing')
    # Init writes only a local profile; no API key or control-plane request is needed.
    arguments = [str(binary), 'init', '--sample', 'sample_mcp_with_dcr', '--profile', PROFILE,
                 '--profile-dir', str(profile.parent), '--tunnel-id', tunnel_id,
                 '--mcp-server-url', endpoint, '--health-listen-addr', '127.0.0.1:0',
                 '--control-plane-api-key-ref', 'env:CONTROL_PLANE_API_KEY']
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'LANG', 'TMPDIR') if k in os.environ}
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=30, env=env)
        if result.returncode or not profile.is_file() or profile.is_symlink():
            raise Rejected('tunnel_profile_creation_failed')
    except subprocess.SubprocessError:
        raise Rejected('tunnel_profile_creation_failed') from None
    profile.chmod(0o600)
    value = {'tunnel_id': tunnel_id, 'binary': str(binary), 'endpoint': endpoint, **provenance,
             'profile_sha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
             'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    write_file(settings, encoded(value))
    say('Private tunnel profile prepared: ' + str(profile))
    say('At runtime supply CONTROL_PLANE_API_KEY; it is never copied into connector or plugin files.')
    say('Start dot-herdr run --tunnel, then add a custom MCP server in ChatGPT using Tunnel: ' + tunnel_id)
    say('Tunnel/workspace access, external OAuth, dot Events and callback delivery still need live verification.')
    return value


def runtime_command(config, command='run', cfg=None):
    value = profile_settings(config)
    root, _, profile = profile_paths(config)
    if not os.environ.get('CONTROL_PLANE_API_KEY'):
        raise Rejected('tunnel_runtime_api_key_required')
    # Explicit flags protect this managed profile from accidental tunnel-client overrides.
    args = [value['binary'], command, '--profile-file', str(profile),
            '--control-plane.base-url', 'https://api.openai.com', '--control-plane.tunnel-id', value['tunnel_id'],
            '--control-plane.api-key', 'env:CONTROL_PLANE_API_KEY', '--mcp.server-url', value['endpoint'],
            '--health.listen-addr', '127.0.0.1:0', '--health.url-file', str(root / 'health.url')]
    if cfg:
        # Explicit operator-configured trust origins, never wildcard redirects.
        for url in dict.fromkeys([cfg['issuer'],cfg['resource']]):
            parsed=urlsplit(url)
            args+=['--mcp.oauth-trusted-origin',parsed.scheme+'://'+parsed.netloc]
    # Keep ordinary system networking configuration; drop unrelated tunnel-client overrides.
    allowed = {'HOME','PATH','LANG','TMPDIR','SSL_CERT_FILE','SSL_CERT_DIR','HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy'}
    env = {k: v for k, v in os.environ.items() if k in allowed or k.startswith('LC_')}
    env['CONTROL_PLANE_API_KEY'] = os.environ['CONTROL_PLANE_API_KEY']
    return args, env


def check_tunnel(config, say=print, cfg=None):
    args, env = runtime_command(config, 'doctor',cfg=cfg)
    try:
        result = subprocess.run(args + ['--explain'], capture_output=True, timeout=45, env=env)
    except subprocess.SubprocessError:
        raise Rejected('tunnel_doctor_failed') from None
    if result.returncode:
        raise Rejected('tunnel_doctor_failed_check_account_permissions_and_runtime')
    say('Tunnel client doctor passed; actual dot delivery and OAuth consent remain separate checks.')
