"""Delegate OAuth discovery, automatic registration and credential storage to Codex."""
import asyncio
import json
import os
import shutil
import ssl
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler, HTTPSHandler
from urllib.error import HTTPError, URLError

from .connections import LOCAL_URL, NAME, register_mcp, read_file, local_url
from .core import Rejected
from .setup import placeholders


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def public_metadata_status(cfg, endpoint, *, details=False):
    """One bounded public metadata GET; optionally include Cloudflare advice."""
    from mcp.server.auth.routes import build_resource_metadata_url
    metadata = str(build_resource_metadata_url(cfg['resource']))
    if endpoint == local_url(cfg):
        metadata = endpoint.removesuffix('/mcp') + urlsplit(metadata).path
    try:
        handlers = [NoRedirect()]
        if endpoint == local_url(cfg):
            handlers.append(ProxyHandler({}))
        certificate = os.environ.get('CODEX_CA_CERTIFICATE')
        if certificate:
            handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=certificate)))
        with build_opener(*handlers).open(metadata, timeout=3) as response:
            code=getattr(response,'status',200)
            raw = response.read(65537)
            advice = _cloudflare_advice(code, getattr(response,'headers',None), raw[:65536], cfg['resource'])
            if len(raw) > 65536:
                result=(f'reachable (HTTP {code})',False)
                return (*result,advice) if details else result
            try:value = json.loads(raw)
            except (ValueError,TypeError):value = None
            matched=(isinstance(value, dict) and value.get('resource') == cfg['resource']
                     and isinstance(value.get('authorization_servers'), list)
                     and cfg['issuer'] in value['authorization_servers'])
            result=(f'reachable (HTTP {code})',matched)
            return (*result,advice) if details else result
    except HTTPError as error:
        advice=None
        try:
            raw=error.read(65537)
            advice=_cloudflare_advice(error.code,error.headers,raw[:65536],cfg['resource'])
        except Exception:
            # The HTTP status is still useful when the optional advice body
            # times out, resets, or is truncated while being read.
            pass
        finally:
            error.close()
        result=(f'unreachable (HTTP {error.code})',False)
        return (*result,advice) if details else result
    except URLError as error:
        result=(f'unreachable ({type(error.reason).__name__})',False)
        return (*result,None) if details else result
    except (OSError, ValueError, TypeError) as error:
        result=(f'unreachable ({type(error).__name__})',False)
        return (*result,None) if details else result


def _cloudflare_advice(code, headers, body, resource):
    headers=headers or {}
    host=urlsplit(resource).hostname or 'this hostname'
    text=body.decode('utf-8','ignore').lower()
    challenge=(str(headers.get('cf-mitigated','')).lower()=='challenge' or
               (str(headers.get('server','')).lower()=='cloudflare' and
                any(marker in text for marker in ('just a moment', 'cf-chl-', 'challenge-platform', 'checking your browser'))))
    if code==403 and challenge:
        return (f"Cloudflare's bot protection is blocking requests to {host}, so ChatGPT's calls are blocked too. "
                f'Turn it off for this hostname, or add a rule that skips it for this hostname. dot-herdr never changes zone security settings.')
    if code==530 or b'error code: 1033' in body.lower():
        return 'The Cloudflare tunnel is down. Check that cloudflared is running (dot-herdr status shows the cloudflared child; restart with dot-herdr service restart or dot-herdr run).'
    if code==524:
        return 'Cloudflare timed out waiting for this computer (HTTP 524). Check that the connector is running and responsive.'
    return None


def discovery_ready(cfg, endpoint):
    """Read public metadata only; refuse a different resource/issuer or a redirect."""
    return public_metadata_status(cfg,endpoint)[1]


async def login_mcp(cfg, endpoint=None, codex_home=None, browser=True, say=print, timeout=300, allow_pairing=False):
    """Collect no OAuth credentials; Codex owns client registration and sign-in."""
    home = Path(codex_home or os.environ.get('CODEX_HOME', str(Path.home() / '.codex')))
    if not home.is_absolute():
        raise Rejected('connection_absolute_codex_home_required')
    if endpoint is None:
        # Repeat login and run --login must use the saved transport, especially
        # when a user selected the canonical HTTPS endpoint during connect.
        raw = read_file(home / 'config.toml')
        try:
            servers = tomllib.loads(raw.decode()).get('mcp_servers', {}) if raw else {}
            entry = servers.get(NAME, {})
            endpoint = entry.get('url', local_url(cfg))
        except (ValueError, AttributeError):
            raise Rejected('connection_invalid_codex_config') from None
    if endpoint not in (local_url(cfg), cfg['resource']):
        raise Rejected('connection_endpoint_must_be_local_or_configured_resource')
    candidate_cfg=cfg
    if allow_pairing:
        # Only the user identity may be pending; issuer, audience, key source,
        # source identity and selected grants must already be configured.
        candidate_cfg={**cfg,'subjects':[{**s,'user_subject':'verified-at-pairing'} for s in cfg['subjects']],
                       'session_users':['verified-at-pairing' for _ in cfg.get('session_users',[])]}
    if placeholders(candidate_cfg):
        say('OAuth sign-in pending: complete the authentication settings with dot-herdr setup.')
        return {'status': 'pending_settings'}
    command = shutil.which('codex')
    if not command:
        say('Codex CLI (advanced): standalone login requires Codex CLI. The routine ChatGPT web plugin signs in through its password page in Settings → Plugins.')
        return {'status': 'missing_codex'}
    register_mcp(home, endpoint, resource=cfg['resource'],client_id=cfg.get('oauth_client_id'))
    if not await asyncio.to_thread(discovery_ready, cfg, endpoint):
        say('OAuth sign-in pending: the configured MCP discovery is not ready. Start dot-herdr run --login, or retry dot-herdr login while it is running.')
        return {'status': 'pending_server'}
    scopes = ['herdr:observe']
    if cfg.get('session_users') or any(s.get('control') for s in cfg['subjects']):
        scopes.append('herdr:control')
    # The supported CLI defaults to automatic CIMD/DCR selection. Do not force
    # a newer flag on older clients, or replace existing provider client settings.
    arguments = [command, 'mcp', 'login', NAME, '--scopes', ','.join(scopes)]
    if not browser:
        arguments.append('--no-browser')
    environment = dict(os.environ, CODEX_HOME=str(home))
    say('Starting advanced standalone Codex CLI sign-in. Follow the browser page opened by this terminal, then return here for verified account approval.')
    if say is print:
        sys.stdout.flush()
    child = None
    status = 'failed'
    try:
        # Inherit the terminal so Codex can display its authorization URL and
        # accept the no-browser callback. Never capture or persist its output.
        child = await asyncio.create_subprocess_exec(*arguments, env=environment)
        code = await asyncio.wait_for(child.wait(), timeout=timeout)
        status = 'authenticated' if code == 0 else 'failed'
    except asyncio.TimeoutError:
        status = 'timed_out'
    except OSError:
        status = 'failed'
    finally:
        if child and child.returncode is None:
            try:
                child.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(child.wait(), timeout=3)
            except asyncio.TimeoutError:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                await child.wait()
    if status == 'authenticated':
        say('The advanced standalone Codex CLI sign-in command completed. Return to this setup terminal for verified account approval; the ChatGPT web plugin has its own Settings → Plugins sign-in.')
    else:
        say('OAuth sign-in ' + status + '. Check the provider supports CIMD or DCR and PKCE S256, then retry dot-herdr login. Existing setup is retained.')
        if endpoint == local_url(cfg):
            say('Codex 0.160.1 rejects loopback discovery with a different HTTPS resource even when oauth_resource is configured. Use the configured HTTPS endpoint when reachable; this local route has not completed sign-in.')
    return {'status': status}


async def request_authenticated_discovery(codex_home=None,timeout=30):
    """Have Codex use its own credentials through its supported app-server API.

    This performs no model turn and reads no credential store. Success only says
    discovery completed; the pairing endpoint must independently observe a token.
    """
    command=shutil.which('codex')
    if not command:return {'status':'missing_codex'}
    home=Path(codex_home or os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))
    if not home.is_absolute():raise Rejected('connection_absolute_codex_home_required')
    child=None
    try:
        async with asyncio.timeout(timeout):
            child=await asyncio.create_subprocess_exec(command,'app-server','--stdio',
                env=dict(os.environ,CODEX_HOME=str(home)),stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,limit=65536)
            observed=0
            async def request(number,method,params):
                nonlocal observed
                child.stdin.write((json.dumps({'id':number,'method':method,'params':params})+'\n').encode())
                await child.stdin.drain()
                while True:
                    line=await child.stdout.readline();observed+=len(line)
                    if not line or observed>524288:raise Rejected('codex_discovery_response_unavailable')
                    value=json.loads(line)
                    if not isinstance(value,dict):raise Rejected('codex_discovery_invalid_response')
                    if value.get('id')==number:
                        if 'error' in value:raise Rejected('codex_discovery_unsupported')
                        return
            await request(1,'initialize',{'clientInfo':{'name':'dot-herdr-setup','version':'1'}})
            child.stdin.write(b'{"method":"initialized"}\n');await child.stdin.drain()
            await request(2,'mcpServerStatus/list',{'serverName':NAME,'detail':'toolsAndAuthOnly'})
            return {'status':'discovery_completed','identity_verified':False}
    except (OSError,ValueError,Rejected,TimeoutError):return {'status':'discovery_pending','identity_verified':False}
    finally:
        if child and child.returncode is None:
            try:child.terminate()
            except ProcessLookupError:pass
            try:await asyncio.wait_for(child.wait(),3)
            except TimeoutError:
                try:child.kill()
                except ProcessLookupError:pass
                await child.wait()
