"""Prepare a local plugin and supported desktop configuration; never install by private API."""
import json
import hashlib
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlencode,quote

from . import __version__
from .core import Rejected
from .skills import SKILL_FILES

NAME = 'dot-herdr'
LOCAL_URL = 'http://127.0.0.1:8000/mcp'

def local_url(cfg):
    return 'http://127.0.0.1:'+str(cfg.get('local_port',8000))+'/mcp'


def safe_path(path):
    path = Path(path).expanduser().absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise Rejected('connection_symlink_path')
        if part.exists():
            info=part.stat()
            unsafe_write=bool(info.st_mode & 0o002 or info.st_mode & 0o020 and info.st_gid not in (0,os.getgid()))
            # System-owned ancestors and a sticky temporary directory are normal.
            if part==path and info.st_uid not in (0,os.getuid()) or unsafe_write and not (part!=path and info.st_mode & 0o1000):
                raise Rejected('connection_untrusted_path')
    return path


def read_file(path, limit=1048576):
    safe_path(path)
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > limit:
        raise Rejected('connection_invalid_file')
    return path.read_bytes()


def write_file(path, body, previous=None, backup=True):
    """Atomic, with original bytes checked and a non-overwriting backup on edits."""
    path = safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    current = read_file(path)
    if current == body:
        return
    if current != previous:
        raise Rejected('connection_file_changed')
    if previous is not None and backup:
        backup_path = path.with_name(path.name + '.dot-herdr-backup')
        if not backup_path.exists():
            write_file(backup_path, previous)
        else:
            read_file(backup_path)
    fd, temporary = tempfile.mkstemp(prefix='.dot-herdr-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        if read_file(path) != previous:
            raise Rejected('connection_file_changed')
        if previous is None:
            os.link(temporary, path)
        else:
            os.chmod(temporary, path.stat().st_mode & 0o777)
            os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def prepare_plugin(home, endpoint=LOCAL_URL, app_id=None, include_mcp=True, preserve_paths=(),migration_owned=None,dry_run=False):
    """Copy only packaged static guidance and manifests, preserving other catalog entries."""
    home = safe_path(home)
    plugin = home / '.codex/plugins' / NAME
    marketplace = home / '.agents/plugins/marketplace.json'
    safe_path(plugin)
    old = read_file(marketplace)
    try:
        catalog = json.loads(old) if old is not None else {'name': 'herdr-local', 'interface': {'displayName': 'Herdr'}, 'plugins': []}
        if not isinstance(catalog, dict) or not isinstance(catalog.get('name'), str) or not re.fullmatch(r'[A-Za-z0-9_-]+', catalog['name']) or not isinstance(catalog.get('plugins'), list):
            raise ValueError
        rows = [p for p in catalog['plugins'] if isinstance(p, dict) and p.get('name') == NAME]
    except (ValueError, TypeError):
        raise Rejected('connection_invalid_marketplace') from None
    entry = {'name': NAME, 'source': {'source': 'local', 'path': './.codex/plugins/' + NAME},
             'policy': {'installation': 'AVAILABLE', 'authentication': 'ON_INSTALL'}, 'category': 'Productivity'}
    if rows and (len(rows) != 1 or rows[0] != entry):
        raise Rejected('connection_existing_marketplace_entry')
    marker = plugin / '.dot-herdr-plugin'
    if plugin.exists() and read_file(marker) != b'dot-herdr\n':
        raise Rejected('connection_unowned_plugin_directory')
    manifest = {'$schema': 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json', 'name': NAME,
                'version': __version__, 'description': 'Inspect and control an explicitly granted Herdr session.',
                'license': 'MIT', 'extensions': {'com.openai': {'interface': {'displayName': 'dot-herdr',
                'shortDescription': 'Connect Herdr agents, controls and attention events.'}}}}
    payload = {'.dot-herdr-plugin': b'dot-herdr\n', 'plugin.json': encoded(manifest),
               'LICENSE': files('dot_herdr').joinpath('plugin','LICENSE').read_bytes()}
    if app_id:
        # ChatGPT's plugin detail URL wraps the registered server's asdk_app ID.
        app_id = app_id.removeprefix('plugin_')
        if not re.fullmatch(r'(asdk_app_|connector_|templated_apps_)[A-Za-z0-9][A-Za-z0-9_-]*', app_id):
            raise Rejected('connection_invalid_registered_server_id')
        manifest['extensions']['com.openai']['apps'] = './.app.json'
        payload['plugin.json'] = encoded(manifest)
        payload['.app.json'] = encoded({'apps': {'herdr': {'id': app_id}}})
    if include_mcp:payload['mcp.json'] = encoded({'$schema': 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
                                 'mcpServers': {NAME: {'type': 'streamable-http', 'url': endpoint}}})
    folder = files('dot_herdr').joinpath('skills', 'herdr-connector')
    for name in SKILL_FILES:
        payload['skills/herdr-connector/' + name] = folder.joinpath(name).read_bytes()
    # Validate every existing destination before making any changes.
    originals = {name: read_file(plugin / name) for name in payload}
    if migration_owned is not None:
        receipts=migration_owned.get('plugin_files',{}) if isinstance(migration_owned,dict) else {}
        if not isinstance(receipts,dict):receipts={}
        for name,raw in originals.items():
            path=str(plugin/name)
            if raw is not None and path not in preserve_paths and hashlib.sha256(raw).hexdigest()!=receipts.get(path):
                raise Rejected('migration_target_conflict: '+path+'; next action: move this file aside, then retry migration')
    if include_mcp and originals.get('mcp.json') is not None:
        try:
            old_servers=json.loads(originals['mcp.json'])['mcpServers']
            if old_servers!={NAME:{'type':'streamable-http','url':endpoint}}:raise ValueError
        except (ValueError,KeyError,TypeError):raise Rejected('connection_existing_plugin_mcp_entry') from None
    if not app_id and (plugin / '.app.json').exists() and not (dry_run and migration_owned is not None):
        raise Rejected('connection_retain_registered_server_id')
    for name, body in payload.items():
        if not dry_run and str(plugin/name) not in preserve_paths:
            raw=read_file(plugin/name)
            if migration_owned is not None and raw is not None and hashlib.sha256(raw).hexdigest()!=receipts.get(str(plugin/name)):
                raise Rejected('migration_target_conflict: '+str(plugin/name)+'; next action: move this file aside, then retry migration')
            write_file(plugin / name, body, originals[name],backup=False)
    if not rows and not dry_run:
        catalog['plugins'].append(entry)
        write_file(marketplace, encoded(catalog), old)
    return {'plugin': str(plugin), 'marketplace': str(marketplace), 'endpoint': endpoint,
            'owned':{'plugin_files':{str(plugin/name):hashlib.sha256(body).hexdigest() for name,body in payload.items() if str(plugin/name) not in preserve_paths},'marketplace':str(marketplace),'marketplace_entry':entry},
            'link': 'codex://plugins/' + NAME + '?' + urlencode({'marketplacePath': str(marketplace)},quote_via=quote)}


def register_mcp(codex_home, endpoint=LOCAL_URL, dry_run=False, resource=None, client_id=None):
    """Append one server's TOML tables, preserving comments and every unrelated byte."""
    path = safe_path(Path(codex_home) / 'config.toml')
    old = read_file(path)
    try:
        config = tomllib.loads((old or b'').decode())
        servers = config.get('mcp_servers', {})
        if not isinstance(servers, dict):
            raise ValueError
    except (ValueError, UnicodeError):
        raise Rejected('connection_invalid_codex_config') from None
    if NAME in servers:
        current = servers[NAME]
        oauth=current.get('oauth',{}) if isinstance(current,dict) else {}
        if not isinstance(current, dict) or current.get('url') != endpoint or current.get('enabled') is False or 'command' in current or (resource and current.get('oauth_resource',resource)!=resource) or (client_id and (not isinstance(oauth,dict) or oauth.get('client_id')!=client_id)):
            raise Rejected('connection_existing_mcp_entry')
        return {'status': 'existing', 'config': str(path)}
    table = '\n[mcp_servers."' + NAME + '"]\nurl = ' + json.dumps(endpoint) + '\n'
    if resource:table+='oauth_resource = '+json.dumps(resource)+'\n'
    if client_id:table+='\n[mcp_servers."'+NAME+'".oauth]\nclient_id = '+json.dumps(client_id)+'\n'
    body = (old or b'') + table.encode()
    tomllib.loads(body.decode())
    if not dry_run:
        write_file(path, body, old)
    return {'status': 'registered', 'config': str(path), 'owned_table':table}


def open_link(link):
    command = shutil.which('open' if sys.platform == 'darwin' else 'xdg-open')
    if not command:
        return False
    try:
        result = subprocess.run([command, link], capture_output=True, timeout=10)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def connection_path(config):
    path=Path(config).expanduser().absolute()
    return path.with_name(path.name+'.connection.json')


class ConnectionRecord(dict):
    def __init__(self,value,previous=None):
        super().__init__(value);self.previous=previous


def valid_client_scopes(value):
    if not isinstance(value,dict) or len(value)>8:return False
    for client,entry in value.items():
        if not isinstance(client,str) or not 1<=len(client)<=256 or not isinstance(entry,dict) or set(entry)!={'scopes','verified_at','expires_at'}:return False
        scopes=entry['scopes']
        if not isinstance(scopes,list) or len(scopes)>32 or any(not isinstance(s,str) or not re.fullmatch(r'[A-Za-z0-9:_-]{1,128}',s) for s in scopes):return False
        verified,expires=entry['verified_at'],entry['expires_at']
        if any(isinstance(t,bool) or not isinstance(t,(int,float)) or not math.isfinite(t) for t in (verified,expires)) or verified>expires:return False
    return True


def exposure_for(config_or_record):
    """Return a validated exposure observation from a config path or record."""
    record=config_or_record if isinstance(config_or_record,dict) else connection_record(config_or_record)
    value=record.get('exposure')
    if not isinstance(value,dict) or set(value)!={'provider','hostname','tunnel_id','mode'}:return None
    if value['provider']!='cloudflare' or value['mode'] not in ('api','login'):return None
    hostname=value['hostname'];tunnel_id=value['tunnel_id']
    if not isinstance(hostname,str) or not 1<=len(hostname)<=253:return None
    if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in hostname.split('.')):return None
    if not isinstance(tunnel_id,str) or not re.fullmatch(r'[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}',tunnel_id):return None
    return value


def connection_record(config):
    path=connection_path(config);raw=read_file(path,65536)
    if raw is None:return ConnectionRecord({'version':1,'stage':'route'})
    if path.stat().st_mode & 0o077:raise Rejected('private_connection_record_required')
    try:
        value=json.loads(raw)
        if not isinstance(value,dict) or value.get('version')!=1:raise ValueError
        allowed={'version','stage','route','wiring','client_app','app_id','endpoint','background','login_start','last_authentication','last_verified_scopes','approved_client_id','verified_client_scopes','identity','owned','local_package','check','pending','migration','exposure'}
        if set(value)-allowed:raise ValueError
        if 'exposure' in value and exposure_for(value) is None:raise ValueError
        if 'last_verified_scopes' in value and (not isinstance(value['last_verified_scopes'],list) or len(value['last_verified_scopes'])>32 or any(not isinstance(s,str) or not re.fullmatch(r'[A-Za-z0-9:_-]{1,128}',s) for s in value['last_verified_scopes'])):raise ValueError
        if value.get('approved_client_id') is not None and (not isinstance(value['approved_client_id'],str) or not 1<=len(value['approved_client_id'])<=256):raise ValueError
        if 'verified_client_scopes' in value and not valid_client_scopes(value['verified_client_scopes']):raise ValueError
        if value.get('route') not in (None,'tunnel','https','loopback'):raise ValueError
        if value.get('wiring') not in (None,'registered-plugin','standalone','plugin-http'):raise ValueError
        if value.get('client_app') not in (None,'chatgpt-web','desktop'):raise ValueError
        return ConnectionRecord(value,raw)
    except (ValueError,TypeError):raise Rejected('invalid_connection_record') from None


def save_connection(config,record):
    # Callers persist only observations/choices, never credentials or prompt text.
    allowed={'version','stage','route','wiring','client_app','app_id','endpoint','background','login_start','last_authentication','last_verified_scopes','approved_client_id','verified_client_scopes','identity','owned','local_package','check','pending','migration','exposure'}
    if set(record)-allowed or record.get('version')!=1:raise Rejected('invalid_connection_record')
    if 'exposure' in record and exposure_for(record) is None:raise Rejected('invalid_connection_record')
    if 'last_verified_scopes' in record and (not isinstance(record['last_verified_scopes'],list) or len(record['last_verified_scopes'])>32 or any(not isinstance(s,str) or not re.fullmatch(r'[A-Za-z0-9:_-]{1,128}',s) for s in record['last_verified_scopes'])):raise Rejected('invalid_connection_record')
    if record.get('approved_client_id') is not None and (not isinstance(record['approved_client_id'],str) or not 1<=len(record['approved_client_id'])<=256):raise Rejected('invalid_connection_record')
    if 'verified_client_scopes' in record and not valid_client_scopes(record['verified_client_scopes']):raise Rejected('invalid_connection_record')
    if record.get('client_app') not in (None,'chatgpt-web','desktop'):raise Rejected('invalid_connection_record')
    path=connection_path(config)
    from .onboarding import private_directory
    private_directory(path.parent)
    old=read_file(path,65536)
    if isinstance(record,ConnectionRecord) and old!=record.previous:raise Rejected('connection_record_changed_resume_setup')
    body=encoded(record)
    write_file(path,body,old,backup=False)
    if isinstance(record,ConnectionRecord):record.previous=body
    os.chmod(path,0o600)


def prepare_connections(cfg, endpoint=None, home=None, codex_home=None, app_id=None, register=None, launch=True, say=print, wiring=None, preserve_paths=(),client_app='chatgpt-web',migration_owned=None,dry_run=False):
    endpoint = endpoint or cfg['resource']
    if endpoint not in (local_url(cfg), cfg['resource']):
        raise Rejected('connection_endpoint_must_be_local_or_configured_resource')
    # Ordinary setup uses one cloud registration. Explicit legacy register flags
    # select standalone; previous dual installations are preserved for migration.
    wiring=wiring or ('standalone' if register is True else 'plugin-http' if register is False else 'registered-plugin')
    if wiring not in ('registered-plugin','standalone','plugin-http'):raise Rejected('invalid_connection_wiring')
    home = Path(home) if home else Path.home()
    codex_home = Path(codex_home) if codex_home else Path(os.environ.get('CODEX_HOME', str(home / '.codex')))
    if not codex_home.is_absolute():raise Rejected('connection_absolute_codex_home_required')
    pending_resource='.invalid' in cfg['resource'] or cfg['resource'].startswith('replace-with-')
    if wiring=='standalone':
        registration=register_mcp(codex_home,endpoint,dry_run=dry_run,resource=cfg['resource'],client_id=cfg.get('oauth_client_id')) if not pending_resource else {'status':'pending_resource'}
        say('Codex CLI (advanced) MCP registration: '+registration['status']+'; authentication is still required.')
        return {'wiring':wiring,'endpoint':endpoint,'registration':registration,'handoff_opened':False,'owned':{'standalone_config':registration['config'],'standalone_block':registration['owned_table']} if registration.get('owned_table') else {}}
    if wiring=='registered-plugin' and not app_id:
        say('The Herdr plugin in the ChatGPT/Codex desktop app is the connection.' if client_app=='desktop' else 'The custom plugin created in ChatGPT in a web browser (chatgpt.com) at Settings → Plugins → + → Add custom MCP server is the connection.')
        return {'wiring':wiring,'endpoint':endpoint,'registration':{'status':'settings_plugin'},'local_package':{'status':'not_prepared','reason':'plugin_created_in_chatgpt_settings'},'owned':{},'handoff_opened':False}
    result = prepare_plugin(home, endpoint, app_id, include_mcp=wiring=='plugin-http',preserve_paths=preserve_paths,migration_owned=migration_owned,dry_run=dry_run)
    result.update(wiring=wiring,registration={'status':'cloud_mapping_prepared' if app_id else 'plugin_http_prepared'},local_package={'status':'prepared'})
    say('ChatGPT/Codex desktop app (explicit local package) local plugin prepared: ' + result['plugin'])
    say('ChatGPT/Codex desktop app (explicit local package) marketplace: ' + result['marketplace'])
    say('ChatGPT/Codex desktop app (explicit local package): restart the Codex desktop app, open this local plugin page, then select Install: ' + result['link'])
    result['handoff_opened'] = open_link(result['link']) if launch and not dry_run else False
    if launch and not result['handoff_opened']:say('ChatGPT/Codex desktop app (explicit local package): open the displayed link manually after restarting the Codex desktop app; local plugin installation remains pending.')
    say('ChatGPT/Codex desktop app (explicit local package): local preparation does not prove local plugin installation, account authorization or Events delivery.')
    return result


class SetupLock:
    """Fence simultaneous setup flows; never unlink the inode while another waits."""
    def __init__(self,config):
        self.path=Path(config).absolute().with_name(Path(config).name+'.setup.lock')
        self.fd=None
    def __enter__(self):
        import fcntl
        import stat
        from .onboarding import private_directory
        safe_path(self.path);private_directory(self.path.parent)
        self.fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:raise Rejected('private_setup_lock_required')
            try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected('setup_already_running') from None
            return self
        except BaseException:
            os.close(self.fd);self.fd=None;raise
    def __exit__(self,*args):
        os.close(self.fd);self.fd=None


def remove_owned_connections(config,home=None,codex_home=None,retain_plugin=False):
    """Remove only receipt-matching connector pieces; shared/edited data survives."""
    record=connection_record(config);owned=record.get('owned',{});removed=[];preserved=[]
    if not isinstance(owned,dict):
        return {'removed':removed,'preserved':[str(connection_path(config))]}
    plugin_files=owned.get('plugin_files',{})
    if not isinstance(plugin_files,dict):
        preserved.append(str(connection_path(config)))
        plugin_files={}
    for text,digest in plugin_files.items():
        if retain_plugin and Path(text).name not in ('mcp.json','.app.json'):continue
        try:
            path=safe_path(text)
            # Recompute the allowed owned plugin root, not a record-controlled arbitrary file.
            root=(Path(home) if home else Path.home())/'.codex/plugins'/NAME
            if not path.is_relative_to(root):raise Rejected('connection_receipt_path_mismatch')
            raw=read_file(path)
            if raw is not None and hashlib.sha256(raw).hexdigest()==digest:path.unlink();removed.append(str(path))
            elif raw is not None:preserved.append(str(path))
        except (OSError,ValueError,TypeError):preserved.append(str(text))
    marketplace=owned.get('marketplace')
    if marketplace and not retain_plugin:
        label=str(marketplace)+'#'+NAME
        try:
            path=safe_path(marketplace)
            if path!=(Path(home) if home else Path.home())/'.agents/plugins/marketplace.json':raise Rejected('connection_receipt_path_mismatch')
            raw=read_file(path)
            if raw is not None:
                value=json.loads(raw);entry=owned.get('marketplace_entry')
                if not isinstance(value,dict) or not isinstance(value.get('plugins'),list):raise ValueError
                matches=[p for p in value['plugins'] if isinstance(p,dict) and p.get('name')==NAME]
                if matches==[entry]:
                    value['plugins'].remove(entry);write_file(path,encoded(value),raw);removed.append(label)
                elif matches:preserved.append(label)
        except (OSError,ValueError,TypeError):preserved.append(label)
    table=owned.get('standalone_block');text=owned.get('standalone_config')
    if table and text:
        label=str(text)+'#'+NAME
        try:
            if not isinstance(table,str):raise ValueError
            path=safe_path(text);selected_home=Path(codex_home) if codex_home else Path(os.environ.get('CODEX_HOME',str((Path(home) if home else Path.home())/'.codex')))
            if path!=selected_home/'config.toml':raise Rejected('connection_receipt_path_mismatch')
            raw=read_file(path);needle=table.encode()
            if raw is not None and raw.count(needle)==1:
                candidate=raw.replace(needle,b'',1)
                # Avoid deleting a matching substring in a table that the user extended.
                before=tomllib.loads(raw.decode());after=tomllib.loads(candidate.decode())
                expected={'url':record.get('endpoint'),'oauth_resource':load_resource(config)}
                from .setup import load_config
                client_id=load_config(config).get('oauth_client_id')
                if client_id:expected['oauth']={'client_id':client_id}
                if before.get('mcp_servers',{}).get(NAME)!=expected or NAME in after.get('mcp_servers',{}):raise ValueError
                write_file(path,candidate,raw);removed.append(label)
            elif raw is not None:preserved.append(label)
        except (OSError,ValueError,TypeError,AttributeError):preserved.append(label)
    return {'removed':removed,'preserved':preserved}


def load_resource(config):
    from .setup import load_config
    return load_config(config)['resource']


def migration_entries(config,home=None,codex_home=None):
    """Classify local registrations against the saved receipt before any migration write."""
    from .setup import load_config
    record=connection_record(config);owned=record.get('owned') or {};cfg=load_config(config)
    home=Path(home) if home else Path.home()
    codex_home=Path(codex_home) if codex_home else Path(os.environ.get('CODEX_HOME',str(home/'.codex')))
    plugin=safe_path(home/'.codex/plugins'/NAME);market=safe_path(home/'.agents/plugins/marketplace.json');toml=safe_path(codex_home/'config.toml')
    rows=[];files=owned.get('plugin_files',{}) if isinstance(owned,dict) else {}
    if not isinstance(files,dict):files={}
    if plugin.exists():
        for path in sorted(plugin.rglob('*')):
            if path.is_dir():continue
            label=str(path);digest=files.get(label)
            try:raw=read_file(path)
            except Rejected:raw=None
            state='unrelated' if digest is None else 'owned-unchanged' if raw is not None and hashlib.sha256(raw).hexdigest()==digest else 'owned-modified'
            rows.append({'kind':'plugin_file','path':label,'classification':state})
    raw=read_file(market)
    if raw is not None:
        try:
            value=json.loads(raw);items=value['plugins']
            if not isinstance(items,list):raise ValueError
            for i,item in enumerate(items):
                label=str(market)+'#'+str(item.get('name',i) if isinstance(item,dict) else i)
                receipt=owned.get('marketplace_entry') if isinstance(owned,dict) and owned.get('marketplace')==str(market) else None
                state='unrelated' if not isinstance(item,dict) or item.get('name')!=NAME or receipt is None else 'owned-unchanged' if item==receipt else 'owned-modified'
                rows.append({'kind':'marketplace','path':label,'classification':state})
        except (ValueError,TypeError,KeyError):rows.append({'kind':'marketplace','path':str(market),'classification':'unrelated'})
    raw=read_file(toml)
    if raw is not None:
        try:
            servers=tomllib.loads(raw.decode()).get('mcp_servers',{})
            if not isinstance(servers,dict):raise ValueError
            for name,value in servers.items():
                receipt=owned.get('standalone_block') if isinstance(owned,dict) and owned.get('standalone_config')==str(toml) and name==NAME else None
                state='unrelated'
                if receipt:
                    expected={'url':record.get('endpoint'),'oauth_resource':cfg['resource']}
                    if cfg.get('oauth_client_id'):expected['oauth']={'client_id':cfg['oauth_client_id']}
                    candidate=raw.replace(receipt.encode(),b'',1) if isinstance(receipt,str) and raw.count(receipt.encode())==1 else raw
                    try:absent=NAME not in tomllib.loads(candidate.decode()).get('mcp_servers',{})
                    except (ValueError,UnicodeError):absent=False
                    state='owned-unchanged' if value==expected and absent else 'owned-modified'
                rows.append({'kind':'standalone','path':str(toml)+'#'+name,'classification':state})
        except (ValueError,UnicodeError):rows.append({'kind':'standalone','path':str(toml),'classification':'unrelated'})
    return rows


def migrate_connection(config,route,wiring,*,endpoint=None,app_id=None,client_app=None,home=None,codex_home=None,launch=False,say=print,to=None,login=False,token_file=None):
    """Resume an explicitly selected route change, retaining edited and unrelated entries."""
    from .setup import load_config
    config=Path(config).expanduser().absolute();cfg=load_config(config)
    if to is not None:
        if to!='cloudflare':raise Rejected('invalid_migration_target')
        with SetupLock(config):
            record=connection_record(config)
            if record.get('route') not in ('https','tunnel') or not record.get('wiring') or record.get('endpoint')!=cfg['resource']:
                raise Rejected('cloudflare_migration_requires_existing_https_or_tunnel')
            if record.get('migration'):raise Rejected('migration_in_progress_resume_saved_selection')
            from .cli import expose_cloudflare
            from .service import service_record
            installed=None
            if record.get('route')=='tunnel':
                try:installed=service_record(config)
                except Rejected:
                    say('No verified installed user service found; check any existing service for --tunnel before running the Cloudflare exposure.')
            exposure=expose_cloudflare(config,login=login,token_file=token_file,say=say)
            record=connection_record(config);record['route']='https';save_connection(config,record)
            say('Plugin URL is unchanged: '+cfg['resource'])
            if installed and installed.get('tunnel'):
                say('The installed user service must be reinstalled without --tunnel: dot-herdr service install. Run refuses an OpenAI tunnel together with a Cloudflare exposure.')
            return {'saved_route':'https','saved_wiring':record['wiring'],'exposure':exposure,'endpoint':cfg['resource']}
    if route not in ('https','tunnel','loopback') or wiring not in ('registered-plugin','standalone','plugin-http'):raise Rejected('invalid_connection_route_or_wiring')
    endpoint=endpoint or (local_url(cfg) if route=='loopback' else cfg['resource'])
    if endpoint not in (local_url(cfg),cfg['resource']):raise Rejected('connection_endpoint_must_be_local_or_configured_resource')
    if route=='tunnel' and endpoint!=cfg['resource']:raise Rejected('tunnel_requires_configured_resource')
    home=Path(home) if home else Path.home()
    codex_home=Path(codex_home) if codex_home else Path(os.environ.get('CODEX_HOME',str(home/'.codex')))
    if not codex_home.is_absolute():raise Rejected('connection_absolute_codex_home_required')
    with SetupLock(config):
        record=connection_record(config);selected_app=app_id if wiring in ('registered-plugin','plugin-http') else None
        selected_client=client_app or record.get('client_app') or 'chatgpt-web'
        if selected_client not in ('chatgpt-web','desktop'):raise Rejected('invalid_client_app')
        if selected_app and selected_client!='desktop':raise Rejected('app_id_requires_desktop_client_app')
        same_route=(record.get('route'),record.get('wiring'),record.get('endpoint'))==(route,wiring,endpoint)
        if same_route and not selected_app and not (record.get('app_id') and selected_client=='chatgpt-web'):
            if record.get('client_app')==selected_client:raise Rejected('migration_selection_unchanged')
            record['client_app']=selected_client;save_connection(config,record)
            return {'saved_route':route,'saved_wiring':wiring,'client_app':selected_client,'entries':[],'backups':[],'removed':[],'preserved':[],'registration':{'status':'unchanged'}}
        intent={'route':route,'wiring':wiring,'endpoint':endpoint,'app_id':selected_app}
        if record.get('migration') and record['migration']!=intent:raise Rejected('migration_in_progress_resume_saved_selection')
        entries=migration_entries(config,home,codex_home)
        if not record.get('migration'):
            if not record.get('route') or not record.get('wiring'):raise Rejected('migration_requires_saved_route_and_wiring')
            if same_route and record.get('client_app')==selected_client and not record.get('app_id'):raise Rejected('migration_selection_unchanged')
            target='standalone' if wiring=='standalone' else 'plugin_file' if selected_app or wiring=='plugin-http' else None
            conflict=next((e for e in entries if e['classification'] in ('owned-modified','unrelated') and (e['kind']==target and (e['kind']=='standalone' or Path(e['path']).name in ('.dot-herdr-plugin','plugin.json','.app.json','mcp.json')) or e['kind']=='marketplace' and e['path'].endswith('#'+NAME) and target=='plugin_file')),None)
            if conflict:raise Rejected('migration_target_conflicts_with_preserved_entry: '+conflict['path']+'; next action: move this entry aside, then retry migration')
        preserved_paths={e['path'] for e in entries if e['kind']=='plugin_file' and e['classification'] in ('owned-modified','unrelated')}
        owned=record.get('owned') or {}
        # The dry run validates the complete target payload before backups or
        # the migration journal are written. Preparation checks again at use.
        prepare_connections(cfg,endpoint=endpoint,home=home,codex_home=codex_home,app_id=intent['app_id'],wiring=wiring,launch=False,say=lambda _:None,preserve_paths=preserved_paths,client_app=selected_client,migration_owned=owned,dry_run=True)
        changed=[e for e in entries if e['classification']=='owned-unchanged']
        backups=[];stamp=str(time.time_ns())
        paths={connection_path(config)}
        for entry in changed:paths.add(Path(entry['path'].split('#',1)[0]))
        for path in sorted(paths):
            raw=read_file(path)
            if raw is None:continue
            backup=path.with_name(path.name+'.migration-backup-'+stamp)
            write_file(backup,raw)
            backups.append(str(backup))
        if not record.get('migration'):
            record['migration']=intent;save_connection(config,record)
        removed=remove_owned_connections(config,home,codex_home,retain_plugin=wiring=='plugin-http' or wiring=='registered-plugin' and bool(intent['app_id']))
        result=prepare_connections(cfg,endpoint=endpoint,home=home,codex_home=codex_home,app_id=intent['app_id'],wiring=wiring,launch=launch,say=say,preserve_paths=preserved_paths,client_app=selected_client,migration_owned=owned)
        record=connection_record(config)
        record.update(route=route,wiring=wiring,client_app=selected_client,endpoint=endpoint,stage='client',owned=result.get('owned',{}))
        if result.get('local_package'):record['local_package']=result['local_package']
        else:record.pop('local_package',None)
        if intent['app_id']:record['app_id']=intent['app_id']
        else:record.pop('app_id',None)
        record.pop('migration',None);save_connection(config,record)
        preserved=list(dict.fromkeys(removed['preserved']+[e['path'] for e in entries if e['classification'] in ('owned-modified','unrelated')]))
        return {'saved_route':route,'saved_wiring':wiring,'entries':entries,'backups':backups,'removed':removed['removed'],'preserved':preserved,'registration':result['registration']}
