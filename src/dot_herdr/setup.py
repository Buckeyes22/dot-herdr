"""Offline setup guidance only: no credential collection, source dial or security edits."""
import json
import os
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit
from .core import Rejected

TEMPLATE={
 'store':'/path/to/private-state/connector.sqlite','socket':'/path/to/herdr.sock',
 'issuer':'https://auth.example.invalid','resource':'https://connector.example.invalid/mcp',
 'public_key':'/path/to/oauth-rsa-public-key.pem',
 'subjects':[{'key':'parent_demo','user_subject':'replace-with-approved-issuer-subject',
              'owner':'owner_demo','pane':'replace-with-exact-pane-id',
              'terminal':'replace-with-exact-terminal-id','native':None,'content':False,'control':False}],
 'session_users':[]}

def default_config_path():
    root=Path(os.environ.get('XDG_CONFIG_HOME',''))
    if not root.is_absolute():root=Path.home()/'.config'
    return root/'dot-herdr'/'config.json'


def write_template(output):
    p=Path(output)
    # Deliberately do not create parents or overwrite anything, including symlinks.
    if p.parent.is_symlink() or not p.parent.is_dir() or p.parent.stat().st_mode & 0o077:raise Rejected('private_output_parent_required')
    fd=os.open(p,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:stream.write(json.dumps(TEMPLATE,indent=2)+'\n')


def load_config(path):
    from .connections import safe_path
    p=safe_path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>65536 or p.stat().st_mode & 0o077:
        raise Rejected('private_configuration_required')
    return validate_config(json.loads(p.read_text()))


def validate_config(value):
    required={'store','socket','issuer','resource','subjects'}
    if not isinstance(value,dict) or not required<=set(value) or set(value)-required-{'session_users','public_key','jwks_url','inactive','access_accounts','oauth_client_id','local_port','signin'}:raise Rejected('invalid_configuration')
    if 'signin' in value:
        from .signin import issuer_for,jwks_url
        try:
            if value['signin']!='builtin' or 'jwks_url' not in value or 'public_key' in value or value['issuer']!=issuer_for(value['resource']) or value['jwks_url']!=jwks_url(value['issuer']):raise ValueError
        except (Rejected,ValueError,TypeError,AttributeError):raise Rejected('invalid_builtin_signin_configuration') from None
    if 'local_port' in value and (type(value['local_port']) is not int or not 1024<=value['local_port']<=65535):raise Rejected('invalid_local_port')
    if ('public_key' in value)==('jwks_url' in value):raise Rejected('exactly_one_auth_key_source_required')
    if 'inactive' in value and not isinstance(value['inactive'],bool):raise Rejected('invalid_inactive_state')
    if 'jwks_url' in value:
        from .auth import same_origin
        same_origin(value['issuer'],value['jwks_url'])
    if 'oauth_client_id' in value and (not isinstance(value['oauth_client_id'],str) or not 1<=len(value['oauth_client_id'])<=2048 or any(ord(c)<33 for c in value['oauth_client_id'])):raise Rejected('invalid_oauth_client_id')
    users=value.get('session_users',[])
    if not isinstance(users,list) or len(users)>32 or any(not isinstance(u,str) or not 1<=len(u)<=256 for u in users) or len(set(users))!=len(users):raise Rejected('invalid_session_grant')
    accounts=value.get('access_accounts',[])
    if not isinstance(accounts,list) or len(accounts)>32 or any(not isinstance(u,str) or not 1<=len(u)<=256 for u in accounts) or len(set(accounts))!=len(accounts):raise Rejected('invalid_access_accounts')
    for field in ('store','socket')+ (('public_key',) if 'public_key' in value else ()):
        if not isinstance(value[field],str) or not value[field] or not Path(value[field]).is_absolute():raise Rejected('absolute_path_required')
    for field in ('issuer','resource'):
        if not isinstance(value[field],str):raise Rejected('invalid_auth_url')
        p=urlsplit(value[field])
        if not value[field].startswith('https://') or p.scheme!='https' or not p.hostname or p.username or p.password or p.fragment or p.query or any(ord(c)<33 for c in value[field]):raise Rejected('invalid_auth_url')
        try:p.port
        except ValueError:raise Rejected('invalid_auth_url') from None
    if not isinstance(value['subjects'],list) or len(value['subjects'])>32 or (not value['subjects'] and not users and not value.get('inactive')):raise Rejected('invalid_roster')
    if value.get('inactive') and (value['subjects'] or users):raise Rejected('inactive_requires_empty_grants')
    for s in value['subjects']:
        if not isinstance(s,dict) or set(s)-{'key','user_subject','owner','pane','terminal','native','content','control'} or not {'key','user_subject','owner','pane','terminal'}<=set(s):raise Rejected('invalid_enrollment')
        for field in ('key','user_subject','owner','pane','terminal'):
            if not isinstance(s[field],str) or not 1<=len(s[field])<=(128 if field=='key' else 256):raise Rejected('invalid_enrollment')
        if 'content' in s and not isinstance(s['content'],bool):raise Rejected('invalid_content_grant')
        if 'control' in s and not isinstance(s['control'],bool):raise Rejected('invalid_control_grant')
        if s.get('native') is not None:
            n=s['native']
            if not isinstance(n,dict) or set(n)!={'source','agent','kind','value'} or any(not isinstance(v,str) or not 1<=len(v)<=256 for v in n.values()):raise Rejected('invalid_native_identity')
    if len({s['key'] for s in value['subjects']})!=len(value['subjects']):raise Rejected('duplicate_subject')
    return value


def public_key(path):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key,Encoding,PublicFormat
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>16384:raise Rejected('auth_public_key_required')
    raw=p.read_bytes()
    if b'PRIVATE KEY' in raw or raw.count(b'-----BEGIN ')!=1:raise Rejected('invalid_rsa_public_key')
    try:key=load_pem_public_key(raw)
    except (ValueError,TypeError,UnsupportedAlgorithm):raise Rejected('invalid_rsa_public_key') from None
    if not isinstance(key,RSAPublicKey) or not 2048<=key.key_size<=8192:raise Rejected('invalid_rsa_public_key')
    return key.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()


def placeholders(cfg):
    strings=[cfg[k] for k in ('store','socket','issuer','resource','public_key','jwks_url') if k in cfg]
    strings.extend(v for s in cfg['subjects'] for v in s.values() if isinstance(v,str))
    strings.extend(cfg.get('session_users',[]))
    return any('.invalid' in x or x.startswith('/path/to/') or x.startswith('replace-with-') for x in strings)


def doctor(config=None):
    import importlib.metadata
    checks=[{'name':'python','status':'pass' if (3,11)<=sys.version_info[:2]<(3,15) else 'blocked'},
            {'name':'mcp_sdk','status':'pass' if importlib.metadata.version('mcp')=='2.3.0' else 'blocked'}]
    if config:
        try:
            cfg=load_config(config);checks.append({'name':'config_shape_and_permissions','status':'pass'})
            checks.append({'name':'operator_placeholders','status':'blocked' if placeholders(cfg) else 'pass'})
            if 'public_key' in cfg:
                try:public_key(cfg['public_key']);checks.append({'name':'rsa_public_key','status':'pass'})
                except (Rejected,OSError):checks.append({'name':'rsa_public_key','status':'blocked'})
            else:checks.append({'name':'issuer_bound_jwks','status':'configured_not_fetched'})
            if 'signin' in cfg:
                from . import signin
                # signin_root creates/chmods directories; doctor only observes.
                root=Path(config).absolute().parent/'signin'
                try:ready=signin.has_password(root) and (root/'keys.json').is_file()
                except OSError:ready=False
                checks.append({'name':'builtin_signin','status':'pass' if ready else 'blocked'})
            checks.append({'name':'access','status':'inactive' if cfg.get('inactive') else 'configured'})
            parent=Path(cfg['store']).parent;db=Path(cfg['store'])
            private=parent.is_dir() and not parent.is_symlink() and not parent.stat().st_mode & 0o077 and not db.is_symlink() and (not db.exists() or not db.stat().st_mode & 0o077)
            checks.append({'name':'private_store_path','status':'pass' if private else 'blocked'})
            socket_path=Path(cfg['socket'])
            present=socket_path.exists() and not socket_path.is_symlink() and stat.S_ISSOCK(socket_path.stat().st_mode)
            checks.append({'name':'source_socket_file','status':'present_not_connected' if present else 'blocked'})
        except (Rejected,ValueError,OSError):checks.append({'name':'config_shape_and_permissions','status':'blocked'})
    else:checks.append({'name':'operator_configuration','status':'not_provided'})
    return {'mode':'offline_only','checks':checks,'live_ready':False,
            'herdr_context':{
                'environment_marker_present':os.environ.get('HERDR_ENV')=='1',
                'pane_id_available':bool(os.environ.get('HERDR_PANE_ID')),
                'socket_path_available':bool(os.environ.get('HERDR_SOCKET_PATH')),
                'source_selection':'explicit_configuration',
                'note':'Missing HERDR_* variables do not prove that Herdr is absent. Detached tool runners may not inherit the frontend context. Select the session socket and exact pane/terminal IDs explicitly; see docs/configuration.md.'},
            'not_checked':['OAuth consent/token issuance/revocation','Herdr version/identity/passivity','HTTPS/proxy exposure','callback DNS/TLS','ChatGPT/dot chat delivery'],
            'next':'Run the credential-free demo, then follow docs/getting-started.md. No source or network was contacted.'}
