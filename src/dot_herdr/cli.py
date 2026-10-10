"""Explicit startup; operator-configured observation and control grants."""
import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
import stat
import warnings
from pathlib import Path
from urllib.parse import urlsplit

if os.environ.get('DOT_HERDR_DEBUG')=='1':
    logging.basicConfig(level=logging.INFO)
    for name in ('mcp','httpx','httpx2','httpcore','uvicorn','uvicorn.access','uvicorn.error'):
        logging.getLogger(name).setLevel(logging.INFO)
else:
    warnings.filterwarnings('ignore',message=r"TypedDict class 'RequestParamsMeta' allows extra items, but 'extra' configuration is set to `'forbid'`\.",category=Warning)
    for name in ('mcp','httpx','httpx2','httpcore','uvicorn','uvicorn.access','uvicorn.error'):
        logging.getLogger(name).setLevel(logging.WARNING)

from .core import Store,Rejected
from .runtime import TunnelRuntimeFailure
from .signin import hidden_input

from .setup import load_config,public_key,doctor,write_template,placeholders,default_config_path


def cloudflare_token(token_file=None):
    """Read a bounded owner file or hidden input; never persist the API credential."""
    if token_file is None:
        if not sys.stdin.isatty():raise Rejected('cloudflare_api_token_requires_terminal_or_token_file')
        token=hidden_input('Cloudflare API token (Account › Cloudflare Tunnel › Edit; Zone › DNS › Edit; Zone › Zone › Read): ',getpass=getpass.getpass).strip()
    else:
        try:
            fd=os.open(Path(token_file).expanduser(),os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_size>4096:
                    raise Rejected('cloudflare_token_file_requires_owned_regular_file_at_most_4kib')
                raw=stream.read(4097)
                if len(raw)>4096:raise Rejected('cloudflare_token_file_requires_owned_regular_file_at_most_4kib')
                token=raw.decode('utf-8').strip()
        except (OSError,UnicodeError):
            raise Rejected('cloudflare_token_file_requires_owned_regular_file_at_most_4kib') from None
    if not token:raise Rejected('cloudflare_api_token_required')
    return token


def expose_cloudflare(config, *, login=False, token_file=None, remove=False, say=print):
    """Shared explicit exposure/removal flow for CLI, migration and uninstall."""
    from . import cloudflare
    from .connections import connection_record,save_connection
    cfg=load_config(config)
    journal=cloudflare.Journal(config).read() if remove else None
    detected=cloudflare.detect_cloudflared()
    if not detected:
        say('cloudflared was not found on PATH.')
        if not (remove and journal and journal['mode']=='api'):
            say(cloudflare.INSTALL_DOCS)
            raise Rejected('cloudflared_not_found_install_it_see_docs_reachability')
    else:
        say('cloudflared: '+detected['path']+'; '+detected['version'])
    record=connection_record(config)
    if remove:
        token=None
        if journal:
            if token_file is not None or journal['mode']=='api':
                token=cloudflare_token(token_file)
            elif sys.stdin.isatty():
                token=hidden_input('Optional: a Cloudflare API token (Zone › DNS › Edit, Zone › Zone › Read) also deletes the DNS record; press Enter to skip: ',getpass=getpass.getpass).strip() or None
        asyncio.run(cloudflare.remove(config,token=token,cloudflared=detected['path'] if detected else None,say=say))
        remaining=cloudflare.Journal(config).read()
        if remaining is None:
            record.pop('exposure',None);save_connection(config,record)
            say('Cloudflare exposure removed; only journaled objects were considered.')
        else:
            pending=[]
            if remaining.get('dns'):pending.append('DNS record pending deletion (delete it manually if no API token was supplied)')
            if not remaining['tunnel_removed']:pending.append('tunnel pending deletion')
            if remaining['phase']!='complete':pending.append('partially provisioned exposure cleanup pending')
            elif remaining['tunnel_removed'] and not remaining['dns']:pending.append('local files pending deletion')
            say('Cloudflare removal incomplete: '+('; '.join(pending) or 'ownership journal remains')+'. Re-running dot-herdr expose cloudflare --remove finishes removal.')
        return None
    hostname=urlsplit(cfg['resource']).hostname
    port=cfg.get('local_port',8000)
    if login:
        exposure=cloudflare.expose_login(config,hostname,port,cloudflared=detected['path'],say=say)
    else:
        token=cloudflare_token(token_file)
        exposure=asyncio.run(cloudflare.expose_api(config,hostname,port,token,say=say))
    record['exposure']=exposure;save_connection(config,record)
    say('Cloudflare exposure saved. Restart the service: dot-herdr service restart; or run dot-herdr run.')
    return exposure

def main():
    parser=argparse.ArgumentParser(description='Guided Herdr-to-dot connector with optional user-service operation.')
    from . import __version__
    parser.add_argument('--version',action='version',version='dot-herdr '+__version__)
    parser.add_argument('command',choices=['setup','connect','migrate-route','login','tunnel-setup','tunnel-check','doctor','init-config','demo','check','run','status','service','access','check-connection','check-recovery','update','uninstall','signin','expose'])
    parser.add_argument('action',nargs='?',choices=['install','start','stop','restart','status','remove','set-password','cloudflare'],help='Service/signin/expose action')
    parser.add_argument('--to',choices=['cloudflare'],help='Migrate-route: expose the existing resource through Cloudflare')
    parser.add_argument('--token-file',help='Cloudflare: owned regular API token file, at most 4 KiB')
    parser.add_argument('--remove',action='store_true',help='Expose: remove only journaled Cloudflare objects')
    parser.add_argument('--json',action='store_true',help='Status: machine-readable observations')
    parser.add_argument('--live',action='store_true',help='Status: bounded read-only live probes')
    parser.add_argument('--recovery',choices=['inspect','finish','abandon','start-new'],help='Check-recovery: inspect or close the saved test')
    parser.add_argument('--request-id',help='Check-recovery start-new: explicit fresh connection-check request ID')
    parser.add_argument('--subscription-id',help='Check-connection: exact test automation subscription ID if ChatGPT showed one')
    parser.add_argument('--credential-file',help='Run/service: absolute private tunnel runtime-key file')
    parser.add_argument('--login-start',action='store_true',help='Service install: explicitly enable user-login startup')
    parser.add_argument('--revoke-all',action='store_true',help='Access: revoke all local grants while retaining history')
    parser.add_argument('--source',help='Update: explicitly selected trusted source/wheel/archive or HTTPS release URL')
    parser.add_argument('--sha256',help='Update: expected published release digest')
    parser.add_argument('--prefix',help='Update/uninstall: owned installation prefix')
    parser.add_argument('--bin-dir',help='Update: owned command directory')
    parser.add_argument('--purge',action='store_true',help='Uninstall: preview deletion of exact private paths')
    parser.add_argument('--confirm-purge',action='store_true',help='Uninstall: explicitly confirm the requested private purge')
    parser.add_argument('--oauth-client-id',help='Setup: advanced pre-registered public OAuth client ID (never a secret)')
    parser.add_argument('--route',choices=['tunnel','https','loopback'],help='Setup/connect: selected transport; eligibility required for tunnel')
    parser.add_argument('--wiring',choices=['registered-plugin','standalone','plugin-http'],help='Setup/connect: one selected client wiring')
    parser.add_argument('--client-app',choices=['chatgpt-web','desktop'],help='Setup/connect/migrate-route: where you will use the plugin')
    parser.add_argument('--confirm',action='store_true',help='Migrate-route: explicitly confirm the reviewed selection')
    parser.add_argument('--output',help='New template path for init-config; refuses overwrite')
    parser.add_argument('--config',help='Private config path; setup/check/run default to the user config directory')
    parser.add_argument('--socket',help='Setup/access: existing absolute Herdr socket; otherwise discover running sessions')
    parser.add_argument('--account-subject',help='Access: verified account subject for explicit selection')
    parser.add_argument('--access-mode',choices=['1','2','3','4'],help='Access: 1 observe agents; 2 control agents; 3 whole session; 4 revoke all')
    parser.add_argument('--agents',help='Access: numbered agents separated by commas; empty only with whole-session access')
    parser.add_argument('--content',action=argparse.BooleanOptionalAction,default=None,help='Access: explicitly allow or withhold visible context')
    parser.add_argument('--apply-access',action='store_true',help='Access: approve the complete requested selection')
    parser.add_argument('--reselect-session',action='store_true',help='Access: treat even the same socket as a new Herdr session')
    parser.add_argument('--no-connect',action='store_true',help='Setup only: skip connection preparation')
    parser.add_argument('--no-open',action='store_true',help='Connect/setup: do not open links or sign in; login: use Codex no-browser flow')
    parser.add_argument('--no-login',action='store_true',help='Connect/setup: defer automatic interactive OAuth sign-in')
    parser.add_argument('--login',action='store_true',help='Run: start local MCP OAuth sign-in after the listener is ready; expose/migrate-route --to cloudflare: use cloudflared login')
    parser.add_argument('--no-register',action='store_true',help='Connect/setup: package the plugin without standalone local MCP registration')
    parser.add_argument('--endpoint',help='Setup: discover this existing HTTPS MCP URL; connect/login: select the configured HTTPS resource')
    parser.add_argument('--app-id',help='ChatGPT/Codex desktop app (explicit): local plugin package mapping for an existing registered server')
    parser.add_argument('--tunnel-id',help='Tunnel-setup/connect/setup: existing OpenAI tunnel ID; does not create an account or tunnel')
    parser.add_argument('--no-download',action='store_true',help='Tunnel-setup/connect/setup: require tunnel-client already on PATH')
    parser.add_argument('--tunnel',action='store_true',help='Run: supervise the prepared Secure MCP Tunnel alongside the connector')
    args=parser.parse_args()
    if args.socket and args.command not in ('setup','access'):parser.error('--socket is only for setup/access; run uses the configured source')
    if (args.account_subject or args.access_mode or args.agents is not None or args.content is not None or args.apply_access or args.reselect_session) and args.command!='access':parser.error('access selection flags are only for access')
    if args.output and args.command!='init-config':parser.error('--output is only for init-config')
    if args.no_connect and args.command!='setup':parser.error('--no-connect is only for setup')
    if args.tunnel and args.command not in ('run','service'):parser.error('--tunnel is only for run')
    if (args.app_id or args.no_register or args.no_login) and args.command not in ('setup','connect','migrate-route') or args.command=='migrate-route' and (args.no_register or args.no_login):parser.error('advanced local plugin options are only for setup/connect')
    if (args.endpoint or args.no_open) and args.command not in ('setup','connect','migrate-route','login'):parser.error('--endpoint/--no-open are only for setup/connect/migrate-route/login')
    cloudflare_migration=args.command=='migrate-route' and args.to=='cloudflare'
    if args.to and args.command!='migrate-route':parser.error('--to is only for migrate-route')
    if args.remove and args.command!='expose':parser.error('--remove is only for expose')
    if args.token_file is not None and args.command!='expose' and not cloudflare_migration:parser.error('--token-file is only for expose/migrate-route --to cloudflare')
    if args.login and args.command not in ('run','expose') and not cloudflare_migration:parser.error('--login is only for run')
    if args.login and args.token_file is not None:parser.error('--login and --token-file cannot be combined')
    if cloudflare_migration and (args.endpoint or args.app_id or args.client_app or args.no_open):parser.error('--to cloudflare keeps the configured resource and wiring; do not combine migration selection flags')
    if (args.tunnel_id or args.no_download) and args.command not in ('setup','connect','tunnel-setup'):parser.error('tunnel setup options are only for setup/connect/tunnel-setup')
    if args.oauth_client_id and args.command!='setup':parser.error('--oauth-client-id is only for setup')
    if args.credential_file and args.command not in ('run','service'):parser.error('--credential-file is only for run/service')
    if args.login_start and not (args.command=='service' and args.action=='install'):parser.error('--login-start is only for service install')
    if args.revoke_all and args.command!='access':parser.error('--revoke-all is only for access')
    if (args.purge or args.confirm_purge) and args.command!='uninstall':parser.error('purge options are only for uninstall')
    if args.confirm_purge and not args.purge:parser.error('--confirm-purge requires --purge')
    if (args.route or args.wiring or args.client_app) and args.command not in ('setup','connect','migrate-route'):parser.error('--route/--wiring/--client-app are only for setup/connect/migrate-route')
    if args.confirm and args.command!='migrate-route':parser.error('--confirm is only for migrate-route')
    if (args.json or args.live) and args.command!='status':parser.error('--json/--live are only for status')
    if args.recovery and args.command!='check-recovery':parser.error('--recovery is only for check-recovery')
    if args.request_id and not (args.command=='check-recovery' and args.recovery=='start-new'):parser.error('--request-id is only for check-recovery --recovery start-new')
    if args.subscription_id and args.command!='check-connection':parser.error('--subscription-id is only for check-connection')
    if args.command=='check-recovery' and not args.recovery:parser.error('check-recovery requires --recovery')
    if args.command=='check-recovery' and args.recovery=='start-new' and not args.request_id:parser.error('start-new requires --request-id')
    try:
        config=Path(args.config) if args.config else default_config_path()
        def service_adapter():
            from .access import service_adapter as owned_service
            return owned_service(config)
        if args.action and args.command not in ('service','signin','expose'):parser.error('action is only for service')
        if args.command=='signin':
            if args.action!='set-password':parser.error('signin requires set-password')
            if not sys.stdin.isatty():raise Rejected('signin_password_requires_terminal')
            from . import signin
            pw=signin.ask_new_password(getpass=getpass.getpass)
            signin.set_password(signin.signin_root(config),pw)
            print('Sign-in password set.');return
        if args.command=='expose':
            if args.action!='cloudflare':parser.error('expose requires cloudflare')
            expose_cloudflare(config,login=args.login,token_file=args.token_file,remove=args.remove);return
        if args.command=='status':
            from .status import status,render
            report=asyncio.run(status(config,live=args.live));print(json.dumps(report,indent=2) if args.json else render(report));return
        if args.command=='migrate-route':
            from .onboarding import ask_clean
            from .connections import connection_record,migration_entries,migrate_connection
            record=connection_record(config)
            if cloudflare_migration:
                print('Saved route: '+str(record.get('route','none'))+'; wiring: '+str(record.get('wiring','none'))+'; endpoint: '+str(record.get('endpoint','none')))
                if not sys.stdin.isatty() and (not args.route or not args.wiring or not args.confirm):raise Rejected('migration_requires_explicit_route_wiring_and_confirm')
                if args.route and args.route!='https' or args.wiring and args.wiring!=record.get('wiring'):raise Rejected('cloudflare_migration_keeps_https_and_saved_wiring')
                if not args.confirm:
                    if ask_clean(input,'Expose the configured resource through Cloudflare, keeping the plugin URL and wiring? [y/N]: ').strip().lower() not in ('y','yes'):raise Rejected('migration_cancelled')
                migrate_connection(config,record.get('route'),record.get('wiring'),to='cloudflare',login=args.login,token_file=args.token_file)
                return
            entries=migration_entries(config)
            print('Saved route: '+str(record.get('route','none'))+'; wiring: '+str(record.get('wiring','none'))+'; endpoint: '+str(record.get('endpoint','none')))
            for entry in entries:print(entry['classification']+': '+entry['path'])
            interactive=sys.stdin.isatty()
            choice_only=bool(args.client_app and not args.route and not args.wiring and not args.app_id)
            if choice_only and record.get('app_id') and args.client_app=='chatgpt-web':raise Rejected('desktop_local_package_requires_confirmed_migration')
            if not interactive and not choice_only and (not args.route or not args.wiring or not args.confirm):raise Rejected('migration_requires_explicit_route_wiring_and_confirm')
            route=args.route or (record.get('route') if choice_only else ask_clean(input,'New route [https/tunnel/loopback]; Enter cancels: ').strip())
            wiring=args.wiring or (record.get('wiring') if choice_only else ask_clean(input,'New wiring [registered-plugin/standalone/plugin-http]; Enter cancels: ').strip())
            if not route or not wiring:raise Rejected('migration_cancelled')
            if interactive and not choice_only and not args.confirm and ask_clean(input,'Back up and migrate only unchanged owned entries? [y/N]: ').strip().lower() not in ('y','yes'):raise Rejected('migration_cancelled')
            value=migrate_connection(config,route,wiring,endpoint=args.endpoint,app_id=args.app_id,client_app=args.client_app,launch=not args.no_open)
            print(json.dumps(value,indent=2));return
        if args.command=='service':
            from .service import install,manage
            if not args.action:parser.error('service requires an action')
            value=install(config,tunnel=args.tunnel,credential_file=args.credential_file,login_start=args.login_start) if args.action=='install' else manage(config,args.action)
            print(json.dumps(value,indent=2));return
        if args.command=='access':
            from .access import configure_access
            value=asyncio.run(configure_access(config,revoke_all=args.revoke_all,user_subject=args.account_subject,socket_path=args.socket,mode=args.access_mode,agent_numbers=args.agents,content=args.content,approve=args.apply_access,reselect_session=args.reselect_session,interactive=sys.stdin.isatty(),service=service_adapter()))
            print(json.dumps(value,indent=2));return
        if args.command=='check-connection':
            from .connection_check import check_connection
            asyncio.run(check_connection(config,interactive=sys.stdin.isatty(),subscription_id=args.subscription_id));return
        if args.command=='check-recovery':
            from .connection_check import recover_connection
            value=asyncio.run(recover_connection(config,args.recovery,request_id=args.request_id));print(json.dumps(value,indent=2));return
        if args.command=='update':
            from .maintenance import update
            if not args.source:parser.error('update requires --source')
            value=update(args.source,config,prefix=args.prefix,bin_dir=args.bin_dir,sha256=args.sha256,service=service_adapter());print(json.dumps(value,indent=2));return
        if args.command=='uninstall':
            from .maintenance import uninstall,purge_preview
            if args.purge and not args.confirm_purge:
                print(json.dumps(purge_preview(config),indent=2));print('Preview only. Rerun with --purge --confirm-purge to explicitly remove these private paths.');return
            value=uninstall(config,prefix=args.prefix,purge=args.purge,confirm_purge=args.confirm_purge,service=service_adapter());print(json.dumps(value,indent=2));return
        if args.command=='setup':
            from .onboarding import guided_setup
            value=asyncio.run(guided_setup(config,args.socket,interactive=sys.stdin.isatty(),endpoint=args.endpoint,app_id=args.app_id,tunnel_id=args.tunnel_id,route=args.route,wiring=args.wiring or ('plugin-http' if args.no_register else None),launch=not args.no_open,login=not args.no_login,prepare=not args.no_connect,download=not args.no_download,oauth_client_id=args.oauth_client_id,client_app=args.client_app))
            return
        if args.command=='connect':
            from .connections import prepare_connections,connection_record,save_connection,local_url
            cfg=load_config(config);record=connection_record(config)
            route=args.route or record.get('route') or ('loopback' if args.endpoint==local_url(cfg) else 'https')
            wiring=args.wiring or record.get('wiring') or ('plugin-http' if args.no_register else 'registered-plugin')
            client_app=args.client_app or record.get('client_app') or 'chatgpt-web'
            if args.app_id and client_app!='desktop':raise Rejected('app_id_requires_desktop_client_app')
            if record.get('client_app') and client_app!=record['client_app']:raise Rejected('existing_client_app_change_requires_explicit_migration (run dot-herdr migrate-route --client-app)')
            if record.get('route') and route!=record['route'] or record.get('wiring') and wiring!=record['wiring']:raise Rejected('existing_route_change_requires_explicit_migration (run dot-herdr migrate-route)')
            endpoint=args.endpoint or record.get('endpoint') or (local_url(cfg) if route=='loopback' else cfg['resource'])
            result=prepare_connections(cfg,endpoint=endpoint,app_id=args.app_id,wiring=wiring,launch=not args.no_open,client_app=client_app)
            record.update(route=route,wiring=wiring,client_app=client_app,endpoint=endpoint,stage='identity',owned={**record.get('owned',{}),**result.get('owned',{})})
            if result.get('local_package'):record['local_package']=result['local_package']
            if args.app_id:record['app_id']=args.app_id
            save_connection(config,record)
            if args.tunnel_id:
                from .tunnel import prepare_tunnel
                prepare_tunnel(config,args.tunnel_id,download=not args.no_download)
            return
        if args.command=='login':
            from .connections import connection_record
            if connection_record(config).get('wiring') in ('registered-plugin','plugin-http'):
                raise Rejected('selected_plugin_authentication_pending_use_app_authenticate')
            from .login import login_mcp
            result=asyncio.run(login_mcp(load_config(config),endpoint=args.endpoint,browser=not args.no_open))
            if result['status']!='authenticated':raise Rejected('oauth_login_'+result['status'])
            return
        if args.command in ('tunnel-setup','tunnel-check'):
            tunnel_cfg=load_config(config)
            from .tunnel import prepare_tunnel,check_tunnel
            if args.command=='tunnel-setup':
                if not args.tunnel_id:raise Rejected('tunnel_id_required')
                prepare_tunnel(config,args.tunnel_id,download=not args.no_download)
            else:check_tunnel(config,cfg=tunnel_cfg)
            return
        if args.command=='init-config':
            if not args.output:raise Rejected('output_required')
            write_template(args.output)
            print('Private template created; placeholders remain. Follow docs/getting-started.md; no credentials or source access.')
            return
        if args.command=='demo':
            from .demo import demo
            import logging
            logging.disable(logging.INFO)
            print(json.dumps(asyncio.run(demo()),indent=2))
            return
        if args.command=='doctor':
            path=args.config or (str(default_config_path()) if default_config_path().exists() else None)
            report=doctor(path);print(json.dumps(report,indent=2))
            if any(c['status']=='blocked' for c in report['checks']):parser.exit(2)
            return
        if not config.exists():raise Rejected('configuration_not_found_run_setup')
        cfg=load_config(config)
        if placeholders(cfg):raise Rejected('operator_placeholders_remaining')
        from .auth import verifier_from_config
        verifier_from_config(cfg)
        if args.command=='check':
            print('Offline configuration and key-source shape accepted. Live Herdr, OAuth and HTTPS readiness NOT tested.')
            return
        from .runtime import run
        asyncio.run(run(config,cfg=cfg,tunnel=args.tunnel,login=args.login,credential_file=args.credential_file))
    except (EOFError,KeyboardInterrupt):
        parser.exit(2,'Cancelled; existing configuration retained. Rerun the requested command to continue.\n')
    except TunnelRuntimeFailure as error:
        parser.exit(1,'Runtime failed: '+str(error)+'. See docs/troubleshooting.md.\n')
    except (Rejected,ValueError,OSError) as error:
        reason=str(error) if isinstance(error,Rejected) else 'configuration_or_filesystem_error'
        parser.exit(2,'Setup/startup rejected: '+reason+'. '+NEXT.get(reason,'See docs/troubleshooting.md.')+'\n')

NEXT={'store_already_owned':'Another connector already runs with this configuration, usually the background service. Check it with dot-herdr service status; run dot-herdr service stop first if you want a foreground dot-herdr run.',
      'runtime_listener_failed':'The local listener could not start, usually because another program uses the local port. Stop that program, or set a different local_port in the configuration, then start again.'}
if __name__=='__main__':main()
