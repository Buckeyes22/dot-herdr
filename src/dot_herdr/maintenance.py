"""Explicit operator backup, never a model tool or automatic retention policy."""
import argparse
import fcntl
import os
import sqlite3
import json
import secrets
import sys
from pathlib import Path
from urllib.parse import quote
from .core import Rejected


def installed_prefix(prefix=None):
    from .installation import inventory
    path=Path(prefix).expanduser().absolute() if prefix else Path.home()/'.local/share/dot-herdr'
    inventory(path)
    return path


def schema_version(path):
    if not path.exists():return None
    db=sqlite3.connect('file:'+quote(str(path),safe='/')+'?mode=ro',uri=True)
    try:return db.execute('PRAGMA user_version').fetchone()[0]
    finally:db.close()


def refresh_inventory(prefix,config,*,associate_data=False):
    """Mirror explicit owned receipts, never whole shared files or credentials."""
    from .installation import inventory,write_record,InstallationLock
    from .connections import connection_record
    from .service import service_record,receipt_path
    prefix=Path(prefix);config=Path(config).expanduser().absolute()
    connection=connection_record(config).get('owned',{})
    allowed={'plugin','marketplace','marketplace_entry','plugin_files','standalone_config','standalone_table','standalone_block'}
    entries={key:value for key,value in connection.items() if key in allowed}
    service=None
    if receipt_path(config).exists():
        owned=service_record(config)
        service={key:owned[key] for key in ('config','path','label','sha256','system')}
    with InstallationLock(prefix):
        record=inventory(prefix)
        record['connection_entries']=entries;record['service']=service;record['config']=str(config)
        if associate_data and config.parent.name=='dot-herdr' and not config.parent.is_symlink() and not config.parent.stat().st_mode&0o077:
            data=record.setdefault('data_dirs',[])
            if str(config.parent) not in data:data.append(str(config.parent))
        write_record(prefix/'.dot-herdr-install',record)
    return {'connections':entries,'service':service}


def update(source,config,*,prefix=None,bin_dir=None,sha256=None,service=None):
    """Stage before stopping; retain database dedupe and safe executable rollback."""
    from .installation import stage,activate,rollback,inventory,write_record,recover,InstallationLock
    from .setup import load_config
    from .access import service_adapter
    from .onboarding import private_directory
    config=Path(config).expanduser().absolute();pending=not config.exists() and not config.is_symlink()
    cfg=None if pending else load_config(config);original=None if pending else config.read_bytes()
    prefix=installed_prefix(prefix);record=inventory(prefix)
    for text in record['releases']:
        release=Path(text)
        if config.parent.is_relative_to(release) or cfg and Path(cfg['store']).is_relative_to(release):raise Rejected('user_state_inside_runtime_move_it_before_update')
        if pending and any(path.resolve().is_relative_to(release) for path in config.parent.glob(config.name+'.*')):raise Rejected('user_state_inside_runtime_move_it_before_update')
    refresh_inventory(prefix,config,associate_data=True)
    bin_dir=Path(bin_dir).expanduser().absolute() if bin_dir else Path(record['command']).parent
    candidate=stage(source,prefix,bin_dir,sha256=sha256)
    service=service if service is not None else service_adapter(config)
    state=service.status() if service else {'owned':False,'active':False}
    if service and not state.get('owned'):raise Rejected('connector_owned_service_required')
    active=bool(state.get('active'))
    snapshot=None
    if not pending:
        backup_root=config.parent/'backups';private_directory(backup_root)
        snapshot=backup_root/('update-'+secrets.token_hex(8));private_directory(snapshot)
    store=Path(cfg['store']) if cfg else None;before_version=schema_version(store) if store else None
    stopped=False;switched=False
    try:
        if active:service.stop();stopped=True
        if config.is_symlink() or (config.exists() if pending else config.read_bytes()!=original):raise Rejected('configuration_changed_during_update')
        if store and store.exists():backup(store,snapshot/'connector.sqlite')
        if original is not None:
            fd=os.open(snapshot/'config.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(original);stream.flush();os.fsync(stream.fileno())
        activated=activate(candidate);switched=True
        if active:
            service.start()
            if not hasattr(service,'verify'):raise Rejected('updated_service_runtime_verification_required')
            service.verify(candidate['release'])
        if snapshot:write_record(snapshot/'update.json',{'status':'updated','release':candidate['release'],'previous':activated['previous'],
                                                      'schema_before':before_version,'schema_after':schema_version(store),'config':str(config)})
    except BaseException:
        after_version=schema_version(store) if store else None
        recovery='active_installation_unchanged'
        if not switched:
            try:
                with InstallationLock(prefix):current=recover(prefix)
                switched=current['current']==candidate['release']
            except Exception:recovery='installation_recovery_uncertain_service_stopped_inspect_pointer_and_inventory'
        if switched:
            if active:
                try:service.stop()
                except Exception:recovery='stop_owned_service_then_inspect_no_automatic_rollback'
            if recovery!='stop_owned_service_then_inspect_no_automatic_rollback' and before_version==after_version and candidate['old_target']:
                try:
                    rollback(prefix,candidate['release']);recovery='previous_executable_restored_database_retained'
                    if active:
                        service.start()
                        if hasattr(service,'verify'):service.verify(candidate['old_target'])
                except Exception:recovery='service_stopped_inspect_installation_pointer_and_database'
            elif recovery!='stop_owned_service_then_inspect_no_automatic_rollback':
                recovery='schema_changed_service_stopped_use_consistent_restore_procedure_no_database_restored'
        elif stopped and recovery=='active_installation_unchanged':
            try:service.start()
            except Exception:recovery='old_installation_retained_service_restart_failed'
        if snapshot:write_record(snapshot/'update.json',{'status':'failed','release':candidate['release'],'schema_before':before_version,'schema_after':after_version,'recovery':recovery})
        raise Rejected('update_failed_'+recovery) from None
    result={'status':'updated','release':candidate['release'],'backup':str(snapshot) if snapshot else None,'service_restarted':active,
            'remote_connection':'unverified_existing_account_grants_retained'}
    if pending:result.update(service_state=state,setup='pending',next_action='Run dot-herdr setup in a normal terminal.')
    return result


def uninstall(config,*,prefix=None,purge=False,confirm_purge=False,service=None,interactive=None,ask=input,say=print):
    from .installation import uninstall as remove_installation
    from .access import service_adapter
    from .setup import load_config
    config=Path(config).expanduser().absolute();cfg=load_config(config) if config.exists() or config.is_symlink() else None;prefix=installed_prefix(prefix)
    from .installation import inventory
    for text in inventory(prefix)['releases']:
        if config.is_relative_to(Path(text)) or (cfg and Path(cfg['store']).is_relative_to(Path(text))):raise Rejected('user_state_inside_runtime_retained_move_it_before_uninstall')
    if purge and not confirm_purge:raise Rejected('purge_requires_explicit_confirmation')
    # Preview is returned separately before consent; normal uninstall retains every private record.
    purge_paths=[config.parent] if purge else []
    if purge and cfg and Path(cfg['store']).parent!=config.parent/'state':raise Rejected('purge_external_store_requires_separate_operator_removal')
    service=service if service is not None else service_adapter(config)
    refresh_inventory(prefix,config)
    if service is not None:
        state=service.status()
        if not state.get('owned'):raise Rejected('connector_owned_service_required')
        if state.get('active'):service.stop()
    store=Path(cfg['store']) if cfg else None;fd=None
    try:
        if store is not None and store.exists():
            lockpath=Path(str(store)+'.owner.lock')
            if not private_file(lockpath):raise Rejected('private_source_store_required')
            fd=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected('stop_foreground_owner_before_uninstall') from None
        if service is not None:service.remove()
        from .connections import exposure_for
        try:exposure=exposure_for(config)
        except (Rejected,ValueError,OSError):
            exposure=None;purge_paths=[]
            say('Exposure ownership could not be verified; private records retained for inspection.')
        exposure_result=None
        from .cloudflare import Journal
        journal=Journal(config)
        try:ownership=journal.read()
        except (Rejected,ValueError,OSError):
            ownership=None;purge_paths=[]
            exposure_result={'status':'ownership_unreadable','retained_journal':str(journal.path),
                             'next_action':'dot-herdr expose cloudflare --remove'}
            say('Cloudflare ownership journal could not be read; private recovery evidence retained: '+str(journal.path))
            say('To remove the exposure later: dot-herdr expose cloudflare --remove')
        if ownership is not None:
            exposure={'provider':'cloudflare','hostname':ownership['hostname'],
                      'tunnel_id':ownership['tunnel']['id'],'mode':ownership['mode']}
        if exposure:
            say('Recorded Cloudflare exposure: '+exposure['hostname']+'; tunnel '+exposure['tunnel_id']+'.')
            exposure_result={**exposure,'status':'retained','next_action':'dot-herdr expose cloudflare --remove'}
            terminal=sys.stdin.isatty() if interactive is None else interactive
            consent=False
            if terminal:
                from .onboarding import ask_clean
                consent=ask_clean(ask,'Remove this journaled Cloudflare exposure? [y/N]: ').strip().lower() in ('y','yes')
            if consent:
                from .cli import expose_cloudflare
                try:
                    expose_cloudflare(config,remove=True,say=say)
                    if journal.read() is None:
                        exposure_result['status']='removed';exposure_result.pop('next_action')
                    else:
                        exposure_result['status']='removal_incomplete'
                        say('Cloudflare removal did not finish; ownership records retained.')
                except (Rejected,ValueError,OSError):
                    exposure_result['status']='removal_incomplete'
                    say('Cloudflare removal did not finish; ownership records retained.')
            if exposure_result['status']!='removed':
                say('To remove the exposure later: dot-herdr expose cloudflare --remove')
                # A private purge must not discard the evidence needed for remote undo.
                purge_paths=[]
        from .connections import remove_owned_connections,connection_path
        try:connections=remove_owned_connections(config)
        except (Rejected,ValueError,OSError):
            connections={'status':'cleanup_incomplete','removed':'unknown','retained_receipt':str(connection_path(config)),
                         'next_action':'Inspect the retained ownership receipts; unverified shared entries were retained.'}
            # Keep the private evidence needed to inspect the affected branch.
            purge_paths=[]
        # Recheck independently of the connection receipt after local cleanup.
        # Journal construction/read is read-only and never creates private state.
        try:remaining=journal.read();unreadable=False
        except (Rejected,ValueError,OSError):remaining=None;unreadable=True
        if remaining is not None or unreadable:
            purge_paths=[]
            if exposure_result is None:
                exposure_result={'status':'ownership_unreadable' if unreadable else 'retained'}
            elif exposure_result['status']=='removed':exposure_result['status']='removal_incomplete'
            exposure_result.update(retained_journal=str(journal.path),next_action='dot-herdr expose cloudflare --remove')
            say('Private Cloudflare recovery evidence retained: '+str(journal.path)+'. Next: dot-herdr expose cloudflare --remove')
        result=remove_installation(prefix,purge_paths=purge_paths,confirm_purge=confirm_purge)
        result['connections']=connections
        if exposure_result:result['exposure']=exposure_result
        return result
    finally:
        if fd is not None:os.close(fd)


def purge_preview(config):
    from .setup import load_config
    config=Path(config).expanduser().absolute();cfg=load_config(config) if config.exists() or config.is_symlink() else None
    return {'directory':str(config.parent),'paths':[str(p) for p in sorted(config.parent.rglob('*'))],
            'external_store':str(Path(cfg['store'])) if cfg and config.parent not in Path(cfg['store']).parents else None}

def private_file(path):
    return path.is_file() and not path.is_symlink() and not path.stat().st_mode & 0o077 and path.parent.is_dir() and not path.parent.is_symlink() and not path.parent.stat().st_mode & 0o077

def backup(source,output):
    source,output=Path(source),Path(output)
    if not source.is_absolute() or not output.is_absolute():raise Rejected('absolute_backup_paths_required')
    if not private_file(source):raise Rejected('private_source_store_required')
    lockpath=Path(str(source)+'.owner.lock')
    if not private_file(lockpath):raise Rejected('source_owner_lock_required')
    if not output.parent.is_dir() or output.parent.is_symlink() or output.parent.stat().st_mode & 0o077:raise Rejected('private_backup_parent_required')
    fd=os.open(lockpath,os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:raise Rejected('stop_store_owner_before_backup') from None
        destfd=os.open(output,os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,0o600);os.close(destfd)
        try:
            src=sqlite3.connect('file:'+quote(str(source.resolve()),safe='/')+'?mode=ro',uri=True)
            try:
                if src.execute('PRAGMA user_version').fetchone()[0] not in (0,1,2):raise Rejected('unsupported_store_schema')
                dst=sqlite3.connect(output)
                try:
                    src.backup(dst)
                    if dst.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise Rejected('backup_integrity_failed')
                finally:dst.close()
            finally:src.close()
            with output.open('rb') as stream:
                if stream.read(16)!=b'SQLite format 3\x00' or output.stat().st_size<100:raise Rejected('backup_integrity_failed')
                os.fsync(stream.fileno())
        except BaseException:
            output.unlink(missing_ok=True);raise
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser(description='Consistent private SQLite backup; owner must be stopped; refuses overwrite.')
    parser.add_argument('--source',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    try:backup(args.source,args.output)
    except (Rejected,OSError,sqlite3.Error) as error:
        reason=str(error) if isinstance(error,Rejected) else 'backup_filesystem_or_sqlite_error'
        parser.exit(2,'Backup rejected: '+reason+'\n')
    print('Private consistent backup created. It contains signing material; do not publish. No runtime started.')
if __name__=='__main__':main()
