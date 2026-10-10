"""Owned user installation with immutable staged environments and atomic activation."""
import hashlib
import fcntl
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

if __package__:
    from .core import Rejected
else:
    Rejected=ValueError  # The source bootstrap loads this module before installation.


class PipInstallRejected(Rejected,subprocess.CalledProcessError):
    """Handled CLI rejection retaining the staging subprocess exception contract."""
    __init__=ValueError.__init__
    __str__=ValueError.__str__

MARKER='.dot-herdr-install'
OWNER='dot-herdr'
MAX_ARTIFACT=128*1024*1024


def check_output(command,label,env=None):
    try:return subprocess.run(command,check=True,capture_output=True,text=True,timeout=60,env=env)
    except subprocess.CalledProcessError as error:
        def safe(value):
            value=(value or '')[-4096:]
            value=re.sub(r'(?i)\bBearer\s+[^\s,;]+','Bearer [REDACTED]',value)
            value=re.sub(r'(?i)\b(authorization|token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+',r'\1=[REDACTED]',value)
            return value.replace('\x00','')
        raise ValueError(label+' failed (exit '+str(error.returncode)+'); stdout: '+safe(error.stdout)+'; stderr: '+safe(error.stderr)) from None


def no_symlink_ancestors(path):
    for ancestor in (path,*path.parents):
        if ancestor.is_symlink():raise ValueError('Symlink destination or ancestor refused.')


class InstallationLock:
    def __init__(self,prefix):self.path=Path(prefix)/'.install.lock';self.fd=None
    def __enter__(self):
        self.fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        if os.fstat(self.fd).st_mode&0o077:os.close(self.fd);raise ValueError('Private installation lock required.')
        try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:os.close(self.fd);raise ValueError('Another installation operation is running.') from None
        return self
    def __exit__(self,*args):os.close(self.fd)


def private_directory(path):
    no_symlink_ancestors(path)
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink() or not path.is_dir() or path.stat().st_mode&0o077:raise ValueError('Private installation directory required.')


def write_record(path,value):
    temporary=path.with_name(path.name+'.new-'+secrets.token_hex(6))
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as stream:json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:temporary.unlink(missing_ok=True)


def inventory(prefix):
    prefix=Path(prefix).expanduser().absolute();marker=prefix/MARKER
    no_symlink_ancestors(prefix)
    if prefix.is_symlink() or not prefix.is_dir() or prefix.stat().st_mode&0o077 or marker.is_symlink() or not marker.is_file():
        raise ValueError('Connector-owned private installation required.')
    if marker.stat().st_size==0:
        # The 0.2 installer used an empty marker and an in-place venv. Reading
        # ownership does not move its live runtime; activation does that stopped.
        if marker.stat().st_uid!=os.getuid() or (prefix/'venv').is_symlink() or not (prefix/'venv/bin/dot-herdr').is_file():raise ValueError('Invalid legacy installation.')
        return {'owner':OWNER,'format':1,'prefix':str(prefix),'command':str(Path.home()/'.local/bin/dot-herdr'),
                'target':str(prefix/'venv/bin/dot-herdr'),'releases':[str(prefix/'venv')],
                'current':str(prefix/'venv'),'previous':None,'legacy':True,'data_dirs':[]}
    if marker.stat().st_mode&0o077:raise ValueError('Private installation inventory required.')
    if marker.stat().st_size>1024*1024:raise ValueError('Invalid installation inventory.')
    record=json.loads(marker.read_text())
    if not isinstance(record,dict) or record.get('owner')!=OWNER or record.get('prefix')!=str(prefix) or record.get('format')!=1:
        raise ValueError('Connector-owned installation inventory required.')
    if not isinstance(record.get('releases'),list) or any(not isinstance(p,str) or (Path(p).parent!=prefix/'releases' and not (record.get('legacy') and Path(p)==prefix/'venv')) for p in record['releases']):raise ValueError('Invalid owned runtime inventory.')
    if record.get('target')!=str(prefix/'venv/bin/dot-herdr') or not isinstance(record.get('command'),str) or not Path(record['command']).is_absolute():raise ValueError('Invalid owned command inventory.')
    if any(record.get(field) is not None and record[field] not in record['releases'] for field in ('current','previous')):raise ValueError('Invalid owned runtime pointer.')
    return record


def recover(prefix):
    """Reconcile a durable switch intent before any runtime is started."""
    prefix=Path(prefix);record=inventory(prefix);pending=record.get('pending')
    if not pending:return record
    pointer=prefix/'venv'
    if pending.get('legacy_from'):
        if pending['legacy_from']!=str(pointer) or Path(pending['from']).parent!=prefix/'releases':raise ValueError('Invalid legacy switch journal.')
        if pointer.is_dir() and not pointer.is_symlink():
            record['current']=str(pointer);record['releases'].remove(pending['from']);record.pop('pending');write_record(prefix/MARKER,record);return record
        if not pointer.exists() and not pointer.is_symlink() and Path(pending['from']).is_dir():pointer.symlink_to(pending['from'])
    current=os.readlink(pointer) if pointer.is_symlink() else None
    if current not in (pending['from'],pending['to']):raise ValueError('Interrupted installation pointer changed; inspect before recovery.')
    if current==pending['to']:
        record['previous']=pending['from'];record['current']=pending['to']
    else:record['current']=pending['from']
    if pending.get('legacy_from'):
        record.pop('legacy',None)
        if pending['legacy_from'] in record['releases']:record['releases'].remove(pending['legacy_from'])
    record.pop('pending');write_record(prefix/MARKER,record)
    return record


def digest(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(65536),b''):result.update(chunk)
    return result.hexdigest()


def artifact(source,destination,sha256=None):
    """HTTPS downloads require an explicit digest from the selected release source."""
    text=str(source);remote=text.startswith('https://')
    if sha256 is not None and (len(sha256)!=64 or any(c not in '0123456789abcdef' for c in sha256.lower())):raise ValueError('A SHA-256 hex digest is required.')
    if remote:
        parsed=urlsplit(text)
        if not sha256 or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:raise ValueError('HTTPS release URL and published SHA-256 required.')
        name=Path(parsed.path).name
        if not name.endswith(('.whl','.tar.gz')):raise ValueError('Select a versioned wheel or source archive.')
        target=destination/name
        with urlopen(Request(text,headers={'User-Agent':OWNER+'/installer'}),timeout=30) as response:
            final=urlsplit(response.geturl())
            if final.scheme!='https' or final.hostname!=parsed.hostname:raise ValueError('Release download redirected outside the selected HTTPS origin.')
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            total=0
            with os.fdopen(fd,'wb') as output:
                while chunk:=response.read(65536):
                    total+=len(chunk)
                    if total>MAX_ARTIFACT:raise ValueError('Release artifact exceeds download limit.')
                    output.write(chunk)
        selected=target
    else:
        selected=Path(source).expanduser().absolute()
        if selected.is_symlink():raise ValueError('Artifact must not be a symlink.')
        if selected.is_dir():
            if sha256:raise ValueError('Checksums apply to wheel/archive files, not source directories.')
            if not (selected/'pyproject.toml').is_file():raise ValueError('Use a source checkout or connector wheel/archive.')
            return selected,{'source':'local_source','integrity':'not_a_release_artifact'}
        if not selected.is_file() or not selected.name.endswith(('.whl','.tar.gz')):raise ValueError('Use a source checkout or connector wheel/archive.')
    actual=digest(selected)
    if sha256 and actual!=sha256.lower():raise ValueError('Release artifact SHA-256 mismatch.')
    evidence={'source':urlsplit(text)._replace(query='',fragment='').geturl() if remote else str(selected),'sha256':actual,'integrity':'published_digest_checked' if sha256 else 'local_artifact_digest_recorded'}
    if selected.name.endswith('.tar.gz'):
        extracted=destination/'source';extracted.mkdir(mode=0o700)
        with tarfile.open(selected,'r:gz') as archive:
            members=archive.getmembers()
            if len(members)>10000 or sum(m.size for m in members)>MAX_ARTIFACT:raise ValueError('Source archive exceeds extraction limit.')
            for member in members:
                path=Path(member.name)
                if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):raise ValueError('Unsafe source archive member.')
            archive.extractall(extracted,members=members,filter='data')
        candidates=[p for p in [extracted,*extracted.iterdir()] if p.is_dir() and (p/'pyproject.toml').is_file()]
        if len(candidates)!=1:raise ValueError('Source archive must contain one project root.')
        selected=candidates[0]
    return selected,evidence


def dependency_constraints(source,destination):
    if source.is_dir():
        lock=source/'requirements.lock'
        if lock.is_symlink() or not lock.is_file() or lock.stat().st_size>65536:raise ValueError('Release must include its reviewed dependency lock.')
        raw=lock.read_bytes()
    else:
        try:
            with zipfile.ZipFile(source) as wheel:
                names=[name for name in wheel.namelist() if name.endswith('.data/data/share/dot-herdr/requirements.lock')]
                if len(names)!=1 or wheel.getinfo(names[0]).file_size>65536:raise ValueError('Release wheel must include its reviewed dependency lock.')
                raw=wheel.read(names[0])
        except zipfile.BadZipFile:raise ValueError('Invalid connector wheel.') from None
    lock=destination/'requirements.lock';lock.write_bytes(raw)
    return lock


def stage(source,prefix,bin_dir,*,sha256=None):
    if sys.platform not in ('linux','darwin'):raise ValueError('Linux or macOS is required.')
    if not (3,11)<=sys.version_info[:2]<(3,15):raise ValueError('Python 3.11–3.14 is required.')
    prefix=Path(prefix).expanduser().absolute();bin_dir=Path(bin_dir).expanduser().absolute()
    marker=prefix/MARKER;link=bin_dir/'dot-herdr';target=prefix/'venv/bin/dot-herdr'
    no_symlink_ancestors(bin_dir)
    if link.exists() or link.is_symlink():
        if not link.is_symlink() or Path(os.readlink(link))!=target:raise ValueError('Existing command would be overwritten.')
    if prefix.is_symlink() or (prefix.exists() and not marker.is_file()):raise ValueError('Installation directory is already used by something else.')
    private_directory(prefix)
    if marker.exists():
        with InstallationLock(prefix):record=recover(prefix)
    else:
        config_root=Path(os.environ.get('XDG_CONFIG_HOME',''))
        if not config_root.is_absolute():config_root=Path.home()/'.config'
        record={'owner':OWNER,'format':1,'prefix':str(prefix),'command':str(link),'target':str(target),'releases':[],'current':None,'previous':None,'data_dirs':[str(config_root/'dot-herdr')]}
        write_record(marker,record)
    if record.get('legacy'):
        record['command']=str(link);write_record(marker,record)
    if record['command']!=str(link) or record['target']!=str(target):raise ValueError('Installation command ownership mismatch.')
    if bin_dir.is_symlink():raise ValueError('Command directory must not be a symlink.')
    if link.exists() or link.is_symlink():
        if not link.is_symlink() or Path(os.readlink(link))!=target:raise ValueError('Existing command would be overwritten.')
    pointer=prefix/'venv'
    if pointer.exists() and not pointer.is_symlink() and not record.get('legacy'):raise ValueError('Unowned environment directory refused.')
    old_target=os.readlink(pointer) if pointer.is_symlink() else str(pointer) if record.get('legacy') else None
    if old_target!=record['current']:raise ValueError('Installation pointer changed outside its inventory.')
    releases=prefix/'releases';private_directory(releases)
    release=releases/('release-'+secrets.token_hex(8));release.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix='artifact-',dir=prefix) as directory:
            selected,evidence=artifact(source,Path(directory),sha256)
            constraints=dependency_constraints(selected,Path(directory));evidence['dependencies_sha256']=digest(constraints)
            venv.EnvBuilder(with_pip=True).create(release)
            python=release/'bin/python';entry=release/'bin/dot-herdr'
            try:check_output([str(python),'-m','pip','install','--disable-pip-version-check','--constraint',str(constraints),str(selected)],'Staged pip install')
            except ValueError as error:raise PipInstallRejected(str(error)+'; current installation retained') from None
            if not entry.is_file() or not os.access(entry,os.X_OK):raise ValueError('Installed command is missing.')
            clean_env=dict(os.environ,TMPDIR=str(Path(directory).resolve()))
            result=check_output([str(entry),'demo'],'Staged demo',clean_env)
            if len(result.stdout)>262144 or json.loads(result.stdout).get('demo')!='passed':raise ValueError('Local demo did not pass.')
            clean_env['XDG_CONFIG_HOME']=str(Path(directory)/'empty-config')
            checked=check_output([str(entry),'doctor'],'Staged doctor',clean_env)
            if len(checked.stdout)>262144:raise ValueError('Offline validation output exceeds limit.')
            report=json.loads(checked.stdout)
            if any(c.get('status')=='blocked' for c in report.get('checks',[])):raise ValueError('Staged offline checks failed.')
        write_record(release/'.dot-herdr-runtime',{'owner':OWNER,'release':str(release),'artifact':evidence})
    except BaseException:
        shutil.rmtree(release);raise
    with InstallationLock(prefix):
        latest=recover(prefix)
        if latest['current']!=old_target:
            shutil.rmtree(release);raise ValueError('Installation changed while staging.')
        latest['releases'].append(str(release));write_record(prefix/MARKER,latest)
    return {'prefix':str(prefix),'release':str(release),'command':str(link),'target':str(target),'old_target':old_target,'artifact':evidence}


def activate(candidate):
    with InstallationLock(candidate['prefix']):return _activate(candidate)


def _activate(candidate):
    prefix=Path(candidate['prefix']);record=inventory(prefix);pointer=prefix/'venv';link=Path(candidate['command'])
    release=Path(candidate['release'])
    no_symlink_ancestors(release);no_symlink_ancestors(link.parent)
    if release.parent!=prefix/'releases' or release.is_symlink() or not (release/'.dot-herdr-runtime').is_file():raise ValueError('Owned staged release required.')
    legacy=bool(record.get('legacy'));current=os.readlink(pointer) if pointer.is_symlink() else str(pointer) if legacy else None
    if current!=candidate['old_target'] or current!=record['current']:raise ValueError('Installation changed while staging.')
    if link.exists() or link.is_symlink():
        if not link.is_symlink() or os.readlink(link)!=candidate['target']:raise ValueError('Command changed while staging.')
    link.parent.mkdir(parents=True,exist_ok=True)
    if not link.is_symlink():link.symlink_to(candidate['target'])
    # Journal both owned runtimes before switching; an interrupted final write is
    # recoverable and never strands NEW pointer / OLD inventory.
    if str(release) not in record['releases']:record['releases'].append(str(release))
    previous=current
    if legacy:
        previous=str(prefix/'releases'/('legacy-'+secrets.token_hex(8)))
        record['releases'].append(previous)
        write_record(pointer/'.dot-herdr-runtime',{'owner':OWNER,'release':previous,'artifact':{'source':'legacy_owned_installation'}})
    record['pending']={'from':previous,'to':str(release)}
    if legacy:record['pending']['legacy_from']=str(pointer)
    write_record(prefix/MARKER,record)
    temporary=pointer.with_name('.venv-new-'+secrets.token_hex(6));temporary.symlink_to(release)
    try:
        if legacy:os.rename(pointer,previous)
        os.replace(temporary,pointer)
        record['previous']=previous;record['current']=str(release);record.pop('pending')
        if legacy:record.pop('legacy');record['releases'].remove(str(pointer))
        record['artifact']=candidate['artifact'];write_record(prefix/MARKER,record)
    except BaseException:
        # write_record may replace the marker before directory fsync fails.
        # Preserve an already consistent NEW pointer/inventory pair.
        observed=inventory(prefix)
        if observed.get('current')==str(release) and not observed.get('pending'):
            return observed
        # Compensate when possible. The durable intent still covers a crash or
        # failed compensation, so the next installer can reconcile the pointer.
        restore=pointer.with_name('.venv-restore-'+secrets.token_hex(6))
        try:
            if current is None:pointer.unlink(missing_ok=True)
            elif legacy and pointer.is_dir() and not pointer.is_symlink():pass
            else:restore.symlink_to(previous);os.replace(restore,pointer)
        finally:restore.unlink(missing_ok=True)
        raise
    finally:temporary.unlink(missing_ok=True)
    return record


def rollback(prefix,expected):
    prefix=Path(prefix)
    with InstallationLock(prefix):
        record=recover(prefix);pointer=prefix/'venv'
        if record['current']!=str(expected) or not pointer.is_symlink() or os.readlink(pointer)!=str(expected):raise ValueError('Installation changed; automatic rollback refused.')
        old=record.get('previous')
        if not old:raise ValueError('No previous validated installation.')
        old_path=Path(old)
        if old_path.parent!=prefix/'releases' or old_path.is_symlink() or not (old_path/'.dot-herdr-runtime').is_file():raise ValueError('Previous runtime ownership missing.')
        return _activate({'prefix':str(prefix),'release':old,'command':record['command'],'target':record['target'],'old_target':str(expected),'artifact':json.loads((old_path/'.dot-herdr-runtime').read_text())['artifact']})


def install(source,prefix,bin_dir,setup=False,*,sha256=None):
    existing=Path(prefix).expanduser().absolute()
    pending=False
    if (existing/MARKER).is_file():
        with InstallationLock(existing):current=recover(existing)
        if current['current']:
            config_root=Path(os.environ.get('XDG_CONFIG_HOME',''))
            if not config_root.is_absolute():config_root=Path.home()/'.config'
            directory=config_root/'dot-herdr';config=directory/'config.json'
            no_symlink_ancestors(config)
            drafts=list(directory.glob('config.json.*')) if directory.is_dir() else []
            if str(directory) not in current.get('data_dirs',[]) or not directory.is_dir() or directory.stat().st_mode&0o077 or config.exists() or not drafts or any(p.is_symlink() or not p.is_file() or p.resolve().is_relative_to(Path(text)) for text in current['releases'] for p in drafts) or any(p.name in ('config.json.service.json','config.json.service.pending.json') for p in drafts):
                raise ValueError('Existing validated installation retained; use dot-herdr update with the selected artifact.')
            pending=True
    candidate=stage(source,prefix,bin_dir,sha256=sha256);activate(candidate)
    command=candidate['command']
    print('Installation and offline validation passed. Command: '+command,flush=True)
    if not any(Path(part or '.').expanduser().absolute()==Path(bin_dir).expanduser().absolute() for part in os.environ.get('PATH','').split(os.pathsep)):
        print('Command directory is not on PATH. Use the absolute command above, or add '+str(Path(bin_dir).expanduser().absolute())+' to PATH.',flush=True)
    if pending:print('Setup is still pending. Next: '+command+' setup in a normal terminal.',flush=True)
    elif setup:subprocess.run([command,'setup'],check=True)
    else:print('Next: '+command+' setup')
    return candidate


def uninstall(prefix,*,purge_paths=(),confirm_purge=False):
    """Remove owned runtime only; callers stop owned services before this operation."""
    prefix=Path(prefix).expanduser().absolute()
    with InstallationLock(prefix):result=_uninstall(prefix,purge_paths=purge_paths,confirm_purge=confirm_purge)
    (prefix/'.install.lock').unlink(missing_ok=True)
    try:prefix.rmdir()
    except OSError:pass
    return result


def _uninstall(prefix,*,purge_paths=(),confirm_purge=False):
    record=recover(prefix)
    if purge_paths and not confirm_purge:raise ValueError('Explicit purge confirmation required.')
    purge=[Path(p).expanduser().absolute() for p in purge_paths]
    for path in purge:
        no_symlink_ancestors(path)
        if str(path) not in record.get('data_dirs',[]):raise ValueError('Purge destination is not associated with this installation.')
        if path.is_symlink() or path in (prefix,Path.home(),Path('/')) or prefix in path.parents or path in prefix.parents:
            raise ValueError('Unsafe purge destination.')
        if not path.is_dir() or path.stat().st_mode&0o077 or path.name!='dot-herdr':raise ValueError('Only the dedicated private connector data directory can be purged.')
        if any(p.is_symlink() for p in path.rglob('*')):raise ValueError('Purge refuses symlinks.')
    # Validate the complete inventory before unlinking the command or pointer.
    for text in record['releases']:
        release=Path(text);no_symlink_ancestors(release)
        if record.get('legacy') and release==prefix/'venv' and release.is_dir():continue
        marker=release/'.dot-herdr-runtime'
        if release.parent!=prefix/'releases' or not marker.is_file() or marker.is_symlink():raise ValueError('Runtime inventory ownership mismatch.')
        runtime=json.loads(marker.read_text())
        if runtime.get('owner')!=OWNER or runtime.get('release')!=text:raise ValueError('Runtime inventory ownership mismatch.')
    command=Path(record['command']);target=record['target'];pointer=prefix/'venv'
    no_symlink_ancestors(command.parent)
    preserved=[]
    if command.is_symlink() and os.readlink(command)==target:command.unlink()
    elif command.exists() or command.is_symlink():preserved.append(str(command))
    if pointer.is_symlink() and os.readlink(pointer)==record['current']:pointer.unlink()
    elif pointer.exists() or pointer.is_symlink():preserved.append(str(pointer))
    for text in record['releases']:
        release=Path(text);marker=release/'.dot-herdr-runtime'
        no_symlink_ancestors(release)
        if record.get('legacy') and release==prefix/'venv' and release.is_dir():
            shutil.rmtree(release);continue
        if release.parent!=prefix/'releases' or release.is_symlink() or not marker.is_file() or marker.is_symlink():raise ValueError('Runtime inventory ownership mismatch.')
        runtime=json.loads(marker.read_text())
        if runtime.get('owner')!=OWNER or runtime.get('release')!=text:raise ValueError('Runtime inventory ownership mismatch.')
        shutil.rmtree(release)
    for path in purge:shutil.rmtree(path)
    (prefix/MARKER).unlink()
    for path in (prefix/'releases',):
        try:path.rmdir()
        except OSError:preserved.append(str(path))
    return {'status':'uninstalled','preserved':preserved,'purged':[str(p) for p in purge],
            'remote_grants':'retained_use_account_owner_revocation_flow'}
