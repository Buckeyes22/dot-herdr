#!/usr/bin/env python3
"""Opt-in actual user-service acceptance with disposable synthetic source/account.

Run from an installed candidate environment. Does not contact Herdr or an OAuth
provider; temporarily creates one connector-owned user service and removes it.
"""
import hashlib
import json
import os
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from dot_herdr.connections import encoded,write_file
from dot_herdr.core import Store,Rejected
from dot_herdr.runtime import process_identity
from dot_herdr.service import install,manage
from dot_herdr.status import runtime_observation
from dot_herdr.tunnel import profile_paths


def await_running(config,old_pid=None):
    until=time.monotonic()+15
    while time.monotonic()<until:
        state=runtime_observation(config)
        if state['state']=='running' and state.get('pid')!=old_pid:return state
        time.sleep(.1)
    raise RuntimeError('Owned service did not become ready.')


def await_child(path,old_pid=None):
    until=time.monotonic()+5
    while time.monotonic()<until:
        try:pid=int(path.read_text())
        except (OSError,ValueError):pid=None
        if pid is not None and pid!=old_pid and process_identity(pid) is not None:return pid
        time.sleep(.1)
    raise RuntimeError('Owned tunnel child did not become ready.')


def main():
    import platform
    result={'classification':'actual_os_service_synthetic_source_and_account','os':platform.system(),'os_version':platform.release(),'python':sys.version.split()[0],'checks':{}}
    with tempfile.TemporaryDirectory(prefix='herdr service validation ') as directory:
        root=Path(directory).resolve();root.chmod(0o700);state=root/'state';state.mkdir(mode=0o700)
        config=root/'fixture.json';public=root/'public.pem'
        public.write_bytes(rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        cfg={'store':str(state/'store.sqlite'),'socket':str(root/'absent-disposable-source.sock'),'issuer':'https://fixture-issuer.example.test','resource':'https://fixture-resource.example.test/mcp','public_key':str(public),'subjects':[],'session_users':['synthetic-service-account']}
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));cfg['local_port']=probe.getsockname()[1]
        write_file(config,encoded(cfg))
        tunnel_root,settings,profile=profile_paths(config);tunnel_root.mkdir(mode=0o700);profile.parent.mkdir(mode=0o700)
        binary=tunnel_root/'fixture-child'
        binary.write_text('#!'+sys.executable+'\nimport os,sys,time\nfrom pathlib import Path\np=Path(sys.argv[sys.argv.index("--health.url-file")+1]).with_name("fixture-child.pid")\np.write_text(str(os.getpid()))\nwhile True:time.sleep(1)\n');binary.chmod(0o700)
        profile.write_text('fixture: true\n');profile.chmod(0o600)
        write_file(settings,encoded({'tunnel_id':'tunnel_disposable_service_fixture','binary':str(binary),'endpoint':f"http://127.0.0.1:{cfg['local_port']}/mcp",'release':'synthetic_fixture','profile_sha256':hashlib.sha256(profile.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        credential=root/'fixture-runtime-key';write_file(credential,b'synthetic-key-not-an-account-credential\n')
        executable=Path(sys.executable).parent/'dot-herdr'
        installed=False
        try:
            receipt=install(config,executable=executable,tunnel=True,credential_file=credential,login_start=True);installed=True
            result['checks']['install_login_start']='passed'
            manage(config,'start');live=await_running(config);result['checks']['start_workers']='passed'
            # Service process must be distinct from this setup/test process.
            assert live['pid']!=os.getpid();result['checks']['manager_owns_runtime']='passed'
            with urlopen(f"http://127.0.0.1:{cfg['local_port']}/.well-known/oauth-protected-resource/mcp",timeout=3) as response:
                assert json.loads(response.read(65536))['resource']==cfg['resource']
            result['checks']['protected_resource_metadata']='passed'
            try:Store(Path(cfg['store']))
            except Rejected as error:assert str(error)=='store_already_owned'
            else:raise AssertionError('Foreground contention was accepted.')
            result['checks']['foreground_contention']='passed'
            child_pid=await_child(tunnel_root/'fixture-child.pid')
            old_pid=live['pid'];manage(config,'restart');await_running(config,old_pid);result['checks']['restart']='passed'
            assert process_identity(child_pid) is None;result['checks']['restart_reaps_child']='passed'
            new_child=await_child(tunnel_root/'fixture-child.pid',child_pid)
            manage(config,'stop')
            assert process_identity(new_child) is None
            store=Store(Path(cfg['store']));store.close();result['checks']['stop_child_and_store_release']='passed'
            manage(config,'remove');installed=False
            assert not Path(receipt['path']).exists();result['checks']['remove']='passed'
        finally:
            if installed:manage(config,'remove')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
