#!/usr/bin/env python3
"""Opt-in disposable artifact install/service/update/default-uninstall acceptance.

Uses synthetic source/account and a private temporary directory. Installs one owned
user service, then removes it. Requires an available logged-in user service manager.
"""
import argparse
import importlib.util
import json
import os
import platform
import socket
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


def exercise(root, artifact):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from dot_herdr.access import service_adapter
    from dot_herdr.connections import encoded, write_file
    from dot_herdr.core import Store
    from dot_herdr.installation import inventory
    from dot_herdr.maintenance import update, uninstall
    from dot_herdr.service import install, manage
    prefix=root/'installation';bin_dir=root/'commands';config=root/'fixture.json'
    state=root/'state';state.mkdir(mode=0o700)
    key=root/'public.pem'
    write_file(key,rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    cfg={'store':str(state/'connector.sqlite'),'socket':str(root/'absent-source.sock'),
         'issuer':'https://fixture-issuer.example.test','resource':'https://fixture-resource.example.test/mcp',
         'public_key':str(key),'subjects':[],'session_users':['synthetic-release-account']}
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));cfg['local_port']=probe.getsockname()[1]
    write_file(config,encoded(cfg));original=config.read_bytes()
    store=Store(Path(cfg['store']));store.begin_action('synthetic-principal','stable-action',{'method':'fixture'});store.close()
    unrelated=root/'unrelated';write_file(unrelated,b'preserve unrelated file\n')
    before=inventory(prefix)['current'];installed=False
    checks={'artifact_install':'passed'}
    try:
        receipt=install(config,executable=prefix/'venv/bin/dot-herdr',login_start=True);installed=True
        manage(config,'start');adapter=service_adapter(config);first=adapter.verify(before)
        checks['stable_service_start']='passed'
        changed=update(str(artifact),config,prefix=prefix,bin_dir=bin_dir)
        after=inventory(prefix)['current'];second=adapter.verify(after)
        assert before!=after and first['pid']!=second['pid']
        assert config.read_bytes()==original
        db=sqlite3.connect('file:'+cfg['store']+'?mode=ro',uri=True)
        try:
            rows=db.execute('SELECT request_id,result FROM actions').fetchall()
            assert len(rows)==1 and rows[0][0]=='stable-action' and json.loads(rows[0][1])['outcome']=='unknown'
        finally:db.close()
        checks.update(artifact_update='passed',config_and_dedupe_preserved='passed',new_release_runtime_verified='passed')
        result=uninstall(config,prefix=prefix);installed=False
        assert not Path(receipt['path']).exists() and not (bin_dir/'dot-herdr').exists()
        assert config.read_bytes()==original and Path(cfg['store']).exists()
        assert unrelated.read_bytes()==b'preserve unrelated file\n'
        assert Path(changed['backup']).exists()
        checks.update(default_uninstall='passed',history_backups_and_unrelated_preserved='passed')
        return {'classification':'actual_artifact_lifecycle_synthetic_source_and_account','os':platform.system(),
                'os_version':platform.release(),'python':sys.version.split()[0],'checks':checks,'cleanup':result.get('status','owned_runtime_removed')}
    finally:
        if installed:manage(config,'remove')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',required=True,type=Path)
    parser.add_argument('--installer',type=Path,help='Install with the distributable zipapp before exercising update and removal')
    parser.add_argument('--exercise-root',type=Path,help=argparse.SUPPRESS)
    args=parser.parse_args();artifact=args.artifact.resolve()
    if args.exercise_root:
        print(json.dumps(exercise(args.exercise_root,artifact),indent=2));return
    module=Path(__file__).resolve().parents[1]/'src/dot_herdr/installation.py'
    if module.is_file():
        spec=importlib.util.spec_from_file_location('release_installer',module)
        installation=importlib.util.module_from_spec(spec);spec.loader.exec_module(installation)
    else:
        from dot_herdr import installation
    with tempfile.TemporaryDirectory(prefix='herdr release validation ') as directory:
        root=Path(directory).resolve();root.chmod(0o700)
        with (root/'install.log').open('w') as log:
            # Pip/installer chatter remains in the disposable private log.
            import contextlib
            with contextlib.redirect_stdout(log):
                old_out=os.dup(1);old_err=os.dup(2)
                try:
                    os.dup2(log.fileno(),1);os.dup2(log.fileno(),2)
                    if args.installer:
                        subprocess.run([sys.executable,str(args.installer.resolve()),'--source',str(artifact),'--prefix',str(root/'installation'),'--bin-dir',str(root/'commands'),'--no-setup'],check=True)
                    else:installation.install(str(artifact),root/'installation',root/'commands',setup=False)
                finally:os.dup2(old_out,1);os.dup2(old_err,2);os.close(old_out);os.close(old_err)
        python=root/'installation/venv/bin/python'
        result=subprocess.run([str(python),str(Path(__file__).resolve()),'--artifact',str(artifact),'--exercise-root',str(root)],capture_output=True,text=True,timeout=300)
        if result.returncode:
            sys.stderr.write(result.stderr);raise RuntimeError('Disposable release lifecycle failed: '+result.stdout[-3000:])
        # Maintenance/installer writes can precede the final JSON object.
        marker=result.stdout.rfind('\n{')
        raw=result.stdout[marker+1:] if marker>=0 else result.stdout
        receipt=json.loads(raw)
        if args.installer:receipt['checks']['installer_zipapp_install_update_handoff']='passed'
        receipt['disposable_root']=str(root)
    receipt['disposable_root_removed']=not root.exists()
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':main()
