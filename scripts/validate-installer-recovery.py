#!/usr/bin/env python3
"""Disposable real zipapp interruption, resume, ownership and stage-failure checks."""
import argparse
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(*command,env=None):
    return subprocess.run(command,capture_output=True,text=True,env=env,timeout=300)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',required=True,type=Path)
    parser.add_argument('--installer',required=True,type=Path)
    args=parser.parse_args();artifact=args.artifact.resolve();installer=args.installer.resolve()
    checks={}
    with tempfile.TemporaryDirectory(prefix='herdr installer recovery ') as directory:
        root=Path(directory).resolve();root.chmod(0o700);env=dict(os.environ,TMPDIR=str(root))
        foreign=root/'foreign';foreign.mkdir(mode=0o700);(foreign/'keep').write_text('untouched')
        refused=run(sys.executable,str(installer),'--source',str(artifact),'--prefix',str(foreign),'--bin-dir',str(root/'foreign-bin'),env=env)
        assert refused.returncode!=0 and 'already used' in refused.stderr and (foreign/'keep').read_text()=='untouched'
        checks['foreign_unowned_target_refused']='passed'
        prefix=root/'interrupted installation';bin_dir=root/'commands with spaces';log=root/'interrupt.log'
        command=[sys.executable,str(installer),'--source',str(artifact),'--prefix',str(prefix),'--bin-dir',str(bin_dir)]
        with log.open('w') as output:
            process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=output,stderr=output,env=env,start_new_session=True)
            deadline=time.monotonic()+30
            while time.monotonic()<deadline and process.poll() is None:
                if list((prefix/'releases').glob('release-*')):break
                time.sleep(0.02)
            assert process.poll() is None and list((prefix/'releases').glob('release-*')), 'staging did not become interruptible'
            os.killpg(process.pid,signal.SIGINT);process.wait(timeout=30)
        assert process.returncode!=0 and not (prefix/'venv').exists()
        assert not list((prefix/'releases').glob('release-*')), 'partial staging was not cleaned'
        checks['interrupted_stage_cleaned']='passed'
        resumed=run(*command,env=env)
        assert resumed.returncode==0, resumed.stderr[-2000:]
        assert 'Next: '+str(bin_dir/'dot-herdr')+' setup' in resumed.stdout
        assert 'Command directory is not on PATH' in resumed.stdout
        pointer=prefix/'venv';before=os.readlink(pointer)
        checks['resume_zipapp_install']='passed';checks['noninteractive_setup_skipped_and_path_hint']='passed'
        bad=root/'broken.whl';bad.write_bytes(b'not a wheel')
        failed=run(str(pointer/'bin/python'),'-c','import sys;from dot_herdr.installation import stage;stage(sys.argv[1],sys.argv[2],sys.argv[3])',str(bad),str(prefix),str(bin_dir),env=env)
        assert failed.returncode!=0 and os.readlink(pointer)==before
        demo=run(str(bin_dir/'dot-herdr'),'demo',env=env)
        assert demo.returncode==0 and json.loads(demo.stdout)['demo']=='passed',demo.stderr[-2000:]
        assert not list((prefix/'releases').glob('release-*'))==[]
        checks['previous_release_active_after_failed_stage']='passed'
        receipt={'classification':'actual_zipapp_recovery_synthetic_state','os':platform.system(),'python':sys.version.split()[0],
                 'checks':checks,'disposable_root':str(root)}
    receipt['disposable_root_removed']=not root.exists()
    print(json.dumps(receipt,indent=2))


if __name__=='__main__':main()
