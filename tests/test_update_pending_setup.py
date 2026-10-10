import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from dot_herdr import installation
from dot_herdr.core import Rejected
from dot_herdr.maintenance import uninstall, update
from dot_herdr.setup import doctor
from dot_herdr.status import status
import asyncio


class PendingSetupMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.prefix=self.root/'owned';self.bin=self.root/'bin';self.source=self.root/'fixture.whl'
        with zipfile.ZipFile(self.source,'w') as wheel:wheel.writestr('dot_herdr.data/data/share/dot-herdr/requirements.lock','mcp==2.3.0\n')
        self.config=self.root/'config'/'dot-herdr'/'config.json';self.config.parent.mkdir(parents=True,mode=0o700)
        (self.config.parent/'state').mkdir(mode=0o700)
        self.drafts={name:content for name,content in (
            ('config.json.draft.json',b'{"stage":"provider"}\n'),
            ('config.json.connection.json',b'{"version":1,"stage":"provider","route":"loopback"}\n'),
            ('config.json.pending-auth.json',b'{"status":"pending"}\n'))}
        for name,content in self.drafts.items():
            path=self.config.parent/name;path.write_bytes(content);path.chmod(0o600)

    def build(self,path):
        (path/'bin').mkdir();(path/'bin/python').write_text('fixture')
        entry=path/'bin/dot-herdr';entry.write_text('fixture');entry.chmod(0o700)

    def execute(self,args,**kwargs):
        output=json.dumps({'demo':'passed'}) if args[-1]=='demo' else json.dumps({'checks':[{'status':'pass'}]})
        return subprocess.CompletedProcess(args,0,stdout=output,stderr='')

    def install(self):
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=self.execute):
            candidate=installation.stage(self.source,self.prefix,self.bin)
        installation.activate(candidate);return candidate

    def test_update_while_setup_pending_preserves_drafts(self):
        initial=self.install();before={name:hashlib.sha256((self.config.parent/name).read_bytes()).hexdigest() for name in self.drafts}
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=self.execute),patch('dot_herdr.access.service_adapter',return_value=None):
            result=update(self.source,self.config,prefix=self.prefix,sha256=hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(result['status'],'updated');self.assertEqual(result['setup'],'pending')
        self.assertFalse(result['service_restarted']);self.assertIsNone(result['backup'])
        self.assertNotEqual(os.readlink(self.prefix/'venv'),initial['release'])
        self.assertFalse(self.config.exists())
        self.assertEqual({name:hashlib.sha256((self.config.parent/name).read_bytes()).hexdigest() for name in self.drafts},before)

    def test_update_rejects_nonregular_configuration(self):
        self.install();target=self.root/'elsewhere';target.write_text('retained');self.config.symlink_to(target)
        with self.assertRaisesRegex(Rejected,'symlink|private_configuration_required'):update(self.source,self.config,prefix=self.prefix)
        self.config.unlink();self.config.mkdir()
        with self.assertRaisesRegex(Rejected,'private_configuration_required'):update(self.source,self.config,prefix=self.prefix)

    def test_pending_update_failure_restores_previous_release(self):
        initial=self.install();before={name:(self.config.parent/name).read_bytes() for name in self.drafts}
        class Service:
            starts=0
            def status(self):return {'owned':True,'active':True}
            def stop(self):pass
            def start(self):
                self.starts+=1
                if self.starts==1:raise ValueError('new runtime failed')
        with patch.object(installation.venv.EnvBuilder,'create',side_effect=self.build),patch.object(installation.subprocess,'run',side_effect=self.execute):
            with self.assertRaisesRegex(Rejected,'previous_executable_restored'):update(self.source,self.config,prefix=self.prefix,service=Service())
        self.assertEqual(os.readlink(self.prefix/'venv'),initial['release'])
        self.assertEqual({name:(self.config.parent/name).read_bytes() for name in self.drafts},before)

    def test_uninstall_and_observations_while_setup_pending(self):
        self.install();before={name:(self.config.parent/name).read_bytes() for name in self.drafts}
        report=asyncio.run(status(self.config));self.assertEqual(report['observations']['configuration']['state'],'missing_or_invalid')
        self.assertFalse(any(check['status']=='blocked' for check in doctor()['checks']))
        result=uninstall(self.config,prefix=self.prefix)
        self.assertEqual(result['status'],'uninstalled');self.assertFalse((self.bin/'dot-herdr').exists())
        self.assertEqual({name:(self.config.parent/name).read_bytes() for name in self.drafts},before)
