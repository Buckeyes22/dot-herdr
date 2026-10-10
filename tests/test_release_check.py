"""Synthetic archive checks for the local release evidence script."""
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/release-check.py'
spec = importlib.util.spec_from_file_location('release_check', SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.dist = self.root / 'dist'
        self.out = self.root / 'out'
        (self.repo / 'src/dot_herdr').mkdir(parents=True)
        self.dist.mkdir()
        (self.repo / 'src/dot_herdr/a.py').write_bytes(b'value = 1\n')
        (self.repo / 'requirements.lock').write_text('example==1.0 --hash=sha256:' + 'a' * 64 + '\n')
        for args in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Test', '-c',
                      'user.email=test@example.test', 'commit', '-qm', 'test']):
            subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True)

    def artifacts(self, extra=None, wheel_source=b'value = 1\n'):
        extra = extra or {}
        common = {'LICENSE': b'MIT\n', 'THIRD-PARTY-NOTICES.md': b'Notices\n'}
        wheel = self.dist / 'example-1.0-py3-none-any.whl'
        with zipfile.ZipFile(wheel, 'w') as archive:
            for name, value in {**common, 'dot_herdr/a.py': wheel_source,
                                'example-1.0.dist-info/METADATA': b'Name: example\nVersion: 1.0\nLicense-Expression: MIT\n\n',
                                **extra}.items():
                archive.writestr(name, value)
        sdist = self.dist / 'example-1.0.tar.gz'
        with tarfile.open(sdist, 'w:gz') as archive:
            for name, value in {**common, 'src/dot_herdr/a.py': b'value = 1\n', **extra}.items():
                info = tarfile.TarInfo('example-1.0/' + name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        with zipfile.ZipFile(self.dist / 'example-1.0-installer.pyz', 'w') as archive:
            archive.writestr('__main__.py', b'print("hello")\n')

    def run_check(self):
        with mock.patch.object(release, 'metadata_inventory', return_value={
                'project': {'license': 'MIT'}, 'locked': [{'name': 'example', 'version': '1.0', 'hashes': ['a' * 64]}],
                'issues': []}):
            return release.run(self.dist, self.out, self.root / 'venv', self.repo)

    def test_clean_artifacts_pass_and_write_verified_receipt(self):
        self.artifacts()
        result = self.run_check()
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['checksums_verified'])
        self.assertEqual(result['equivalence']['mismatches'], [])
        self.assertEqual(len((self.out / 'SHA256SUMS').read_text().splitlines()), 3)

    def test_each_sanitization_rule_redacts_secret(self):
        samples = {
            'private-key-pem': '-----BEGIN ' + 'PRIVATE KEY-----',
            'jwt': 'eyJabcdefgh.' + 'eyJijklmnop.abcdefghij',
            'bearer-token': 'Bearer ' + 'a' * 24,
            'password-assignment': 'PROBE_' + 'PASSWORD' + '=shouldneverprint',
            'aws-key': 'AKIA' + 'A' * 16,
            'github-key': 'ghp_' + 'a' * 30,
            'openai-key': 'sk-' + 'a' * 30,
            'home-path': '/' + 'home/somebody/private',
            'private-host': 'host.' + 'lan',
            'private-ip': '192.' + '168.1.5',
            'maintainer-email': 'chris@' + 'lateapexllc.com',
        }
        for rule, value in samples.items():
            with self.subTest(rule=rule):
                hit = release.scan([Path('sample.whl')], {'sample.whl': {'leak.txt': value.encode()}})
                self.assertIn(rule, {item['rule'] for item in hit})
                self.assertNotIn(value, json.dumps(hit))
        excluded = release.scan([Path('sample.whl')], {'sample.whl': {'private/record.txt': b'clean'}})
        self.assertEqual(excluded[0]['rule'], 'excluded-path')
        allowed = release.scan([Path('sample.whl')], {'sample.whl': {
            'SECURITY.md': b'chris@' + b'lateapexllc.com', 'pyproject.toml': b'chris@' + b'lateapexllc.com'}})
        self.assertFalse(allowed)

    def test_private_terms_come_only_from_the_local_word_list(self):
        terms = self.root / 'terms.txt'
        terms.write_text('# local words\nworkstation-one\nExample Corp\n')
        rule = release.private_terms_rule(terms)
        files = {'sample.whl': {'a.md': b'see workstation-one\n', 'b.md': b'example corp docs\n', 'c.md': b'workstation-onex\n'}}
        hits = {(hit['path'], hit['rule']) for hit in release.scan([Path('sample.whl')], files, rule)}
        self.assertEqual({h for h in hits if h[1] == 'private-term'}, {('a.md', 'private-term'), ('b.md', 'private-term')})
        self.assertFalse([h for h in release.scan([Path('sample.whl')], files) if h['rule'] == 'private-term'])
        self.assertIsNone(release.private_terms_rule(self.root / 'missing.txt'))

    def test_short_demo_bearers_are_allowed_but_realistic_fake_and_jwt_are_caught(self):
        lines = {
            'demo.py': b'Authorization: Bearer synthetic-demo-token\n',
            'test.py': b'Authorization: Bearer observer\n',
            'fake.py': b'Authorization: Bearer ' + b'x' * 24 + b'\n',
            'jwt.py': b'Authorization: Bearer ' + b'eyJabcdefgh.' + b'eyJijklmnop.' + b'abcdefghij\n',
        }
        hits = release.scan([Path('sample.whl')], {'sample.whl': lines})
        by_path = {(hit['path'], hit['rule']) for hit in hits}
        self.assertNotIn(('demo.py', 'bearer-token'), by_path)
        self.assertNotIn(('test.py', 'bearer-token'), by_path)
        self.assertIn(('fake.py', 'bearer-token'), by_path)
        self.assertIn(('jwt.py', 'jwt'), by_path)

    def test_inline_allow_marker_is_same_line_and_rule_specific(self):
        files = {'sample.whl': {
            'tests/rejection.py': (
                b'http://' + b'192.168.' + b'1.1/mcp  # release-check: allow private-ip (rejection test vector)\n'
                b'192.168.' + b'1.2 # release-check: allow private-host (wrong rule)\n'
                b'192.168.' + b'1.3\n'
                b'192.168.' + b'1.4\n# release-check: allow private-ip\n'
            )}}
        hits = release.scan([Path('sample.whl')], files)
        private_ips = {(hit['line'], hit['rule']) for hit in hits if hit['rule'] == 'private-ip'}
        self.assertEqual(private_ips, {(2, 'private-ip'), (3, 'private-ip'), (4, 'private-ip')})

    def test_maintainer_email_allowlist_is_limited_to_disclosure_and_package_files(self):
        address = 'chris@' + 'lateapexllc' + '.com'
        files = {'sample.whl': {
            'SECURITY.md': (address + '\n').encode(),
            'CONTRIBUTING.md': (address + '\n').encode(),
            'docs/dependencies.md': (address + '\n').encode(),
            'pyproject.toml': (address + '\n').encode(),
            'dot_herdr-1.dist-info/METADATA': ('Author-email: ' + address + '\n').encode(),
            'src/dot_herdr/module.py': (address + '\n').encode(),
            'tests/test_contact.py': (address + '\n').encode(),
            'docs/nested/readme.md': (address + '\n').encode(),
        }}
        hits = release.scan([Path('sample.whl')], files)
        self.assertEqual({hit['path'] for hit in hits if hit['rule'] == 'maintainer-email'},
                         {'src/dot_herdr/module.py', 'tests/test_contact.py', 'docs/nested/readme.md'})

    def test_wheel_sdist_drift_fails(self):
        self.artifacts(wheel_source=b'value = 2\n')
        result = self.run_check()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['equivalence']['mismatches'], ['a.py'])

    def test_refuses_receipt_overwrite(self):
        self.artifacts()
        self.run_check()
        with self.assertRaises(FileExistsError):
            self.run_check()
