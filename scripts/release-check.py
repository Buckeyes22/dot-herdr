#!/usr/bin/env python3
"""Check local release archives and write a private, dated evidence receipt.

Minimal release exceptions: maintainer contact is permitted in SECURITY.md,
CONTRIBUTING.md, docs/*.md, pyproject.toml, and wheel METADATA only. Rejection
tests may mark one private-IP test vector with ``release-check: allow private-ip``
on that same line; the marker suppresses only the named rule on that line.

Maintainer-specific words (hostnames, account names) never live in this public
script: list them one per line in the untracked ``private/release-check-terms.txt``
or pass ``--private-terms FILE``. Each is matched case-insensitively as a word.
"""
import argparse
import datetime as dt
import email
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_VENV = REPO / '.venv-py313'
DEFAULT_TERMS = REPO / 'private' / 'release-check-terms.txt'
ARTIFACT_SUFFIXES = ('.whl', '.tar.gz', '.pyz')
RULES = {
    'private-key-pem': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----', re.I),
    'jwt': re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'),
    'bearer-token': re.compile(r'\bBearer\s+[A-Za-z0-9._~+/-]{24,}', re.I),
    'password-assignment': re.compile(r'\b(?:PROBE_PASSWORD|[A-Za-z_]*password[A-Za-z_]*)\b\s*(?:=|:)\s*["\']?[^\s"\',;}]{2,}', re.I),
    'aws-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'github-key': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b'),
    'openai-key': re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b'),
    'home-path': re.compile(r'/(?:home|Users)/[^\s"\'<>]+'),
    'private-host': re.compile(r'\b[A-Za-z0-9.-]+\.lan\b', re.I),
    'private-ip': re.compile(r'\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})\b'),
    'maintainer-email': re.compile(r'chris@lateapexllc\.com', re.I),
}
EXCLUDED = {'private', 'private-records', 'history', 'build', 'dist'}


def private_terms_rule(path):
    """Build the optional maintainer-term rule from a local, untracked word list."""
    if path is None or not path.exists():
        return None
    terms = [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith('#')]
    return re.compile(r'\b(?:' + '|'.join(map(re.escape, terms)) + r')\b', re.I) if terms else None


ALLOW_MARKER = re.compile(r'#\s*release-check:\s*allow\s+([a-z0-9-]+)\b', re.I)


def maintainer_email_allowed(path):
    parts = Path(path).parts
    name = parts[-1]
    docs_index = len(parts) - 2
    return (name in {'SECURITY.md', 'CONTRIBUTING.md'} or
            (docs_index >= 0 and parts[docs_index] == 'docs' and name.endswith('.md')) or
            path == 'pyproject.toml' or path.endswith('.dist-info/METADATA'))


def archive_files(path):
    if path.name.endswith('.tar.gz'):
        with tarfile.open(path, 'r:gz') as archive:
            return {item.name: archive.extractfile(item).read() for item in archive if item.isfile()}
    with zipfile.ZipFile(path) as archive:
        return {item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()}


def logical_path(name, artifact):
    parts = Path(name).parts
    return '/'.join(parts[1:]) if artifact.name.endswith('.tar.gz') else name


def scan(artifacts, files, terms=None):
    rules = {**RULES, 'private-term': terms} if terms else RULES
    hits = []
    for artifact in artifacts:
        for raw_path, data in files[artifact.name].items():
            path = logical_path(raw_path, artifact)
            parts = Path(path).parts
            if any(part in EXCLUDED or part.startswith('.venv') for part in parts):
                hits.append(dict(artifact=artifact.name, path=path, line=0,
                                 rule='excluded-path', excerpt='[redacted]'))
            for number, line in enumerate(data.decode('utf-8', 'replace').splitlines(), 1):
                for rule, pattern in rules.items():
                    if rule == 'maintainer-email' and maintainer_email_allowed(path):
                        continue
                    allowed_rules = {m.group(1).lower() for m in ALLOW_MARKER.finditer(line)}
                    if rule not in allowed_rules and pattern.search(line):
                        hits.append(dict(artifact=artifact.name, path=path, line=number,
                                         rule=rule, excerpt='[redacted]'))
    return hits


def metadata_inventory(files, wheel, lock, venv):
    entries = files[wheel.name]
    names = [n for n in entries if n.endswith('.dist-info/METADATA')]
    if len(names) != 1:
        raise ValueError('Wheel must contain one METADATA file')
    meta = email.message_from_bytes(entries[names[0]])
    project = {'name': meta.get('Name'), 'version': meta.get('Version'),
               'license': meta.get('License-Expression') or meta.get('License'),
               'requires_dist': meta.get_all('Requires-Dist', [])}
    pins = []
    for line in lock.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.match(r'^([A-Za-z0-9_.-]+)==([^\s;]+)(.*)$', line)
        if not match:
            raise ValueError('Unpinned lock entry')
        pins.append({'name': match[1], 'version': match[2],
                     'hashes': re.findall(r'--hash=sha256:([0-9a-fA-F]{64})', match[3])})
    python = venv / 'bin/python'
    code = ('import importlib.metadata as m,json,sys; '
            'out=[]; '
            '[(lambda d:out.append({"name":d.metadata.get("Name"),"version":d.version,'
            '"license":d.metadata.get("License-Expression") or d.metadata.get("License"),'
            '"classifiers":d.metadata.get_all("Classifier",[])}))(m.distribution(n)) '
            'for n in json.loads(sys.stdin.read())]; print(json.dumps(out))')
    result = subprocess.run([str(python), '-c', code], input=json.dumps([p['name'] for p in pins]),
                            text=True, capture_output=True)
    if result.returncode:
        raise ValueError('Cannot read locked dependency metadata from venv: ' + result.stderr[-300:])
    installed = json.loads(result.stdout)
    issues = []
    for pin, package in zip(pins, installed):
        pin.update(installed=package)
        if pin['version'] != package['version']:
            issues.append(f"version mismatch: {pin['name']}")
        license_text = ' '.join([package.get('license') or ''] +
                                [c for c in package['classifiers'] if 'License ::' in c])
        if not license_text.strip() or re.search(r'\b(?:UNKNOWN|NONE)\b', license_text, re.I):
            issues.append(f"unknown license: {pin['name']}")
        if re.search(r'\b(?:A?GPL|LGPL)(?:v?\d|\b)', license_text, re.I):
            issues.append(f"copyleft review: {pin['name']}")
    if not project['license']:
        issues.append('unknown project license')
    return {'project': project, 'locked': pins, 'issues': issues}


def equivalence(files, wheel, sdist, repo):
    def members(artifact, prefix):
        out = {}
        for name, data in files[artifact.name].items():
            path = logical_path(name, artifact)
            if path.startswith(prefix) and not path.endswith('/'):
                out[path[len(prefix):]] = data
        return out
    wheel_src = members(wheel, 'dot_herdr/')
    source_src = members(sdist, 'src/dot_herdr/')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    tracked = subprocess.check_output(['git', 'ls-files', 'src/dot_herdr'], cwd=repo, text=True).splitlines()
    head_src = {p[len('src/dot_herdr/'):]: subprocess.check_output(
        ['git', 'show', 'HEAD:' + p], cwd=repo) for p in tracked if p.startswith('src/dot_herdr/')}
    mismatches = sorted(k for k in set(wheel_src) | set(source_src) | set(head_src)
                        if wheel_src.get(k) is None or source_src.get(k) is None or
                        head_src.get(k) is None or not (wheel_src[k] == source_src[k] == head_src[k]))
    return {'head': head, 'files': len(head_src), 'mismatches': mismatches}


def run(dist, out, venv, repo, terms_file=None):
    date = dt.datetime.now(dt.timezone.utc).date().isoformat()
    receipt = out / f'release-check-{date}.json'
    summary = out / f'release-check-{date}.md'
    if receipt.exists() or summary.exists():
        raise FileExistsError(f'Receipt already exists: {receipt}')
    artifacts = sorted(p for p in dist.iterdir() if p.is_file() and
                       any(p.name.endswith(s) for s in ARTIFACT_SUFFIXES))
    if len(artifacts) != 3 or any(sum(p.name.endswith(s) for p in artifacts) != 1
                                  for s in ARTIFACT_SUFFIXES):
        raise ValueError('Dist must contain exactly one wheel, one sdist, and one installer pyz')
    wheel = next(p for p in artifacts if p.name.endswith('.whl'))
    sdist = next(p for p in artifacts if p.name.endswith('.tar.gz'))
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}
    out.mkdir(parents=True, exist_ok=True)
    sums = out / 'SHA256SUMS'
    if sums.exists():
        raise FileExistsError(f'Checksum file already exists: {sums}')
    sums.write_text(''.join(f'{digest}  {name}\n' for name, digest in hashes.items()))
    verified = all(hashlib.sha256((dist / name).read_bytes()).hexdigest() == digest
                   for name, digest in hashes.items())
    files = {p.name: archive_files(p) for p in artifacts}
    hits = scan(artifacts, files, private_terms_rule(terms_file))
    license_files = {}
    for artifact in (wheel, sdist):
        paths = [logical_path(n, artifact) for n in files[artifact.name]]
        license_files[artifact.name] = {target: any(p == target or p.endswith('/' + target)
                                                     for p in paths)
                                        for target in ('LICENSE', 'THIRD-PARTY-NOTICES.md')}
    inventory = metadata_inventory(files, wheel, repo / 'requirements.lock', venv)
    equivalent = equivalence(files, wheel, sdist, repo)
    failures = ([] if verified else ['checksum verification failed'])
    failures += [f"sanitization: {len(hits)} hit(s)"] if hits else []
    failures += [f'missing {name} in {artifact}' for artifact, checks in license_files.items()
                 for name, present in checks.items() if not present]
    failures += inventory['issues']
    failures += [f"source equivalence: {len(equivalent['mismatches'])} mismatch(es)"] if equivalent['mismatches'] else []
    result = {'date_utc': date, 'status': 'FAIL' if failures else 'PASS', 'artifacts': hashes,
              'checksums_verified': verified, 'sanitization_hits': hits,
              'license_files': license_files, 'inventory': inventory,
              'equivalence': equivalent, 'failures': failures}
    receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    lines = [f'# Release check {date}', '', f"Status: **{result['status']}**", '',
             f'Checksums: {"verified" if verified else "failed"} ({len(hashes)} artifacts)',
             f'Sanitization: {len(hits)} hit(s)',
             f"License/package inventory: {len(inventory['locked'])} locked packages; {len(inventory['issues'])} issue(s)",
             f"LICENSE and notices: {'present' if all(all(v.values()) for v in license_files.values()) else 'missing'}",
             f"Source/wheel/HEAD: {equivalent['files']} files; {len(equivalent['mismatches'])} mismatch(es); HEAD {equivalent['head']}", '']
    lines += [f"- {h['artifact']}:{h['path']}:{h['line']}: {h['rule']} [redacted]" for h in hits]
    lines += [f'- {failure}' for failure in failures if not failure.startswith('sanitization:')]
    summary.write_text('\n'.join(lines) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--venv', type=Path, default=DEFAULT_VENV)
    parser.add_argument('--private-terms', type=Path, default=DEFAULT_TERMS)
    args = parser.parse_args()
    try:
        result = run(args.dist, args.out, args.venv, REPO, args.private_terms)
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f'release-check: {exc}', file=sys.stderr)
        return 1
    print(f"Release check: {result['status']}; {len(result['sanitization_hits'])} sanitization hits; "
          f"{len(result['inventory']['issues'])} inventory issues; "
          f"{len(result['equivalence']['mismatches'])} equivalence mismatches")
    return 1 if result['failures'] else 0


if __name__ == '__main__':
    sys.exit(main())
