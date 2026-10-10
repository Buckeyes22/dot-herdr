#!/usr/bin/env python3
"""Build a standard-library installer zipapp from the reviewed source implementation."""
import argparse
import re
import tempfile
import zipapp
from pathlib import Path

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir',type=Path,default=root/'dist')
args=parser.parse_args()
version=re.search(r'^version = "([^"]+)"', (root/'pyproject.toml').read_text(),re.M).group(1)
bootstrap=(root/'scripts/install.py').read_text()
bootstrap=bootstrap.replace('Source bootstrap: run from an extracted source archive with src/dot_herdr beside scripts/. This file is not portable on its own.','Portable installer zipapp: select a wheel or source archive with --source.')
start=bootstrap.index('# A source installer')
end=bootstrap.index('install=implementation.install')
bootstrap=bootstrap[:start]+'import installation as implementation\n'+bootstrap[end:]
bootstrap=bootstrap.replace("parser.add_argument('--source',default=str(Path(__file__).resolve().parents[1]),", "parser.add_argument('--source',required=True,")
output=args.output_dir.resolve()/('dot_herdr-'+version+'-installer.pyz')
output.parent.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory() as directory:
    path=Path(directory)
    (path/'__main__.py').write_text(bootstrap)
    (path/'installation.py').write_bytes((root/'src/dot_herdr/installation.py').read_bytes())
    zipapp.create_archive(path,output,interpreter='/usr/bin/env python3',compressed=True)
print(str(output))
