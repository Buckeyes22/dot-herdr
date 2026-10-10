#!/usr/bin/env python3
"""Source bootstrap: run from an extracted source archive with src/dot_herdr beside scripts/. This file is not portable on its own."""
import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

# A source installer must work before package dependencies have been installed.
module=Path(__file__).resolve().parents[1]/'src/dot_herdr/installation.py'
if not module.is_file():raise SystemExit('Source bootstrap requires the extracted source archive layout (scripts/ and src/dot_herdr/). Use the installer zipapp for a portable bootstrap.')
spec=importlib.util.spec_from_file_location('dot_herdr_installer',module)
implementation=importlib.util.module_from_spec(spec);spec.loader.exec_module(implementation)
install=implementation.install
MARKER=implementation.MARKER


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',default=str(Path(__file__).resolve().parents[1]),help='Local checkout/wheel/archive or explicitly selected HTTPS release URL')
    parser.add_argument('--sha256',help='Published SHA-256; required for HTTPS release downloads')
    parser.add_argument('--prefix',type=Path,default=Path.home()/'.local/share/dot-herdr')
    parser.add_argument('--bin-dir',type=Path,default=Path.home()/'.local/bin')
    parser.add_argument('--no-setup',action='store_true')
    args=parser.parse_args()
    try:install(args.source,args.prefix,args.bin_dir,setup=not args.no_setup and sys.stdin.isatty(),sha256=args.sha256)
    except (OSError,ValueError,subprocess.SubprocessError) as error:parser.exit(2,'Installation stopped: '+str(error)+'\n')
    except KeyboardInterrupt:parser.exit(2,'Installation interrupted; the active installation was retained. Rerun to stage again.\n')

if __name__=='__main__':main()
