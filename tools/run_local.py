"""Root-only TAP lifecycle; drop privileges before starting fixtures/probe."""
import argparse
import os
from pathlib import Path
import pwd
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--uid', required=True, type=int)
parser.add_argument('--binary', type=Path)
suite = parser.add_mutually_exclusive_group()
suite.add_argument('--faults', action='store_true')
suite.add_argument('--pressure', action='store_true')
suite.add_argument('--connections', action='store_true')
args = parser.parse_args()
if os.geteuid() != 0 or args.uid <= 0:
    raise SystemExit('Run setup as root and specify a non-root test user with --uid.')
root = Path(__file__).resolve().parents[1]
user = pwd.getpwuid(args.uid).pw_name
subprocess.run([sys.executable, str(root / 'tools/tap.py'), 'create', '--uid', str(args.uid)], check=True)
try:
    command = ['runuser', '-u', user, '--', sys.executable, str(root / 'tests/run_probe.py')]
    if args.binary:
        command += ['--binary', str(args.binary.resolve())]
    if args.faults:
        command += ['--faults']
    if args.pressure:
        command += ['--pressure']
    if args.connections:
        command += ['--connections']
    result = subprocess.run(command, timeout=150)
finally:
    subprocess.run([sys.executable, str(root / 'tools/tap.py'), 'remove'], check=True)
raise SystemExit(result.returncode)
