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
suite.add_argument('--sessions', action='store_true')
suite.add_argument('--security', action='store_true')
suite.add_argument('--allocations', action='store_true')
suite.add_argument('--handshake-allocations', action='store_true')
suite.add_argument('--records', action='store_true')
suite.add_argument('--boundaries', action='store_true')
suite.add_argument('--throughput', action='store_true')
suite.add_argument('--memory', action='store_true')
suite.add_argument('--exhaustion', action='store_true')
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
    if args.sessions:
        command += ['--sessions']
    if args.security:
        command += ['--security']
    if args.allocations:
        command += ['--allocations']
    if args.handshake_allocations:
        command += ['--handshake-allocations']
    if args.records:
        command += ['--records']
    if args.boundaries:
        command += ['--boundaries']
    if args.throughput:
        command += ['--throughput']
    if args.memory:
        command += ['--memory']
    if args.exhaustion:
        command += ['--exhaustion']
    result = subprocess.run(command, timeout=240 if args.memory else 150)
finally:
    subprocess.run([sys.executable, str(root / 'tools/tap.py'), 'remove'], check=True)
raise SystemExit(result.returncode)
