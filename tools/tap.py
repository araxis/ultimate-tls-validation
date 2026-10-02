"""Create/remove only this lab's private TAP interface (requires root)."""
import argparse
import json
import os
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('action', choices=['create', 'remove'])
parser.add_argument('--uid', type=int, default=1000)
args = parser.parse_args()
name = 'ult-tls0'
marker = 'ultimate-tls-lab-private-interface'
if os.geteuid() != 0:
    raise SystemExit('Run this interface setup command as root; run the probe as your normal user.')
interfaces = json.loads(subprocess.check_output(['ip', '-json', '-details', 'link', 'show']))
existing = next((item for item in interfaces if item['ifname'] == name), None)
if args.action == 'create':
    if existing:
        raise SystemExit('Interface already exists; refusing to replace it.')
    routes = subprocess.check_output(['ip', 'route', 'show', 'match', '192.0.2.0/30'], text=True)
    if any(line and not line.startswith('default ') for line in routes.splitlines()):
        raise SystemExit('The private test subnet already has a route; choose another isolated environment.')
    subprocess.run(['ip', 'tuntap', 'add', 'dev', name, 'mode', 'tap', 'user', str(args.uid)], check=True)
    try:
        subprocess.run(['ip', 'link', 'set', 'dev', name, 'alias', marker], check=True)
        subprocess.run(['ip', 'address', 'add', '192.0.2.1/30', 'dev', name], check=True)
        subprocess.run(['ip', 'link', 'set', 'dev', name, 'up'], check=True)
    except BaseException:
        subprocess.run(['ip', 'link', 'delete', 'dev', name], check=True)
        raise
else:
    if not existing or existing.get('ifalias') != marker:
        raise SystemExit('Lab interface marker not found; refusing removal.')
    subprocess.run(['ip', 'link', 'delete', 'dev', name], check=True)
print(f'{args.action}: {name}')
