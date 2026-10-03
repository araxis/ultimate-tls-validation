"""Run one prepared image on a private TAP; never flash or contact hardware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from run_probe import Peers


def probe(args):
    directory = args.evidence.resolve()
    build = json.loads((directory / 'build-result.json').read_text())
    if not build['prepared'] or abs(time.time() - build['fixture_utc_seconds']) > 3600:
        raise ValueError('Use a successfully prepared fixture less than one hour old')
    for name, expected in build['artifacts'].items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Prepared artifact changed: ' + name)
    if (directory / 'result.json').exists():
        raise ValueError('Evidence already contains a run; prepare a new fixture')
    peers = Peers(directory)
    command = [str(args.qemu.resolve()), '-machine', 'esp32s3', '-display', 'none',
               '-serial', 'stdio', '-monitor', 'none',
               '-drive', f'file={directory / "flash.bin"},if=mtd,format=raw', '-snapshot',
               '-nic', 'tap,model=open_eth,ifname=ult-tls0,script=no,downscript=no']
    process = None
    output = bytearray()
    failure = None
    completed = False
    start = time.monotonic()
    try:
        peers.listen(socket.SOCK_STREAM, 8443, peers.tls, 'trusted')
        # Keep input open: EOF disconnects QEMU's stdio character backend.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        # Read bytes instead of blocking readline, retaining partial panic output.
        while time.monotonic() - start < 60:
            ready, _, _ = select.select([process.stdout], [], [], 0.25)
            if ready:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                output.extend(chunk)
                if b'main_task: Returned from app_main()' in output:
                    completed = True
                    break
            if process.poll() is not None:
                break
        if not completed:
            failure = 'Guest did not finish within the bounded run'
    except Exception as error:
        failure = repr(error)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process is not None:
            output.extend(process.stdout.read())
            process.stdout.close()
            process.stdin.close()
        try:
            peers.close()
        except Exception as error:
            failure = repr(error)
    text = output.decode(errors='replace')
    (directory / 'guest.log').write_text(text)
    (directory / 'peer-events.json').write_text(json.dumps(peers.events, indent=2) + '\n')
    summaries = re.findall(r'^SUMMARY checks=(\d+) failures=(\d+) ticks=(\d+) run=(\S+)\r?$', text, re.M)
    requests = [e for e in peers.events if e['kind'] == 'request']
    peer_ok = (len(requests) == 1 and requests[0]['exact'] and requests[0]['protocol'] == 'TLSv1.2'
               and requests[0]['cipher'] == 'ECDHE-RSA-AES128-GCM-SHA256'
               and [e['name'] for e in peers.events if e['kind'] == 'sni'] == ['192.0.2.1']
               and not any(e['kind'] in ('fixture-error', 'tls-alert') for e in peers.events))
    passed = (failure is None and completed and len(summaries) == 1 and summaries[0][:2] == ('10', '0')
              and int(summaries[0][2]) > 0 and summaries[0][3] == directory.name
              and len(re.findall(r'^PASS ', text, re.M)) == 10
              and not re.search(r'^FAIL|Guru Meditation|assert failed|abort\(\) was called', text, re.M) and peer_ok)
    report = {'passed': passed, 'guest_completed': completed, 'failure': failure,
              'peer_accounting_passed': peer_ok, 'checks': int(summaries[0][0]) if len(summaries) == 1 else None,
              'elapsed_seconds': time.monotonic() - start, 'command': command,
              'qemu_sha256': hashlib.sha256(args.qemu.read_bytes()).hexdigest(),
              'image_sha256': hashlib.sha256((directory / 'flash.bin').read_bytes()).hexdigest(),
              'scope': 'One IP-literal RSA exchange under ESP32-S3 emulation; no DNS, fault matrix or hardware qualification'}
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(text)
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        if os.geteuid() != args.uid or args.uid <= 0:
            parser.error('Child must run as the selected normal user')
        return probe(args)
    if os.geteuid() != 0 or args.uid <= 0:
        parser.error('Run TAP setup as root with a non-root --uid')
    user = pwd.getpwuid(args.uid).pw_name
    subprocess.run([sys.executable, str(ROOT / 'tools/tap.py'), 'create', '--uid', str(args.uid)], check=True)
    try:
        process = subprocess.run(['runuser', '-u', user, '--', sys.executable, str(Path(__file__).resolve()),
                                  '--child', '--uid', str(args.uid), '--evidence', str(args.evidence.resolve()),
                                  '--qemu', str(args.qemu.resolve())], timeout=85)
        return process.returncode
    finally:
        subprocess.run([sys.executable, str(ROOT / 'tools/tap.py'), 'remove'], check=True)


if __name__ == '__main__':
    raise SystemExit(main())
