"""Account for dated-certificate rejection, abrupt closure and fresh recovery."""
from collections import Counter
import json
import re
import subprocess
from security_peers import make_dated_certificates

CASES = {
    'expired': (5, 8, -9984, 1, 0, 1),
    'future': (5, 8, -9984, 512, 0, 1),
    'handshake-eof': (5, 8, -29312, 4294967295, 0, 1),
    'unclean-eof': (7, 9, 0, 0, 7, 1),
    'peer-reset': (4, 9, -27648, 0, 0, 1),
}
CHECKS = 98


def prepare(directory, utc):
    make_dated_certificates(directory)
    reports = []
    for name, expected in [('expired', 10), ('future', 9)]:
        command = ['openssl', 'verify', '-CAfile', 'trusted-ca.pem', '-no-CApath', '-no-CAstore',
                   '-purpose', 'sslserver', '-verify_ip', '192.0.2.1']
        structural = subprocess.run(command + ['-no_check_time', name + '.pem'], cwd=directory,
                                    capture_output=True, text=True, timeout=30)
        structural.check_returncode()
        dated = subprocess.run(command + ['-attime', str(utc), name + '.pem'], cwd=directory,
                               capture_output=True, text=True, timeout=30)
        if dated.returncode == 0 or f'error {expected} at 0 depth lookup' not in dated.stderr:
            raise ValueError('Unexpected IP certificate date verification: ' + dated.stdout + dated.stderr)
        reports.append({'leaf': name, 'utc': utc, 'address': '192.0.2.1', 'expected_error': expected,
                        'structural': structural.stdout, 'date_result': dated.stderr})
    (directory / 'security-fixtures.json').write_text(json.dumps(reports, indent=2) + '\n')


def account(output, events):
    labels = [label for case in CASES for label in (case, 'recovery-' + case)]
    attempts = re.findall(r'^ATTEMPT ([a-z-]+)\r?$', output, re.M)
    rows = re.findall(r'^SECURITY_RESULT ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) '
                      r'verify=(\d+) received=(\d+) opens=(\d+) elapsed=(\d+)\r?$', output, re.M)
    recoveries = re.findall(r'^RESULT (recovery-[a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) '
                            r'verify=(\d+) sent=(\d+) received=(\d+) opens=(\d+)\r?$', output, re.M)
    cleanup = re.findall(r'^SECURITY_CLEANUP active=(\d+) timewait=(\d+) dns=(\d+) elapsed=(\d+)\r?$', output, re.M)
    complete = (attempts == labels and [r[0] for r in rows] == list(CASES) and
                [r[0] for r in recoveries] == ['recovery-' + n for n in CASES] and
                all(tuple(map(int, r[1:-1])) == CASES[r[0]] and int(r[-1]) <= 3250 for r in rows) and
                all(tuple(map(int, r[1:])) == (0, 9, -30848, 0, 62, 65, 1) for r in recoveries) and
                len(cleanup) == 1 and tuple(map(int, cleanup[0][:3])) == (0, 0, 0) and
                int(cleanup[0][3]) <= 137000)
    kinds = Counter(e['kind'] for e in events)
    sni = [e for e in events if e['kind'] == 'sni']
    requests = [e for e in events if e['kind'] == 'request']
    alerts = [e for e in events if e['kind'] == 'tls-alert']
    closures = [e for e in events if e['kind'] == 'closure']
    peer_ok = (kinds == Counter(sni=9, request=5, **{'tls-alert': 2, 'closure': 3}) and
               Counter(e['server'] for e in sni) == Counter(trusted=7, expired=1, future=1) and
               all(e['name'] == '192.0.2.1' for e in sni) and
               all(e['exact'] and e['server'] == 'trusted' and e['protocol'] == 'TLSv1.2' and
                   e['cipher'] == 'ECDHE-RSA-AES128-GCM-SHA256' for e in requests) and
               Counter(e['server'] for e in alerts) == Counter(expired=1, future=1) and
               all(e['reason'] == {'expired': 'SSLV3_ALERT_CERTIFICATE_EXPIRED',
                                   'future': 'SSLV3_ALERT_CERTIFICATE_UNKNOWN'}[e['server']] for e in alerts) and
               [(e['mode'], e['established'], e['exact'], e['sent']) for e in closures] ==
               [('handshake-eof', False, True, 0), ('unclean-eof', True, True, 7), ('reset', True, True, 0)])
    return {'complete_attempts': bool(complete), 'peer_accounting_passed': bool(peer_ok),
            'failures': rows, 'recoveries': recoveries, 'cleanup': cleanup}
