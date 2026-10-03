"""Independent acceptance checks for finite target waits and recovery."""
from collections import Counter
import re

CHECKS = 91
FAULTS = ['handshake-timeout', 'handshake-cancel', 'read-timeout', 'read-cancel']


def account(output, events):
    labels = [label for fault in FAULTS for label in (fault, 'recovery-' + fault)]
    rows = re.findall(r'^TIMING ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) verify=(\d+) '
                      r'elapsed=(-?\d+) read_start=(-?\d+) cancel_delay=(-?\d+) cancel_return=(-?\d+) opens=(\d+)\r?$', output, re.M)
    recovery = re.findall(r'^RESULT ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) '
                          r'verify=(\d+) sent=(\d+) received=(\d+) opens=(\d+)\r?$', output, re.M)
    complete = (re.findall(r'^ATTEMPT ([a-z-]+)\r?$', output, re.M) == labels and
                [r[0] for r in rows] == FAULTS and
                [r[0] for r in recovery] == ['recovery-' + f for f in FAULTS] and
                all(tuple(map(int, r[1:])) == (0, 9, -30848, 0, 62, 65, 1) for r in recovery))
    for row in rows:
        label = row[0]
        status, stage, code, verify, elapsed, read_start, delay, returned, opens = map(int, row[1:])
        cancel, reading = label.endswith('cancel'), label.startswith('read')
        budget = 10000 if cancel else (3000 if reading else 1500)
        timing_ok = (40 <= delay <= elapsed < budget and 0 <= returned <= 250) if cancel else (
            budget <= elapsed <= budget + 250 and delay == returned == 0)
        complete = complete and (status == (2 if cancel else 3) and stage == (9 if reading else 8)
                                 and code == -26624 and verify == (0 if reading else 0xffffffff)
                                 and opens == 1 and timing_ok
                                 and (0 <= read_start < elapsed if reading else read_start == 0)
                                 and (not reading or cancel or read_start >= 500))
    kinds = Counter(e['kind'] for e in events)
    peer_ok = (kinds == Counter({'sni': 6, 'request': 6, 'stall': 4}) and
               Counter(e['phase'] for e in events if e['kind'] == 'stall') == Counter({'handshake': 2, 'read': 2}) and
               all(e['name'] == '192.0.2.1' and e['server'] == 'trusted' for e in events if e['kind'] == 'sni') and
               all(e['server'] == 'trusted' and e['exact'] and e['protocol'] == 'TLSv1.2' and
                   e['cipher'] == 'ECDHE-RSA-AES128-GCM-SHA256' for e in events if e['kind'] == 'request'))
    return {'complete_attempts': bool(complete), 'peer_accounting_passed': peer_ok,
            'results': rows, 'recovery': recovery}
