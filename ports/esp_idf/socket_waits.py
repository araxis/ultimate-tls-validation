"""Accept only observed connection stalls/backpressure and complete recovery."""
from collections import Counter
import re

CHECKS = 122
CASES = ['connect-refused', 'connect-timeout', 'connect-cancel', 'write-timeout', 'write-cancel']


def account(output, events):
    labels = [label for case in CASES for label in (case, 'recovery-' + case)]
    rows = re.findall(r'^SOCKET_WAIT ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) verify=(\d+) '
                      r'elapsed=(-?\d+) cancel_return=(-?\d+) syns=(\d+) drops=(\d+) blocked=(\d+) sent=(\d+) opens=(\d+)\r?$', output, re.M)
    recovery = re.findall(r'^RESULT ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) '
                          r'verify=(\d+) sent=(\d+) received=(\d+) opens=(\d+)\r?$', output, re.M)
    complete = (re.findall(r'^ATTEMPT ([a-z-]+)\r?$', output, re.M) == labels and
                [r[0] for r in rows] == CASES and [r[0] for r in recovery] == ['recovery-' + c for c in CASES] and
                all(tuple(map(int, r[1:])) == (0, 9, -30848, 0, 62, 65, 1) for r in recovery))
    for row in rows:
        label = row[0]
        status, stage, code, verify, elapsed, returned, syns, drops, blocked, sent, opens = map(int, row[1:])
        writing, cancel, refused = label.startswith('write'), label.endswith('cancel'), label.endswith('refused')
        budget = 4000 if writing else 1500
        bounded = (0 <= elapsed <= 500) if refused else (0 <= returned <= 250 and 0 <= elapsed < 10000) if cancel else (
            budget <= elapsed <= budget + 250)
        mechanism = (syns == drops == 0 and blocked > 0 and 0 < sent < 262144) if writing else (
            syns > 0 and drops == (0 if refused else syns) and blocked == sent == 0)
        complete = complete and (status == (4 if refused else 2 if cancel else 3) and stage == (10 if writing else 7)
                                 and code == (-26624 if writing else 0) and verify == 0 and opens == 1
                                 and bounded and mechanism and (cancel or returned == 0))
    kinds = Counter(e['kind'] for e in events)
    peer_ok = (kinds == Counter({'sni': 7, 'request': 5, 'write-stall': 2}) and
               all(e['name'] == '192.0.2.1' and e['server'] == 'trusted' for e in events if e['kind'] == 'sni') and
               all(e['server'] == 'trusted' and e['exact'] and e['protocol'] == 'TLSv1.2' and
                   e['cipher'] == 'ECDHE-RSA-AES128-GCM-SHA256' for e in events if e['kind'] == 'request') and
               all(e['closed'] and e['queued_bytes_peak'] > 0 and
                   (e['closed_before_probe'] != e['close_probe_sent'])
                   for e in events if e['kind'] == 'write-stall'))
    return {'complete_attempts': bool(complete), 'peer_accounting_passed': peer_ok,
            'results': rows, 'recovery': recovery}
