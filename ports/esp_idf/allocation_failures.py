"""Account for selected allocation failures, recoveries and natural cleanup."""
from collections import Counter
import re
from resources import FIELDS

CHECKS = 174


def account(output, events, ecdsa):
    labels = ['allocation-recovery-0']
    expected_samples = [(0, 'settled'), (0, 'cooldown-start'), (0, 'cooldown-end')]
    for i in range(1, 7):
        point = (i - 1) % 3
        labels.extend(['allocation-%d-%s' % (i, ('create', 'setup', 'handshake')[point]), 'allocation-recovery-%d' % i])
        expected_samples.extend([(i, 'before'), (i, 'settled'), (i, 'settled')])
        if i % 3 == 0:
            expected_samples.extend([(i // 3, 'cooldown-start'), (i // 3, 'cooldown-end')])
    rows = re.findall(r'^ALLOCATION_RESULT index=(\d+) point=(\d+) status=(\d+) stage=(\d+) code=(-?\d+) verify=(\d+) rejected=(\d+) bytes=(\d+) opens=(\d+)\r?$', output, re.M)
    recoveries = re.findall(r'^RESULT allocation-recovery-(\d+) status=(\d+) stage=(\d+) code=(-?\d+) verify=(\d+) sent=(\d+) received=(\d+) opens=(\d+)\r?$', output, re.M)
    measurements = re.findall(r'^RESOURCE attempt=(\d+) phase=([a-z-]+) ' + ' '.join(k + r'=(\d+)' for k in FIELDS) + r'\r?$', output, re.M)
    complete = (re.findall(r'^ATTEMPT ([a-z0-9-]+)\r?$', output, re.M) == labels and len(rows) == 6 and
                len(recoveries) == 7 and [(int(r[0]), r[1]) for r in measurements] == expected_samples)
    for i, row in enumerate(rows, 1):
        index, point, status, stage, code, flags, rejected, size, opens = map(int, row)
        p = (i - 1) % 3
        complete = complete and (index, point, status, stage, code, flags, rejected, opens) == (
            i, p, 1 if p == 0 else 5, (0, 5, 8)[p], 0 if p == 0 else -32512,
            4294967295 if p == 2 else 0, 1, 1 if p == 2 else 0) and size > 0
    for i, row in enumerate(recoveries):
        complete = complete and tuple(map(int, row)) == (i, 0, 9, -30848, 0, 62, 65, 1)
    samples = []
    for row in measurements:
        values = dict(zip(FIELDS, map(int, row[2:])))
        samples.append({'attempt': int(row[0]), 'phase': row[1], **values})
        complete = complete and values['requested'] == values['core'] == values['crypto'] == values['live'] == values['active'] == values['dns'] == 0
        complete = complete and 0 < values['largest'] <= values['free'] and 0 < values['main_stack_free'] <= 12288 and 0 < values['tcp_stack_free'] <= 3584
        if row[1] == 'cooldown-end':
            complete = complete and values['timewait'] == 0
    cipher = 'ECDHE-ECDSA-AES128-GCM-SHA256' if ecdsa else 'ECDHE-RSA-AES128-GCM-SHA256'
    kinds = Counter(e['kind'] for e in events)
    peer_ok = (kinds == Counter({'sni': 9, 'request': 7, 'tls-alert': 2}) and
               all(e['name'] == '192.0.2.1' and e['server'] == 'trusted' for e in events if e['kind'] == 'sni') and
               all(e['exact'] and e['protocol'] == 'TLSv1.2' and e['cipher'] == cipher for e in events if e['kind'] == 'request') and
               all(e['server'] == 'trusted' and e['reason'] == 'TLSV1_ALERT_INTERNAL_ERROR' for e in events if e['kind'] == 'tls-alert'))
    return {'complete_attempts': bool(complete), 'peer_accounting_passed': bool(peer_ok),
            'failures': rows, 'recoveries': recoveries, 'samples': samples}
