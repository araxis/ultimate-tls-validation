"""Strict resource-probe accounting; observations are not whole-device budgets."""
from collections import Counter
import re

CHECKS = 119
PHASES = ['before', 'root', 'created', 'opened', 'destroyed', 'settled']
FIELDS = ['requested', 'peak', 'core', 'crypto', 'live', 'allocations', 'free', 'largest', 'minimum',
          'main_stack_free', 'tcp_stack_free', 'active', 'timewait', 'dns']


def check_count(rounds, duration_seconds=0):
    if duration_seconds:
        from duration import rounds_for
        if rounds != rounds_for(duration_seconds):
            raise ValueError('Resource rounds do not match duration')
    elif rounds not in (1, 3):
        raise ValueError('Resource rounds must be 1 or 3')
    return CHECKS + (rounds - 1) * 115


def account(output, events, ecdsa, rounds=1, duration_seconds=0):
    check_count(rounds, duration_seconds)
    labels = ['resource-%d-%s' % (i, 'reject' if i % 2 else 'valid') for i in range(8 * rounds)]
    expected = []
    for start in range(0, 8 * rounds, 8):
        expected.extend((i, p) for i in range(start, start + 8) for p in PHASES)
        expected.extend([(start + 8, 'cooldown-start'), (start + 8, 'cooldown-end')])
    rows = re.findall(r'^RESOURCE_RESULT attempt=(\d+) status=(\d+) stage=(\d+) code=(-?\d+) verify=(\d+) opens=(\d+)\r?$', output, re.M)
    config = re.findall(r'^RESOURCE_CONFIG cycles=(\d+) stack_element=(\d+) main_stack=(\d+) tcp_stack=(\d+) tracker_capacity=(\d+)\r?$', output, re.M)
    measurements = re.findall(r'^RESOURCE attempt=(\d+) phase=([a-z-]+) ' + ' '.join(k + r'=(\d+)' for k in FIELDS) + r'\r?$', output, re.M)
    complete = (re.findall(r'^ATTEMPT ([a-z0-9-]+)\r?$', output, re.M) == labels and len(rows) == 8 * rounds and
                len(config) == 1 and config[0][0:3] == (str(4 * rounds), '1', '12288') and config[0][4] == '256' and
                [(int(r[0]), r[1]) for r in measurements] == expected)
    for i, row in enumerate(rows):
        complete = complete and tuple(map(int, row)) == ((i, 5, 8, -9984, 4, 1) if i % 2 else (i, 0, 8, 0, 0, 1))
    samples = []
    for row in measurements:
        attempt, phase = int(row[0]), row[1]
        values = dict(zip(FIELDS, map(int, row[2:])))
        samples.append({'attempt': attempt, 'phase': phase, **values})
        complete = complete and (values['requested'] == values['core'] + values['crypto'] <= values['peak'] and
            0 < values['largest'] <= values['free'] and 0 < values['minimum'] <= values['free'] and
            0 < values['main_stack_free'] <= 12288 and 0 < values['tcp_stack_free'] <= int(config[0][3]) and
            values['dns'] == 0 and values['timewait'] <= 4)
        if phase in ('before', 'destroyed', 'settled', 'cooldown-start', 'cooldown-end'):
            complete = complete and values['requested'] == values['live'] == 0
        if phase == 'root':
            complete = complete and values['core'] == 0 and values['crypto'] > 0
        if phase in ('created', 'opened'):
            complete = complete and values['core'] > 0 and values['crypto'] > 0 and values['live'] > 1
        if phase == 'opened':
            complete = complete and values['active'] == (0 if attempt % 2 else 1)
        if phase == 'settled':
            complete = complete and values['active'] == 0 and values['allocations'] > 1 and values['peak'] > 0
        if phase == 'cooldown-end':
            complete = complete and values['active'] == values['timewait'] == 0
    kinds = Counter(e['kind'] for e in events)
    cipher = 'ECDHE-ECDSA-AES128-GCM-SHA256' if ecdsa else 'ECDHE-RSA-AES128-GCM-SHA256'
    peer_ok = (kinds == Counter({'sni': 8 * rounds, 'request': 4 * rounds, 'tls-alert': 4 * rounds}) and
               all(e['name'] == '192.0.2.1' for e in events if e['kind'] == 'sni') and
               Counter(e['server'] for e in events if e['kind'] == 'sni') == Counter({'trusted': 4 * rounds, 'wrong-host': 4 * rounds}) and
               all(e['server'] == 'trusted' and e['exact'] and e['protocol'] == 'TLSv1.2' and e['cipher'] == cipher for e in events if e['kind'] == 'request') and
               all(e['server'] == 'wrong-host' and e['reason'] == 'SSLV3_ALERT_BAD_CERTIFICATE' for e in events if e['kind'] == 'tls-alert'))
    return {'complete_attempts': bool(complete), 'peer_accounting_passed': peer_ok,
            'results': rows, 'configuration': config, 'samples': samples}
