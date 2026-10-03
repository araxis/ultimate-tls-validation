"""Controlled DNS replies and strict accounting for the emulator DNS profile."""
from collections import Counter
import re
import socket
import struct
import time

CHECKS = 154
CASES = ['dns-negative', 'dns-timeout', 'dns-cancel', 'dns-identity', 'dns-budget']


def serve(peers, listener):
    pending, scheduled = [], set()
    listener.settimeout(0.02)
    while not peers.stop.is_set():
        for due, response, endpoint, name in pending[:]:
            if time.monotonic() >= due:
                listener.sendto(response, endpoint)
                peers.record(kind='dns-reply', name=name)
                pending.remove((due, response, endpoint, name))
        try:
            packet, endpoint = listener.recvfrom(512)
        except socket.timeout:
            continue
        try:
            offset, labels = 12, []
            while packet[offset]:
                length = packet[offset]
                if length > 63:
                    raise ValueError('invalid query label')
                labels.append(packet[offset + 1:offset + 1 + length].decode('ascii'))
                offset += length + 1
            end = offset + 5
            query_type, query_class = struct.unpack('!HH', packet[offset + 1:end])
            name = '.'.join(labels)
            allowed = name in ('tls.lab.test', 'wrong.lab.test', 'late.lab.test', 'cancel-late.lab.test', 'budget.lab.test') or bool(re.fullmatch(r'pool-[0-3]\.lab\.test', name))
            accepted = allowed and query_type == 1 and query_class == 1
            peers.record(kind='dns-query', name=name, query_type=query_type, query_class=query_class)
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('192.0.2.1') if accepted else b''
            response = packet[:2] + struct.pack('!HHHHH', 0x8180 if accepted else 0x8183, 1, int(accepted), 0, 0) + packet[12:end] + answer
            delay = 2 if name.startswith('pool-') else 0.6 if name in ('late.lab.test', 'cancel-late.lab.test', 'budget.lab.test') else 0
            if delay:
                if name not in scheduled:
                    scheduled.add(name)
                    pending.append((time.monotonic() + delay, response, endpoint, name))
            else:
                listener.sendto(response, endpoint)
                peers.record(kind='dns-reply', name=name)
        except (IndexError, ValueError, struct.error) as error:
            peers.record(kind='fixture-error', error=str(error))


def account(output, events):
    labels = ['valid-hostname'] + [label for case in CASES for label in (case, 'recovery-' + case)] + ['dns-pool', 'literal-while-full', 'recovery-pool']
    rows = re.findall(r'^DNS_RESULT ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) verify=(\d+) elapsed=(\d+) cancel_return=(\d+) pending=(\d+)\r?$', output, re.M)
    recovery = re.findall(r'^RESULT ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) verify=(\d+) sent=(\d+) received=(\d+) opens=(\d+)\r?$', output, re.M)
    expected_recovery = ['valid-hostname'] + ['recovery-' + c for c in CASES] + ['literal-while-full', 'recovery-pool']
    complete = (re.findall(r'^ATTEMPT ([a-z-]+)\r?$', output, re.M) == labels and [r[0] for r in rows] == CASES and
                [r[0] for r in recovery] == expected_recovery and
                all(tuple(map(int, r[1:])) == (0, 9, -30848, 0, 62, 65, 1) for r in recovery))
    expected = [(4, 7, 0, 0, 0), (3, 7, 0, 0, 1), (2, 7, 0, 0, 1), (5, 8, -9984, 4, 0), (3, 8, -26624, 4294967295, 0)]
    for i, row in enumerate(rows):
        status, stage, code, flags, elapsed, returned, pending = map(int, row[1:])
        bounded = 100 <= elapsed <= 350 if i == 1 else 0 <= returned <= 250 and elapsed < 3000 if i == 2 else 1000 <= elapsed <= 1250 if i == 4 else elapsed <= 1500
        complete = complete and (status, stage, code, flags, pending) == expected[i] and bounded and (i == 2 or returned == 0)
    pool = re.findall(r'^DNS_POOL index=(\d+) elapsed=(\d+) pending=(\d+)\r?$', output, re.M)
    full = re.findall(r'^DNS_FULL capacity=(\d+) elapsed=(\d+) pending=(\d+)\r?$', output, re.M)
    drains = re.findall(r'^DNS_DRAIN ([a-z-]+) pending=(\d+)\r?$', output, re.M)
    complete = complete and len(pool) == 4 and all(int(i) == index and 60 <= int(ms) <= 310 and int(pending) == index + 1 for index, (i, ms, pending) in enumerate(pool))
    complete = complete and len(full) == 1 and full[0][0] == full[0][2] == '4' and int(full[0][1]) <= 250
    complete = complete and drains == [(c, '0') for c in CASES + ['pool']]
    kinds = Counter(e['kind'] for e in events)
    queries, replies = [e for e in events if e['kind'] == 'dns-query'], [e for e in events if e['kind'] == 'dns-reply']
    names = {'tls.lab.test', 'absent.lab.test', 'late.lab.test', 'cancel-late.lab.test', 'wrong.lab.test', 'budget.lab.test'} | {'pool-%d.lab.test' % i for i in range(4)}
    query_counts, reply_counts = Counter(e['name'] for e in queries), Counter(e['name'] for e in replies)
    peer_ok = (set(kinds) == {'dns-query', 'dns-reply', 'sni', 'request', 'tls-alert', 'stall'} and
               kinds['sni'] == 9 and kinds['request'] == 8 and kinds['tls-alert'] == 1 and kinds['stall'] == 1 and
               all(e['phase'] == 'handshake' for e in events if e['kind'] == 'stall') and
               set(query_counts) == set(reply_counts) == names and
               all(1 <= n <= 4 for n in query_counts.values()) and
               all(reply_counts[n] == (query_counts[n] if n in ('tls.lab.test', 'absent.lab.test', 'wrong.lab.test') else 1) for n in names) and
               all(e['query_type'] == e['query_class'] == 1 for e in queries) and
               Counter(e['name'] for e in events if e['kind'] == 'sni') == Counter({'tls.lab.test': 7, 'wrong.lab.test': 1, '192.0.2.1': 1}) and
               all(e['server'] == 'trusted' for e in events if e['kind'] in ('sni', 'request', 'tls-alert')) and
               all(e['exact'] and e['protocol'] == 'TLSv1.2' and e['cipher'] == 'ECDHE-RSA-AES128-GCM-SHA256' for e in events if e['kind'] == 'request') and
               all(e['reason'] == 'SSLV3_ALERT_BAD_CERTIFICATE' for e in events if e['kind'] == 'tls-alert'))
    return {'complete_attempts': bool(complete), 'peer_accounting_passed': bool(peer_ok), 'results': rows,
            'recovery': recovery, 'pool': pool, 'full': full, 'drains': drains}
