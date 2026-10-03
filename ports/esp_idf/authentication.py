"""IP-SAN certificate fixtures and independent target authentication accounting."""
from collections import Counter
import json
import re
import shutil
import subprocess

from run_probe import make_certificate

ATTEMPTS = ['valid-chain', 'wrong-host', 'recovery-after-host', 'wrong-root',
            'recovery-after-root', 'missing-time', 'recovery-after-time',
            'entropy-failure', 'recovery-after-entropy']
CHECKS = 83


def prepare_certificates(directory, ecdsa):
    def openssl(*args):
        return subprocess.run(['openssl', *args], cwd=directory,
                              capture_output=True, text=True, timeout=30)

    for name in ('trusted', 'untrusted'):
        make_certificate(directory, name, ecdsa=ecdsa)
    shutil.copyfile(directory / 'trusted.key', directory / 'wrong-host.key')
    for name, root, csr, address in (
        ('trusted', 'trusted', 'trusted', '192.0.2.1'),
        ('untrusted', 'untrusted', 'untrusted', '192.0.2.1'),
        ('wrong-host', 'trusted', 'trusted', '192.0.2.9'),
    ):
        extension = directory / f'{name}.ext'
        extension.write_text('subjectAltName=DNS:tls.lab.test,IP:' + address + '\n'
                             'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                             'extendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-in', f'{csr}.csr', '-CA', f'{root}-ca.pem',
                '-CAkey', f'{root}-ca.key', '-set_serial', '2' if name == 'wrong-host' else '1',
                '-days', '2', '-out', f'{name}.pem', '-extfile', str(extension)).check_returncode()
    verification = []
    for name, root, address, expected_error in (
        ('trusted', 'trusted', '192.0.2.1', None),
        ('untrusted', 'untrusted', '192.0.2.1', None),
        ('wrong-host', 'trusted', '192.0.2.9', None),
        ('wrong-host', 'trusted', '192.0.2.1', 64),
        ('untrusted', 'trusted', '192.0.2.1', 20),
    ):
        result = openssl('verify', '-CAfile', f'{root}-ca.pem', '-no-CApath', '-no-CAstore',
                         '-purpose', 'sslserver', '-verify_ip', address, f'{name}.pem')
        valid = result.returncode == 0 if expected_error is None else (
            result.returncode != 0 and f'error {expected_error} at 0 depth lookup' in result.stderr)
        verification.append({'leaf': name, 'root': root, 'address': address,
                             'expected_error': expected_error, 'returncode': result.returncode,
                             'output': result.stdout + result.stderr})
        if not valid:
            raise ValueError('Unexpected certificate fixture verification: ' + str(verification[-1]))
    details = {}
    for name in ('trusted-ca', 'trusted', 'untrusted-ca', 'untrusted', 'wrong-host'):
        result = openssl('x509', '-in', f'{name}.pem', '-noout', '-text')
        result.check_returncode()
        required = ('Public Key Algorithm: id-ecPublicKey', 'ASN1 OID: prime256v1',
                    'Signature Algorithm: ecdsa-with-SHA256') if ecdsa else (
                    'Public Key Algorithm: rsaEncryption', 'Public-Key: (2048 bit)',
                    'Signature Algorithm: sha256WithRSAEncryption')
        if not all(value in result.stdout for value in required):
            raise ValueError('Unexpected certificate algorithm: ' + name)
        details[name] = result.stdout
    (directory / 'authentication-fixtures.json').write_text(json.dumps(
        {'profile': 'ecdsa' if ecdsa else 'rsa', 'verification': verification,
         'details': details}, indent=2) + '\n')


def account(output, events, ecdsa):
    attempts = re.findall(r'^ATTEMPT ([a-z-]+)\r?$', output, re.M)
    rows = re.findall(r'^RESULT ([a-z-]+) status=(\d+) stage=(\d+) code=(-?\d+) '
                      r'verify=(\d+) sent=(\d+) received=(\d+) opens=(\d+)\r?$', output, re.M)
    expected = {
        'wrong-host': (5, 8, -9984, 4, 0, 0, 1),
        'wrong-root': (5, 8, -9984, 8, 0, 0, 1),
        'missing-time': (6, 1, 0, 0, 0, 0, 0),
        'entropy-failure': (5, 2, -52, 0, 0, 0, 0),
    }
    complete = (attempts == ATTEMPTS and [r[0] for r in rows] == ATTEMPTS and
                all(tuple(map(int, row[1:])) == expected.get(row[0], (0, 9, -30848, 0, 62, 65, 1))
                    for row in rows))
    requests = [e for e in events if e['kind'] == 'request']
    alerts = [e for e in events if e['kind'] == 'tls-alert']
    sni = [e for e in events if e['kind'] == 'sni']
    cipher = 'ECDHE-ECDSA-AES128-GCM-SHA256' if ecdsa else 'ECDHE-RSA-AES128-GCM-SHA256'
    peer_ok = (len(requests) == 5 and all(e['server'] == 'trusted' and e['exact'] and
               e['protocol'] == 'TLSv1.2' and e['cipher'] == cipher for e in requests)
               and Counter(e['server'] for e in alerts) == Counter({'wrong-host': 1, 'untrusted': 1})
               and all(e['reason'] == {'wrong-host': 'SSLV3_ALERT_BAD_CERTIFICATE',
                                       'untrusted': 'TLSV1_ALERT_UNKNOWN_CA'}[e['server']] for e in alerts)
               and Counter(e['server'] for e in sni) == Counter({'trusted': 5, 'wrong-host': 1, 'untrusted': 1})
               and all(e['name'] == '192.0.2.1' for e in sni)
               and len(events) == 14)
    return {'complete_attempts': complete, 'peer_accounting_passed': peer_ok,
            'attempts': attempts, 'results': rows}
