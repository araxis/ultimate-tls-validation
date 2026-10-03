"""Independent validation of the P-256 authentication fixture and its accounting."""
import hashlib
import json
import re
import subprocess


def verify_certificates(directory):
    def openssl(*args, check=True):
        return subprocess.run(['openssl', *args], cwd=directory, check=check,
                              capture_output=True, text=True, timeout=30)

    certificates = []
    for name in ('trusted-ca', 'trusted', 'untrusted-ca', 'untrusted'):
        details = openssl('x509', '-in', name + '.pem', '-noout', '-text').stdout
        if ('Public Key Algorithm: id-ecPublicKey' not in details or
                'ASN1 OID: prime256v1' not in details or
                'Signature Algorithm: ecdsa-with-SHA256' not in details):
            raise ValueError('Expected P-256 key and ECDSA SHA-256 certificate signature')
        certificates.append({'name': name, 'details': details,
                             'sha256': hashlib.sha256((directory / (name + '.pem')).read_bytes()).hexdigest()})
    verification = []
    for name, root, host, error in (
        ('trusted', 'trusted-ca', 'tls.lab.test', None),
        ('untrusted', 'untrusted-ca', 'tls.lab.test', None),
        ('trusted', 'trusted-ca', 'wrong.lab.test', 62),
        ('untrusted', 'trusted-ca', 'tls.lab.test', 20),
    ):
        result = openssl('verify', '-CAfile', root + '.pem', '-no-CApath', '-no-CAstore',
                         '-purpose', 'sslserver', '-verify_hostname', host, name + '.pem', check=False)
        valid = result.returncode == 0 if error is None else (
            result.returncode != 0 and f'error {error} at 0 depth lookup' in result.stderr)
        if not valid:
            raise ValueError(f'Unexpected ECDSA fixture verification: {result.stdout}{result.stderr}')
        verification.append({'leaf': name, 'root': root, 'hostname': host, 'expected_error': error,
                             'returncode': result.returncode, 'output': result.stdout + result.stderr})
    (directory / 'ecdsa-fixtures.json').write_text(json.dumps(
        {'openssl': openssl('version').stdout.strip(), 'certificates': certificates,
         'verification': verification}, indent=2) + '\n')


def ecdsa_allocation_accounting(output, attempts):
    rows = re.findall(r'^ECDSA_MEMORY label=([a-z-]+) open_bytes=(\d+) open_peak=(\d+) '
                      r'peak=(\d+) final_live=(\d+) final_bytes=(\d+)$', output, re.MULTILINE)
    return ([row[0] for row in rows] == attempts
            and all(int(peak) >= int(open_peak) >= int(open_bytes) > 0
                    and int(live) == 0 and int(final) == 0
                    for _, open_bytes, open_peak, peak, live, final in rows))
