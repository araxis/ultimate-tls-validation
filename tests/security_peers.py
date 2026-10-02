"""Date-invalid certificates and controlled TLS closure fixtures."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import socket
import ssl
import struct
import subprocess


def make_dated_certificates(directory):
    def openssl(*args, check=True):
        return subprocess.run(['openssl', *args], cwd=directory, check=check,
                              capture_output=True, text=True, timeout=30)

    (directory / 'date-index').write_text('')
    (directory / 'date-serial').write_text('1000\n')
    (directory / 'date-ca.cnf').write_text('''[ca]
default_ca = issuer
[issuer]
database = date-index
serial = date-serial
new_certs_dir = .
certificate = trusted-ca.pem
private_key = trusted-ca.key
default_md = sha256
policy = subject
unique_subject = no
[subject]
commonName = supplied
''')
    now = datetime.now(timezone.utc).replace(microsecond=0)
    reports = []
    for name, start, end, error in (
        ('expired', now - timedelta(days=2), now - timedelta(days=1), 10),
        ('future', now + timedelta(days=1), now + timedelta(days=2), 9),
    ):
        openssl('ca', '-batch', '-notext', '-config', 'date-ca.cnf',
                '-in', 'trusted.csr', '-out', f'{name}.pem', '-extfile', 'trusted.ext',
                '-startdate', start.strftime('%Y%m%d%H%M%SZ'), '-enddate', end.strftime('%Y%m%d%H%M%SZ'))
        # Verify chain, hostname and purpose independently with only dates ignored.
        common = ('verify', '-CAfile', 'trusted-ca.pem', '-purpose', 'sslserver', '-verify_hostname', 'tls.lab.test')
        structural = openssl(*common, '-no_check_time', f'{name}.pem')
        dated = openssl(*common, f'{name}.pem', check=False)
        if dated.returncode == 0 or f'error {error} at 0 depth lookup' not in dated.stderr:
            raise RuntimeError(f'Unexpected certificate fixture validation: {dated.stdout}{dated.stderr}')
        metadata = openssl('x509', '-in', f'{name}.pem', '-noout', '-dates', '-issuer', '-subject').stdout
        reports.append({'name': name, 'reference_utc': now.isoformat(), 'metadata': metadata,
                        'structural_verification': structural.stdout.strip(),
                        'date_verification': dated.stderr.strip(), 'expected_verify_error': error,
                        'sha256': hashlib.sha256((directory / f'{name}.pem').read_bytes()).hexdigest()})
    (directory / 'date-fixtures.json').write_text(json.dumps(reports, indent=2) + '\n')


def serve_closure(peers, listener, mode):
    def receive_exact(connection, length):
        data = b''
        while len(data) < length:
            chunk = connection.recv(length - len(data))
            if not chunk:
                raise ValueError('Incomplete ClientHello record')
            data += chunk
        return data

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.load_cert_chain(peers.directory / 'trusted.pem', peers.directory / 'trusted.key')
    context.set_servername_callback(lambda stream, host, config: peers.record(kind='sni', name=host, server='trusted'))
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        connection.settimeout(6)
        try:
            if mode == 'handshake-eof':
                header = receive_exact(connection, 5)
                length = int.from_bytes(header[3:5], 'big')
                if header[0:2] != b'\x16\x03' or not 4 <= length <= 18432:
                    raise ValueError('Expected TLS handshake record')
                hello = receive_exact(connection, length)
                if hello[0] != 1:
                    raise ValueError('Expected ClientHello')
                connection.shutdown(socket.SHUT_WR)
                peers.record(kind='closure', mode=mode, established=False, exact=True, sent=0)
                # Consume the complete record before FIN, then wait for the
                # client to close, avoiding an unread-data reset from close().
                if connection.recv(1):
                    raise ValueError('Unexpected data after handshake EOF')
            else:
                with context.wrap_socket(connection, server_side=True) as stream:
                    if stream.recv(1) != b'!':
                        raise ValueError('Expected authenticated client marker')
                    sent = 0
                    if mode == 'unclean-eof':
                        stream.sendall(b'partial')
                        sent = 7
                    # Detach prevents any TLS shutdown: the fixture must not
                    # accidentally turn a missing close_notify into clean EOF.
                    with socket.socket(fileno=stream.detach()) as raw:
                        if mode == 'reset':
                            raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                        else:
                            raw.shutdown(socket.SHUT_WR)
                    peers.record(kind='closure', mode=mode, established=True, exact=True, sent=sent)
        except (OSError, ValueError) as error:
            peers.record(kind='fixture-error', error=f'{mode}: {error}')
        finally:
            connection.close()
