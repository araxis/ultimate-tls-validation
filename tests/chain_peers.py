"""Measured certificate-chain fixtures and independently framed TLS transfers."""
import hashlib
import json
import socket
import ssl
import subprocess
from record_peer import RecordConnection

PROFILES = ('direct', 'one-intermediate', 'three-intermediates', 'padded-certificate')
PAYLOAD_BYTES = 65536


def make_chains(directory):
    def openssl(*args):
        return subprocess.run(['openssl', *map(str, args)], cwd=directory, check=True,
                              capture_output=True, timeout=30).stdout

    issuers = ['trusted-ca']
    for level in range(1, 4):
        name = f'intermediate-{level}'
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN=TLS lab intermediate {level}',
                '-keyout', name + '.key', '-out', name + '.csr')
        ext = directory / (name + '.ext')
        ext.write_text(f'basicConstraints=critical,CA:TRUE,pathlen:{3-level}\n'
                       'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
        openssl('x509', '-req', '-in', name + '.csr', '-CA', issuers[-1] + '.pem',
                '-CAkey', issuers[-1] + '.key', '-set_serial', 100 + level, '-days', 2,
                '-extfile', ext, '-out', name + '.pem')
        issuers.append(name)
    inventory = []
    for profile, depth in enumerate((0, 1, 3, 3)):
        name = f'chain-{profile}'
        if depth:
            ext = directory / (name + '.ext')
            extension = ('subjectAltName=DNS:tls.lab.test\nbasicConstraints=critical,CA:FALSE\n'
                         'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
            if profile == 3:
                # An explicit synthetic size stressor, not a realistic CA policy:
                # noncritical private extension containing an 8 KiB OCTET STRING.
                extension += '1.3.6.1.4.1.55555.1=DER:' + (b'\x04\x82\x20\x00' + bytes(8192)).hex(':') + '\n'
            ext.write_text(extension)
            openssl('x509', '-req', '-in', 'trusted.csr', '-CA', issuers[depth] + '.pem',
                    '-CAkey', issuers[depth] + '.key', '-set_serial', 200 + profile, '-days', 2,
                    '-extfile', ext, '-out', name + '-leaf.pem')
            leaf = name + '-leaf.pem'
        else:
            leaf = 'trusted.pem'
        certificates = [leaf] + [issuers[i] + '.pem' for i in range(depth, 0, -1)]
        (directory / (name + '.pem')).write_bytes(b''.join((directory / path).read_bytes() for path in certificates))
        verify_args = ['verify', '-verify_hostname', 'tls.lab.test', '-purpose', 'sslserver', '-CAfile', 'trusted-ca.pem']
        if depth:
            bundle = name + '-issuers.pem'
            (directory / bundle).write_bytes(b''.join((directory / path).read_bytes() for path in certificates[1:]))
            verify_args += ['-untrusted', bundle]
        verification = openssl(*verify_args, leaf).decode().strip()
        encoded = [openssl('x509', '-in', path, '-outform', 'DER') for path in certificates]
        # TLS 1.2 Certificate handshake: header + list length + per-cert lengths.
        handshake_bytes = 4 + 3 + sum(3 + len(der) for der in encoded)
        if handshake_bytes >= 16384:
            raise ValueError('Fixture exceeds the intended single-handshake-record size boundary')
        inventory.append(dict(profile=profile, name=PROFILES[profile], intermediates=depth,
                              certificate_der_bytes=[len(der) for der in encoded],
                              certificate_sha256=[hashlib.sha256(der).hexdigest() for der in encoded],
                              certificate_message_bytes=handshake_bytes, verification=verification,
                              synthetic_padding_bytes=8192 if profile == 3 else 0))
    (directory / 'chain-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')


def serve_chain(peers, listener, profile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.load_cert_chain(peers.directory / f'chain-{profile}.pem', peers.directory / 'trusted.key')
    block = bytes((i * 37 + 11) & 255 for i in range(16384))
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        event = dict(kind='chain-peer', profile=profile, index=None, sent=0, records=0, sni=None, close_sent=False)
        context.set_servername_callback(lambda stream, host, config: event.update(sni=host))
        with connection:
            connection.settimeout(8)
            try:
                tls = RecordConnection(connection, context)
                tls.perform(tls.stream.do_handshake)
                trigger = tls.perform(lambda: tls.stream.read(1))
                if len(trigger) != 1 or trigger[0] >= 16 or (trigger[0] % 8) // 2 != profile:
                    raise ValueError('Unexpected certificate-profile request')
                index = trigger[0]
                chunk = 16384 if index % 2 else 512
                event.update(index=index, chunk=chunk, protocol=tls.stream.version(), cipher=tls.stream.cipher()[0])
                while event['sent'] < PAYLOAD_BYTES:
                    record = tls.record(block[:chunk])
                    if len(record) != chunk + 29:
                        raise ValueError('Unexpected TLS 1.2 GCM record size')
                    connection.sendall(record)
                    event['sent'] += chunk
                    event['records'] += 1
                try:
                    tls.stream.unwrap()
                except ssl.SSLWantReadError:
                    pass
                alert = tls.outgoing.read()
                if alert[:3] != b'\x15\x03\x03' or len(alert) != 5 + int.from_bytes(alert[3:5], 'big'):
                    raise ValueError('Expected one TLS close notification')
                connection.sendall(alert)
                event['close_sent'] = True
            except (OSError, ValueError) as error:
                peers.record(kind='fixture-error', error=f'Chain peer {profile}: {error}')
            finally:
                peers.record(**event)


def chain_accounting(events):
    rows = [e for e in events if e['kind'] == 'chain-peer']
    return (len(rows) == 16 and {e['index'] for e in rows} == set(range(16))
            and all(e['profile'] == (e['index'] % 8) // 2 and e['sent'] == PAYLOAD_BYTES
                    and e['chunk'] == (16384 if e['index'] % 2 else 512)
                    and e['records'] * e['chunk'] == PAYLOAD_BYTES and e['close_sent']
                    and e['sni'] == 'tls.lab.test' and e['protocol'] == 'TLSv1.2'
                    and e['cipher'] == 'ECDHE-RSA-AES128-GCM-SHA256' for e in rows))
