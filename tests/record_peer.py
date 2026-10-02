"""Cut real TLS application records at selected encrypted byte boundaries."""
import socket
import ssl


def serve_record_cut(peers, listener, mode):
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
        with connection:
            connection.settimeout(6)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            stream = context.wrap_bio(incoming, outgoing, server_side=True)

            def flush():
                while outgoing.pending:
                    connection.sendall(outgoing.read())

            def perform(operation):
                while True:
                    try:
                        value = operation()
                        flush()
                        return value
                    except ssl.SSLWantReadError:
                        flush()
                        data = connection.recv(4096)
                        if not data:
                            raise ValueError('Peer closed before record-cut fixture was ready')
                        incoming.write(data)
                    except ssl.SSLWantWriteError:
                        flush()

            try:
                perform(stream.do_handshake)
                if perform(lambda: stream.read(1)) != b'!':
                    raise ValueError('Expected authenticated marker')
                if stream.write(b'never-expose-this') != 17:
                    raise ValueError('Incomplete fixture record construction')
                record = outgoing.read()
                if record[:3] != b'\x17\x03\x03' or len(record) != 5 + int.from_bytes(record[3:5], 'big'):
                    raise ValueError('Expected exactly one TLS 1.2 application record')
                cut = {'header': 3, 'body': 17, 'tag': len(record) - 1}[mode]
                if not 0 < cut < len(record):
                    raise ValueError('Record cut must remove ciphertext')
                connection.sendall(record[:cut])
                connection.shutdown(socket.SHUT_WR)
                peers.record(kind='record-cut', mode=mode, record_bytes=len(record), sent=cut)
                if connection.recv(1):
                    raise ValueError('Unexpected application traffic after record cut')
            except (OSError, ValueError) as error:
                peers.record(kind='fixture-error', error=f'record-cut {mode}: {error}')
