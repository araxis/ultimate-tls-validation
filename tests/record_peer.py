"""Construct real TLS records for bounded truncation and rejection fixtures."""
import socket
import ssl


def record_context(peers):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.load_cert_chain(peers.directory / 'trusted.pem', peers.directory / 'trusted.key')
    context.set_servername_callback(lambda stream, host, config: peers.record(kind='sni', name=host, server='trusted'))
    return context


class RecordConnection:
    def __init__(self, connection, context):
        self.connection = connection
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.stream = context.wrap_bio(self.incoming, self.outgoing, server_side=True)

    def flush(self):
        while self.outgoing.pending:
            self.connection.sendall(self.outgoing.read())

    def perform(self, operation):
        while True:
            try:
                value = operation()
                self.flush()
                return value
            except ssl.SSLWantReadError:
                self.flush()
                data = self.connection.recv(4096)
                if not data:
                    raise ValueError('Peer closed before record fixture was ready')
                self.incoming.write(data)
            except ssl.SSLWantWriteError:
                self.flush()

    def handshake_marker(self):
        self.perform(self.stream.do_handshake)
        if self.perform(lambda: self.stream.read(1)) != b'!':
            raise ValueError('Expected authenticated marker')

    def record(self, payload):
        if self.stream.write(payload) != len(payload):
            raise ValueError('Incomplete fixture record construction')
        record = self.outgoing.read()
        if record[:3] != b'\x17\x03\x03' or len(record) != 5 + int.from_bytes(record[3:5], 'big'):
            raise ValueError('Expected exactly one TLS 1.2 application record')
        return record


def serve_record_cut(peers, listener, mode):
    context = record_context(peers)
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        with connection:
            connection.settimeout(6)
            stream = RecordConnection(connection, context)
            try:
                stream.handshake_marker()
                record = stream.record(b'never-expose-this')
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
