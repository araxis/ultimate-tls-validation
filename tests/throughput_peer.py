"""Fixed binary bulk transfers for local read timing, with independent accounting."""
import socket
import ssl

PAYLOAD_BYTES = 2 * 1024 * 1024


def serve_throughput(peers, listener):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.load_cert_chain(peers.directory / 'trusted.pem', peers.directory / 'trusted.key')
    context.set_servername_callback(lambda stream, host, config: peers.record(kind='sni', name=host, server='trusted'))
    block = bytes((index * 37 + 11) & 255 for index in range(16384))
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        connection.settimeout(15)
        index, sent, established = None, 0, False
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                established = True
                trigger = stream.recv(1)
                if len(trigger) != 1 or trigger[0] >= 8:
                    raise ValueError('Invalid bulk-transfer request')
                index = trigger[0]
                while sent < PAYLOAD_BYTES:
                    stream.sendall(block)
                    sent += len(block)
                stream.unwrap().close()
        except (ConnectionResetError, ssl.SSLEOFError):
            # The client destroys TCP after consuming the server close_notify.
            pass
        except (OSError, ValueError) as error:
            peers.record(kind='fixture-error', error=f'Throughput peer: {error}')
        finally:
            connection.close()
            peers.record(kind='throughput-peer', index=index, sent=sent, established=established)


def throughput_accounting(events):
    rows = [event for event in events if event['kind'] == 'throughput-peer']
    return ([row['index'] for row in rows] == list(range(8))
            and all(row['established'] and row['sent'] == PAYLOAD_BYTES for row in rows))
