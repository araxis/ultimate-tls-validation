"""Two independent listeners keep both TLS sessions alive before their exchanges."""
import socket
import ssl


def serve_memory(peers, listener, slot):
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
        connection.settimeout(12)
        request, sent = b'', False
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                request = stream.recv(1)
                if len(request) != 1 or request[0] >= 8 or request[0] % 2 != slot:
                    raise ValueError('Invalid memory-test request')
                stream.sendall(b'Y')
                sent = True
                stream.unwrap().close()
        except (ConnectionResetError, ssl.SSLEOFError):
            pass
        except (OSError, ValueError) as error:
            peers.record(kind='fixture-error', error=f'Memory peer: {error}')
        finally:
            connection.close()
            peers.record(kind='memory-peer', index=request[0] if len(request) == 1 else None, slot=slot, sent=sent)


def memory_accounting(events):
    rows = [row for row in events if row['kind'] == 'memory-peer']
    return (len(rows) == 8 and {row['index'] for row in rows} == set(range(8))
            and all(row['sent'] and row['slot'] == row['index'] % 2 for row in rows))
