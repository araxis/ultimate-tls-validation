"""Independent binary peers for session isolation and transport-boundary tests."""
import socket
import ssl


def serve_sessions(peers, listener, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.load_cert_chain(peers.directory / 'trusted.pem', peers.directory / 'trusted.key')
    context.set_servername_callback(lambda stream, host, config: peers.record(kind='sni', name=host, server='trusted'))
    expected = bytes((i * 37 + port) & 255 for i in range(1025))
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        received, established, sent = b'', False, 0
        connection.settimeout(6)
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                established = True
                while len(received) < len(expected):
                    chunk = stream.recv(min(127, len(expected) - len(received)))
                    if not chunk:
                        break
                    received += chunk
                if received == expected:
                    for offset in range(0, len(expected), 113):
                        part = expected[offset:offset + 113]
                        stream.sendall(part)
                        sent += len(part)
                    stream.unwrap().close()
                elif port != 8451:
                    peers.record(kind='fixture-error', error=f'Unexpected session payload on {port}')
        except (ConnectionResetError, ssl.SSLEOFError):
            # Boundary cancellation intentionally aborts TCP. Successful clients
            # also close TCP after receiving the server's close_notify.
            pass
        except (OSError, ValueError) as error:
            peers.record(kind='fixture-error', error=f'Session peer {port}: {error}')
        finally:
            connection.close()
            peers.record(kind='session-peer', port=port, established=established,
                         received=len(received), exact=received == expected, sent=sent)


def session_accounting(events):
    sessions = [event for event in events if event['kind'] == 'session-peer']
    if sorted(event['port'] for event in sessions) != list(range(8450, 8456)):
        return False
    for event in sessions:
        port = event['port']
        if port == 8450:
            if event['established'] or event['received'] or event['sent']:
                return False
        elif port == 8451:
            if not event['established'] or event['received'] or event['sent']:
                return False
        elif not event['established'] or not event['exact']:
            return False
        if port in (8453, 8455) and event['sent'] != 1025:
            return False
    return True
