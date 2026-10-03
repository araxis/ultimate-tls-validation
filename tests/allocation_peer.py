"""Dedicated handshake-allocation peer; failed handshakes are expected here only."""
import socket
import ssl


def serve_allocations(peers, listener):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.load_cert_chain(peers.directory / 'trusted.pem', peers.directory / 'trusted.key')
    sequence = 0
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        sequence += 1
        event = dict(kind='allocation-peer', port=listener.getsockname()[1], sequence=sequence,
                     confirmed=False, established=False, sni=None)
        context.set_servername_callback(lambda stream, host, config: event.update(sni=host))
        connection.settimeout(4)
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                event.update(established=True, protocol=stream.version(), cipher=stream.cipher()[0])
                marker = stream.recv(1)
                if marker != b'K':
                    raise ValueError('missing allocation recovery marker')
                stream.sendall(b'Y')
                event['confirmed'] = True
                try:
                    stream.unwrap().close()
                except (ssl.SSLEOFError, ConnectionResetError):
                    pass  # Client reads close_notify, then releases its socket.
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError) as error:
            event['abort'] = type(error).__name__
            event['reason'] = getattr(error, 'reason', str(error))
        except (OSError, ValueError) as error:
            peers.record(kind='fixture-error', error=str(error))
        finally:
            connection.close()
            peers.record(**event)


def allocation_accounting(events, indexes):
    connections = [event for event in events if event['kind'] == 'allocation-peer']
    return (len(connections) == len(indexes)
            and all(event['sequence'] == number and event['confirmed'] == (index == 0)
                    and (index != 0 or event.get('protocol') == 'TLSv1.2'
                         and event.get('cipher') == 'ECDHE-RSA-AES128-GCM-SHA256'
                         and event['sni'] == 'tls.lab.test')
                    and (index == 0 or 'abort' in event)
                    for number, (event, index) in enumerate(zip(connections, indexes), 1)))
