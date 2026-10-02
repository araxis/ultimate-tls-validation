"""Peers for controlled stream deadline and cancellation completion tests."""
import socket
import ssl
from record_peer import record_context

MODES = ('deadline-open', 'deadline-before-write', 'deadline-after-write',
         'deadline-buffered-read', 'cancel-buffered-read', 'both-buffered-read',
         'deadline-close-notify', 'cancel-close-notify', 'terminal-eof',
         'cumulative-deadline', 'deadline-finished', 'cancel-finished')
DATA_MODES = set(MODES[3:6]) | {'cumulative-deadline'}
CLOSE_MODES = set(MODES[6:9])


def serve_boundary(peers, listener, mode):
    context = record_context(peers)
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        connection.settimeout(4)
        event = dict(kind='boundary-peer', mode=mode, established=False, marker='', sent=0, close_started=False)
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                event['established'] = True
                marker = stream.recv(1)
                event['marker'] = marker.hex()
                if marker == b'!' and mode in DATA_MODES | CLOSE_MODES:
                    if mode in DATA_MODES:
                        stream.sendall(b'boundary-data')
                        event['sent'] = 13
                    event['close_started'] = True
                    stream.unwrap().close()
                elif marker not in (b'', b'!'):
                    raise ValueError('Unexpected boundary marker')
        except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
            pass  # The selected boundary intentionally closes the client socket.
        except (OSError, ValueError) as error:
            peers.record(kind='fixture-error', error=f'boundary {mode}: {error}')
        finally:
            connection.close()
            peers.record(**event)


def boundary_accounting(events):
    cases = [event for event in events if event['kind'] == 'boundary-peer']
    if len(cases) != len(MODES) or {event['mode'] for event in cases} != set(MODES):
        return False
    for event in cases:
        mode = event['mode']
        if event['established'] != (mode != 'deadline-open'):
            return False
        if mode in DATA_MODES | CLOSE_MODES:
            if event['marker'] != '21' or not event['close_started']:
                return False
            if event['sent'] != (13 if mode in DATA_MODES else 0):
                return False
        elif event['sent'] or event['close_started']:
            return False
        elif mode == 'deadline-after-write':
            # An unsuccessful write cannot promise that the peer saw no data.
            if event['marker'] not in ('', '21'):
                return False
        elif event['marker']:
            return False
    return True
