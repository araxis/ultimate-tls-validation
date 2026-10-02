"""Mutate authenticated TLS records and independently account for their bytes."""
import socket
from record_peer import RecordConnection, record_context

MODES = ('type', 'version', 'empty', 'oversized', 'nonce', 'ciphertext', 'tag', 'replay')


def fault_bytes(record, mode):
    wire = bytearray(record)
    if mode == 'type':
        wire[0] = 255
    elif mode == 'version':
        wire[1] = 4
    elif mode == 'empty':
        wire[3:5] = b'\0\0'
    elif mode == 'oversized':
        wire[3:5] = b'\xff\xff'
    elif mode in ('nonce', 'ciphertext', 'tag'):
        wire[{'nonce': 5, 'ciphertext': 13, 'tag': len(record) - 1}[mode]] ^= 1
    elif mode == 'replay':
        return record * 2
    else:
        raise ValueError('Unknown record fault')
    return bytes(wire[:5] if mode in MODES[:4] else wire)


def serve_record_fault(peers, listener, mode):
    context = record_context(peers)
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        with connection:
            connection.settimeout(4)
            stream = RecordConnection(connection, context)
            try:
                stream.handshake_marker()
                record = stream.record(b'authenticated-one')
                if len(record) != 46:
                    raise ValueError('Expected 5-byte header, 8-byte nonce, 17-byte body and 16-byte tag')
                wire = fault_bytes(record, mode)
                connection.sendall(wire)
                # Keep TCP open. A missing advertised body must be rejected
                # from its header, rather than timing out or observing EOF.
                reply = bytearray()
                closed = 'fin'
                try:
                    while True:
                        data = connection.recv(512)
                        if not data:
                            break
                        reply.extend(data)
                        if len(reply) > 1024:
                            raise ValueError('Unexpected traffic after rejected record')
                except ConnectionResetError:
                    closed = 'reset'
                peers.record(kind='record-fault', mode=mode, original=record.hex(), wire=wire.hex(),
                             closure=closed, reply_bytes=len(reply), protocol=stream.stream.version(),
                             cipher=stream.stream.cipher()[0])
            except (OSError, ValueError) as error:
                peers.record(kind='fixture-error', error=f'record-fault {mode}: {error}')


def record_fault_accounting(events):
    cases = [event for event in events if event['kind'] == 'record-fault']
    # Separate listener threads may record closure in a different order.
    if len(cases) != len(MODES) or {event['mode'] for event in cases} != set(MODES):
        return False
    for event in cases:
        original, wire = bytes.fromhex(event['original']), bytes.fromhex(event['wire'])
        mode = event['mode']
        if (len(original) != 46 or original[:5] != b'\x17\x03\x03\0)'
                or event['protocol'] != 'TLSv1.2' or event['cipher'] != 'ECDHE-RSA-AES128-GCM-SHA256'
                or event['closure'] not in ('fin', 'reset')):
            return False
        # Check recorded mutations independently of the construction helper.
        if mode in MODES[:4]:
            headers = {'type': b'\xff\x03\x03\0)', 'version': b'\x17\x04\x03\0)',
                       'empty': b'\x17\x03\x03\0\0', 'oversized': b'\x17\x03\x03\xff\xff'}
            if wire != headers[mode]:
                return False
        elif mode == 'replay':
            if wire != original + original:
                return False
        else:
            offset = {'nonce': 5, 'ciphertext': 13, 'tag': 45}[mode]
            if len(wire) != 46 or [a ^ b for a, b in zip(original, wire)] != [int(i == offset) for i in range(46)]:
                return False
    return True
