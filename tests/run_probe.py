"""Bounded local DNS/TLS fixtures with independent request and SNI accounting."""
import argparse
import array
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import re
import select
import socket
import ssl
import struct
import subprocess
import threading
import termios
import time
from session_peers import serve_sessions, session_accounting
from security_peers import make_dated_certificates, serve_closure

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = '192.0.2.1'
REQUEST = b'GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n'
RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nlwip-ok\n'


def make_certificate(directory, name):
    def openssl(*arguments):
        subprocess.run(['openssl', *arguments], cwd=directory, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
            '-subj', f'/CN={name} test root', '-keyout', f'{name}-ca.key',
            '-out', f'{name}-ca.pem', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=tls.lab.test',
            '-keyout', f'{name}.key', '-out', f'{name}.csr')
    extension = directory / f'{name}.ext'
    extension.write_text('subjectAltName=DNS:tls.lab.test\nbasicConstraints=critical,CA:FALSE\n'
                         'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', f'{name}.csr', '-CA', f'{name}-ca.pem',
            '-CAkey', f'{name}-ca.key', '-CAcreateserial', '-days', '2',
            '-out', f'{name}.pem', '-extfile', str(extension))


class Peers:
    def __init__(self, directory):
        self.directory = directory
        self.stop = threading.Event()
        self.events = []
        self.lock = threading.Lock()
        self.sockets = []
        self.threads = []

    def record(self, **event):
        with self.lock:
            self.events.append(event)

    def listen(self, kind, port, target, *arguments, receive_buffer=None):
        listener = socket.socket(socket.AF_INET, kind)
        self.sockets.append(listener)
        if kind == socket.SOCK_STREAM:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if receive_buffer is not None:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        listener.bind((ADDRESS, port))
        listener.settimeout(0.2)
        if kind == socket.SOCK_STREAM:
            listener.listen(4)
        thread = threading.Thread(target=target, args=(listener, *arguments))
        self.threads.append(thread)
        thread.start()

    def dns(self, listener):
        pending = []
        listener.settimeout(0.02)
        while not self.stop.is_set():
            now = time.monotonic()
            for due, response, peer in pending[:]:
                if now >= due:
                    listener.sendto(response, peer)
                    self.record(kind='dns-late-reply')
                    pending.remove((due, response, peer))
            try:
                packet, peer = listener.recvfrom(512)
            except socket.timeout:
                continue
            try:
                offset, labels = 12, []
                while packet[offset]:
                    length = packet[offset]
                    if length > 63:
                        raise ValueError('compressed/invalid query')
                    labels.append(packet[offset + 1:offset + 1 + length].decode('ascii'))
                    offset += length + 1
                end = offset + 5
                query_type, query_class = struct.unpack('!HH', packet[offset + 1:end])
                name = '.'.join(labels)
                if name in ('silent.lab.test', 'cancel.lab.test') or re.fullmatch(r'pool-\d+\.lab\.test', name):
                    self.record(kind='dns-drop', name=name)
                    continue
                accepted = name in ('tls.lab.test', 'wrong.lab.test', 'late.lab.test') and query_type == 1 and query_class == 1
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ADDRESS) if accepted else b''
                header = packet[:2] + struct.pack('!HHHHH', 0x8180 if accepted else 0x8183, 1, int(accepted), 0, 0)
                response = header + packet[12:end] + answer
                if name == 'late.lab.test':
                    pending.append((time.monotonic() + 0.6, response, peer))
                else:
                    listener.sendto(response, peer)
                self.record(kind='dns', name=name, accepted=accepted)
            except (ValueError, IndexError, struct.error) as error:
                self.record(kind='fixture-error', error=str(error))

    def handshake_stall(self, listener):
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(6)
                self.record(kind='stall', phase='handshake')
                try:
                    while connection.recv(4096):
                        pass
                except ConnectionResetError:
                    pass
                except OSError as error:
                    self.record(kind='fixture-error', error=str(error))

    def tls(self, listener, name, stall=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
        key_name = 'trusted' if name in ('expired', 'future') else name
        context.load_cert_chain(self.directory / f'{name}.pem', self.directory / f'{key_name}.key')
        context.set_servername_callback(lambda stream, host, config: self.record(kind='sni', name=host, server=name))
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            connection.settimeout(6)
            try:
                with context.wrap_socket(connection, server_side=True) as stream:
                    request = b''
                    while b'\r\n\r\n' not in request and len(request) < 2048:
                        chunk = stream.recv(512)
                        if not chunk:
                            break
                        request += chunk
                    self.record(kind='request', server=name, exact=request == REQUEST,
                                protocol=stream.version(), cipher=stream.cipher()[0])
                    if request != REQUEST:
                        raise ValueError('unexpected HTTP request')
                    if stall:
                        self.record(kind='stall', phase='read')
                        try:
                            stream.recv(1)
                        except (ConnectionResetError, ssl.SSLEOFError):
                            pass
                        continue
                    # Several TLS records exercise stream assembly.
                    for offset in range(0, len(RESPONSE), 7):
                        stream.sendall(RESPONSE[offset:offset + 7])
                    try:
                        stream.unwrap().close()
                    except (ssl.SSLEOFError, ConnectionResetError):
                        # The client receives close_notify, then releases TCP.
                        pass
            except ssl.SSLError as error:
                self.record(kind='tls-alert', server=name, reason=error.reason)
            except (OSError, ValueError) as error:
                self.record(kind='fixture-error', error=str(error))
            finally:
                connection.close()

    def write_stall(self, listener):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
        context.load_cert_chain(self.directory / 'trusted.pem', self.directory / 'trusted.key')
        context.set_servername_callback(lambda stream, host, config: self.record(kind='sni', name=host, server='trusted'))
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            connection.settimeout(6)
            try:
                with context.wrap_socket(connection, server_side=True) as stream:
                    stream.sendall(b'\x01')
                    poller = select.poll()
                    closed_flags = select.POLLERR | select.POLLHUP | select.POLLRDHUP
                    poller.register(stream.fileno(), closed_flags)
                    peak, closed = 0, False
                    deadline = time.monotonic() + 6
                    # Inspect unread ciphertext without consuming application data.
                    while time.monotonic() < deadline:
                        unread = array.array('i', [0])
                        fcntl.ioctl(stream.fileno(), termios.FIONREAD, unread, True)
                        peak = max(peak, unread[0])
                        if any(flags & closed_flags for _, flags in poller.poll(10)):
                            closed = True
                            break
                    self.record(kind='write-stall', queued_bytes_peak=peak, closed=closed)
            except (OSError, ValueError) as error:
                self.record(kind='fixture-error', error=str(error))
            finally:
                connection.close()

    def start(self, connections=False, sessions=False, security=False):
        if security:
            self.listen(socket.SOCK_STREAM, 8456, self.tls, 'expired')
            self.listen(socket.SOCK_STREAM, 8457, self.tls, 'future')
            for port, mode in ((8458, 'handshake-eof'), (8459, 'unclean-eof'), (8460, 'reset')):
                self.listen(socket.SOCK_STREAM, port,
                            lambda listener, mode: serve_closure(self, listener, mode), mode)
        if sessions:
            for port in range(8450, 8456):
                self.listen(socket.SOCK_STREAM, port,
                            lambda listener, port: serve_sessions(self, listener, port), port)
        if connections:
            # Reserve both ports without listen(): the kernel refuses any SYN
            # that reaches these sockets. No other process can claim the ports.
            for port in (8448, 8449):
                reserved = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sockets.append(reserved)
                reserved.bind((ADDRESS, port))
                self.record(kind='reserved-port', port=port,
                            listening=bool(reserved.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)))
        self.listen(socket.SOCK_DGRAM, 1053, self.dns)
        self.listen(socket.SOCK_STREAM, 8443, self.tls, 'trusted')
        self.listen(socket.SOCK_STREAM, 8444, self.tls, 'untrusted')
        self.listen(socket.SOCK_STREAM, 8445, self.handshake_stall)
        self.listen(socket.SOCK_STREAM, 8446, self.tls, 'trusted', True)
        self.listen(socket.SOCK_STREAM, 8447, self.write_stall, receive_buffer=4096)

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=8)
        for listener in self.sockets:
            listener.close()
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError('Fixture thread did not exit')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'build/tls_probe')
    suites = parser.add_mutually_exclusive_group()
    suites.add_argument('--faults', action='store_true')
    suites.add_argument('--pressure', action='store_true')
    suites.add_argument('--connections', action='store_true')
    suites.add_argument('--sessions', action='store_true')
    suites.add_argument('--security', action='store_true')
    args = parser.parse_args()
    directory = ROOT / 'evidence' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    directory.mkdir(parents=True)
    source_files = [ROOT / name for name in ('CMakeLists.txt', 'dependencies.json', 'README.md', 'LICENSE.txt', '.gitignore')]
    for name in ('src', 'include', 'platform', 'config', 'tests', 'tools'):
        source_files.extend(path for path in (ROOT / name).rglob('*')
                            if path.is_file() and '__pycache__' not in path.parts)
    manifest = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(source_files)}
    (directory / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for name in ('trusted', 'untrusted'):
        make_certificate(directory, name)
    if args.security:
        make_dated_certificates(directory)
    peers = Peers(directory)
    start = time.monotonic()
    returncode, output, failure = None, '', None
    try:
        peers.start(connections=args.connections, sessions=args.sessions, security=args.security)
        command = [str(args.binary.resolve()), 'ult-tls0', str(directory / 'trusted-ca.pem')]
        if args.faults:
            command.append('--faults')
        if args.pressure:
            command.append('--pressure')
        if args.connections:
            command.append('--connections')
        if args.sessions:
            command.append('--sessions')
        if args.security:
            command.append('--security')
        completed = subprocess.run(command,
                                   text=True, capture_output=True, timeout=75)
        returncode = completed.returncode
        output = completed.stdout + completed.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        failure = str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            output = (error.stdout or b'').decode() + (error.stderr or b'').decode()
    finally:
        peers.close()
    (directory / 'probe.log').write_text(output)
    (directory / 'peer-events.json').write_text(json.dumps(peers.events, indent=2) + '\n')
    requests = [event for event in peers.events if event['kind'] == 'request']
    alerts = [event for event in peers.events if event['kind'] == 'tls-alert']
    sni = [event['name'] for event in peers.events if event['kind'] == 'sni']
    dns = {event['name'] for event in peers.events if event['kind'] == 'dns' and event['accepted']}
    summary = re.search(r'SUMMARY checks=(\d+) failures=(\d+) rx=(\d+) tx=(\d+) ticks=(\d+)', output)
    attempts = re.findall(r'^RESULT ([a-z-]+) ', output, re.MULTILINE)
    complete = attempts == ['valid-chain', 'wrong-host', 'recovery-after-host', 'unknown-root',
                            'recovery-after-root', 'missing-time', 'missing-entropy', 'final-recovery']
    peer_ok = (len(requests) == 4 and all(event['exact'] and event['server'] == 'trusted' for event in requests)
               and len(alerts) == 2 and sni == ['tls.lab.test', 'wrong.lab.test', 'tls.lab.test',
                                               'tls.lab.test', 'tls.lab.test', 'tls.lab.test']
               and dns == {'tls.lab.test', 'wrong.lab.test'}
               and not any(event['kind'] == 'fixture-error' for event in peers.events))
    expected_checks = 32
    if args.faults:
        complete = attempts == ['dns-timeout', 'dns-cancel', 'dns-late-reply', 'handshake-timeout',
                                'handshake-cancel', 'read-timeout', 'read-cancel', 'dns-recovery']
        dropped = {event['name'] for event in peers.events if event['kind'] == 'dns-drop'}
        stalls = [event['phase'] for event in peers.events if event['kind'] == 'stall']
        peer_ok = (len(requests) == 3 and all(event['exact'] and event['server'] == 'trusted' for event in requests)
                   and not alerts and sni == ['tls.lab.test'] * 3 and dns == {'tls.lab.test', 'late.lab.test'}
                   and stalls == ['handshake', 'handshake', 'read', 'read']
                   and dropped == {'silent.lab.test', 'cancel.lab.test'}
                   and any(event['kind'] == 'dns-late-reply' for event in peers.events)
                   and not any(event['kind'] == 'fixture-error' for event in peers.events))
        expected_checks = 40
    if args.pressure:
        complete = attempts == ['dns-pool-fill'] * 4 + ['dns-pool-full', 'dns-queue-full',
                           'dns-queued-timeout', 'write-timeout', 'write-cancel', 'pressure-recovery']
        dropped = {event['name'] for event in peers.events if event['kind'] == 'dns-drop'}
        queried = {event['name'] for event in peers.events if event['kind'] in ('dns', 'dns-drop')}
        pool_names = {f'pool-{index}.lab.test' for index in range(4)}
        stalls = [event for event in peers.events if event['kind'] == 'write-stall']
        peer_ok = (len(requests) == 1 and requests[0]['exact'] and requests[0]['server'] == 'trusted'
                   and not alerts and sni == ['tls.lab.test'] * 3 and dns == {'tls.lab.test'}
                   and dropped == pool_names and queried == pool_names | {'tls.lab.test'}
                   and len(stalls) == 2 and all(event['queued_bytes_peak'] > 0 and event['closed'] for event in stalls)
                   and not any(event['kind'] == 'fixture-error' for event in peers.events))
        expected_checks = 61
    if args.connections:
        complete = attempts == ['connect-refused', 'connect-timeout', 'connect-cancel', 'connect-recovery']
        reserved = [event for event in peers.events if event['kind'] == 'reserved-port']
        peer_ok = (len(requests) == 1 and requests[0]['exact'] and requests[0]['server'] == 'trusted'
                   and not alerts and sni == ['tls.lab.test'] and dns == {'tls.lab.test'}
                   and [event['port'] for event in reserved] == [8448, 8449]
                   and all(not event['listening'] for event in reserved)
                   and not any(event['kind'] == 'fixture-error' for event in peers.events))
        expected_checks = 42
    if args.sessions:
        complete = (attempts[:5] == ['cancel-before-open', 'cancel-after-open', 'cancel-after-write',
                                    'cancel-after-read', 'short-transfer']
                    and sorted(attempts[5:7]) == ['concurrent-cancel', 'concurrent-success']
                    and attempts[7:] == ['sessions-recovery'])
        peer_ok = (len(requests) == 1 and requests[0]['exact'] and requests[0]['server'] == 'trusted'
                   and not alerts and sni == ['tls.lab.test'] * 6 and dns == {'tls.lab.test'}
                   and session_accounting(peers.events)
                   and not any(event['kind'] == 'fixture-error' for event in peers.events))
        expected_checks = 63
    if args.security:
        complete = attempts == ['expired-certificate', 'future-certificate', 'handshake-eof',
                                'unclean-eof', 'peer-reset', 'security-recovery']
        closures = [event for event in peers.events if event['kind'] == 'closure']
        peer_ok = (len(requests) == 1 and requests[0]['exact'] and requests[0]['server'] == 'trusted'
                   and [event['server'] for event in alerts] == ['expired', 'future']
                   and sni == ['tls.lab.test'] * 5 and dns == {'tls.lab.test'}
                   and [event['mode'] for event in closures] == ['handshake-eof', 'unclean-eof', 'reset']
                   and [event['sent'] for event in closures] == [0, 7, 0]
                   and [event['established'] for event in closures] == [False, True, True]
                   and all(event['exact'] for event in closures)
                   and not any(event['kind'] == 'fixture-error' for event in peers.events))
        expected_checks = 44
    passed = (returncode == 0 and summary is not None and int(summary[1]) == expected_checks and int(summary[2]) == 0
              and all(int(summary[index]) > 0 for index in (3, 4, 5))
              and complete and peer_ok and failure is None)
    report = {'passed': passed, 'returncode': returncode, 'failure': failure,
              'suite': 'security' if args.security else 'sessions' if args.sessions else 'connections' if args.connections else 'pressure' if args.pressure else 'wait-faults' if args.faults else 'baseline',
              'elapsed_seconds': time.monotonic() - start, 'peer_accounting_passed': peer_ok,
              'complete_attempts': complete,
              'checks': int(summary[1]) if summary else None,
              'dependencies': json.loads((ROOT / 'dependencies.json').read_text()),
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest()}
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(output)
    print(json.dumps(report, indent=2))
    print(f'Evidence: {directory}')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
