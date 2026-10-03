"""Controlled authenticated stall and independent two-task session accounting."""
from collections import Counter
import re
import socket
import ssl
from run_probe import REQUEST

CHECKS = 38


def stalled_session(peers, listener):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.load_cert_chain(peers.directory / 'trusted.pem', peers.directory / 'trusted.key')
    context.set_servername_callback(lambda stream, host, config: peers.record(kind='sni',name=host,server='cancel'))
    while not peers.stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        try:
            connection.settimeout(6)
            with context.wrap_socket(connection,server_side=True) as stream:
                protocol, cipher = stream.version(), stream.cipher()[0]
                request = b''
                while len(request) < len(REQUEST):
                    chunk = stream.recv(len(REQUEST)-len(request))
                    if not chunk:
                        break
                    request += chunk
                if request != REQUEST:
                    raise ValueError('Unexpected stalled-session request')
                stream.sendall(b'\x01')
                try:
                    if stream.recv(1):
                        raise ValueError('Unexpected data after ready marker')
                except (ConnectionResetError,ssl.SSLEOFError):
                    pass
                peers.record(kind='session-stall',exact=True,closed=True,
                             protocol=protocol,cipher=cipher)
        except (OSError,ValueError) as error:
            peers.record(kind='fixture-error',error=str(error))
        finally:
            connection.close()


def account(output,events):
    labels=['sessions-0','session-recovery-0','sessions-1','session-recovery-1']
    rows=re.findall(r'^SESSION_RESULT round=(\d+) cancelled_core=(\d+) survivor_core=(\d+) live=(\d+) '
                    r'remaining=(\d+) latency=(\d+) cancelled=(\d+) survivor=(\d+) sent=(\d+) received=(\d+)\r?$',output,re.M)
    recoveries=re.findall(r'^RESULT session-recovery-(\d+) status=(\d+) stage=(\d+) code=(-?\d+) '
                          r'verify=(\d+) sent=(\d+) received=(\d+) opens=(\d+)\r?$',output,re.M)
    cleanup=re.findall(r'^SESSION_CLEANUP active=(\d+) timewait=(\d+) dns=(\d+) elapsed=(\d+)\r?$',output,re.M)
    complete=(re.findall(r'^ATTEMPT ([a-z0-9-]+)\r?$',output,re.M)==labels and len(rows)==2 and len(recoveries)==2 and
              len(cleanup)==1 and tuple(map(int,cleanup[0][:3]))==(0,0,0) and int(cleanup[0][3])<=137000)
    for i,r in enumerate(rows):
        values=tuple(map(int,r))
        complete=complete and values[:5]==(i,i,1-i,2,1) and values[5]<=250 and values[6:]==(2,0,62,65)
    for i,r in enumerate(recoveries):
        complete=complete and tuple(map(int,r))==(i,0,9,-30848,0,62,65,1)
    sni=[e for e in events if e['kind']=='sni']
    traffic=[e for e in events if e['kind'] in ('request','session-stall')]
    peer_ok=(Counter(e['kind'] for e in events)==Counter(sni=6,request=4,**{'session-stall':2}) and
             Counter(e['server'] for e in sni)==Counter(trusted=4,cancel=2) and
             all(e['name']=='192.0.2.1' for e in sni) and
             all(e['exact'] and e['protocol']=='TLSv1.2' and e['cipher']=='ECDHE-RSA-AES128-GCM-SHA256' for e in traffic) and
             all(e['closed'] for e in traffic if e['kind']=='session-stall'))
    return {'complete_attempts':bool(complete),'peer_accounting_passed':bool(peer_ok),
            'sessions':rows,'recoveries':recoveries,'cleanup':cleanup}
