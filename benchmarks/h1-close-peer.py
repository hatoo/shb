"""Fixed, independent sequential TCP peer: complete 65537-byte body then EOF."""
import argparse, json, os, signal, socket
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--port', type=int, required=True)
p.add_argument('--requests', type=int, required=True)
p.add_argument('--ledger', type=Path, required=True)
a = p.parse_args()
os.sched_setaffinity(0, {1})
body = b'x' * 65537
response = b'HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n' + body
requests = 0
received = 0
responses = 0
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', a.port))
    listener.listen(128)
    listener.settimeout(30)
    print('READY', flush=True)
    while requests < a.requests:
        stream, _ = listener.accept()
        stream.settimeout(10)
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with stream:
            request = b''
            while b'\r\n\r\n' not in request:
                part = stream.recv(4096)
                assert part
                request += part
            assert request == f'GET / HTTP/1.1\r\nHost: 127.0.0.1:{a.port}\r\nConnection: close\r\n\r\n'.encode(), request
            received += len(request)
            stream.sendall(response)
            responses += len(response)
            requests += 1
            assert stream.recv(1) == b'', 'extra request/body bytes or missing close'
    a.ledger.open('x').write(json.dumps(dict(requests=requests, accepted=requests, bytes_received=received, bytes_sent=responses, body_size=len(body), response_size=len(response))) + '\n')
    while True:
        signal.pause()
