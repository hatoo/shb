#!/usr/bin/env python3
"""Independent H2 upload rearming after complete and refused stream cohorts."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

import h2.config
import h2.connection
import h2.events
import h2.settings

from report_accounting import validate_sample_accounting


def exercise(binary, directory, tls, refuse):
    body = bytes(33 + i % 90 for i in range(1024))
    body_file = directory / 'body'
    body_file.write_bytes(body)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    result = dict(tls=tls, refuse=refuse, starts=[], ends=[], refused=[], barriers=[], body_bytes=0)
    failures = []

    def peer():
        try:
            raw, _ = listener.accept()
            raw.settimeout(10)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(directory / 'cert.pem', directory / 'key.pem')
                context.set_alpn_protocols(['h2'])
                raw = context.wrap_socket(raw, server_side=True)
                assert raw.selected_alpn_protocol() == 'h2'
            with raw:
                conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding='utf-8'))
                conn.initiate_connection()
                conn.update_settings({h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 8})
                bodies = {}
                allowed = set(range(1, 16, 2))

                def flush():
                    wire = conn.data_to_send()
                    if wire:
                        raw.sendall(wire)

                def receive():
                    wire = raw.recv(65536)
                    assert wire, 'client closed before all expected uploads'
                    events = conn.receive_data(wire)
                    for event in events:
                        if isinstance(event, h2.events.RequestReceived):
                            headers = dict(event.headers)
                            assert headers[':method'] == 'POST'
                            assert headers[':path'] == '/rearm'
                            assert headers['content-length'] == str(len(body))
                            assert event.stream_id not in bodies
                            bodies[event.stream_id] = bytearray()
                            result['starts'].append(event.stream_id)
                        elif isinstance(event, h2.events.DataReceived):
                            assert event.stream_id in allowed, 'DATA sent before stream credit'
                            assert event.stream_id not in result['ends'], 'DATA after END_STREAM'
                            data = bodies[event.stream_id]
                            offset = len(data)
                            assert event.data == body[offset:offset + len(event.data)]
                            assert offset + len(event.data) <= len(body)
                            data.extend(event.data)
                            result['body_bytes'] += len(event.data)
                        elif isinstance(event, h2.events.StreamEnded):
                            assert event.stream_id not in result['ends']
                            assert bodies[event.stream_id] == body
                            result['ends'].append(event.stream_id)
                    flush()
                    return events

                def barrier(token):
                    conn.ping(token)
                    flush()
                    while True:
                        events = receive()
                        if any(isinstance(e, h2.events.PingAckReceived) and e.ping_data == token for e in events):
                            result['barriers'].append(token.decode())
                            return

                flush()
                while len(result['ends']) < 8:
                    receive()
                assert set(result['ends']) == set(range(1, 16, 2))
                # The first generation is fully sent. Fence the zero initial
                # stream window before responses allow the next generation.
                conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
                barrier(b'all-sent')
                allowed.clear()
                for stream in reversed(result['ends']):
                    conn.send_headers(stream, [(':status', '200')], end_stream=True)
                flush()
                while len(result['starts']) < 16:
                    receive()
                blocked = list(range(17, 32, 2))
                assert result['starts'] == list(range(1, 32, 2))
                conn.increment_flow_control_window(65535)
                barrier(b'connonly')
                assert all(not bodies[s] for s in blocked)
                if refuse:
                    # Every pending body is retired; retries open a third
                    # generation with the same zero initial stream window.
                    for stream in blocked:
                        conn.reset_stream(stream, error_code=7)
                        result['refused'].append(stream)
                    flush()
                    while len(result['starts']) < 24:
                        receive()
                    blocked = list(range(33, 48, 2))
                    assert result['starts'] == list(range(1, 48, 2))
                    barrier(b'retries!')
                    assert all(not bodies[s] for s in blocked)
                allowed.update(blocked)
                for stream in reversed(blocked):
                    conn.increment_flow_control_window(len(body), stream_id=stream)
                flush()
                while len(result['ends']) < 16:
                    receive()
                assert set(result['ends']) == set(range(1, 16, 2)) | set(blocked)
                for stream in reversed(blocked):
                    conn.send_headers(stream, [(':status', '200')], end_stream=True)
                flush()
                while True:
                    try:
                        wire = raw.recv(65536)
                    except (ConnectionResetError, ssl.SSLEOFError):
                        break
                    if not wire:
                        break
                    events = conn.receive_data(wire)
                    assert not any(isinstance(e, (h2.events.RequestReceived, h2.events.DataReceived, h2.events.StreamEnded)) for e in events), events
                assert result['body_bytes'] == 16 * len(body)
                assert all(not bodies[s] for s in result['refused'])
                result['pending'] = sum(s not in result['ends'] and s not in result['refused'] for s in bodies)
                assert result['pending'] == 0
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=peer, daemon=True)
    thread.start()
    command = [str(binary), '--http2', '-j', '-c', '1', '-p', '8', '-t', '1',
               '-n', '16', '--timeout', '10s', '-d', '@' + str(body_file),
               f'{"https" if tls else "http"}://127.0.0.1:{port}/rearm']
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=30)
    finally:
        thread.join(timeout=15)
        listener.close()
    assert not thread.is_alive(), 'peer did not drain'
    if failures:
        raise failures[0]
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    validate_sample_accounting(report)
    assert report['requests'] == dict(ok=16, errors=0, connectErrors=0, total=16)
    assert report['statusCodes'] == {'200': 16}
    result.update(command=command, report=report, stderr=run.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.shb.resolve()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='h2-body-scheduling-') as tmp:
        directory = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(directory / 'key.pem'), '-out', str(directory / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost'], capture_output=True, check=True)
        rows = [exercise(binary, directory, tls, refuse)
                for tls in [False, True] for refuse in [False, True]]
    assert digest == hashlib.sha256(binary.read_bytes()).hexdigest()
    with args.output.open('x') as output:
        json.dump(dict(binary=str(binary), sha256=digest, h2_version=h2.__version__, cases=rows), output, indent=2)
        output.write('\n')
    print('PASS: four rearming cases, 64 completions and exact latency samples')


if __name__ == '__main__':
    main()
