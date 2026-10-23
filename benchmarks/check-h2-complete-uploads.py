#!/usr/bin/env python3
"""Independent hyper-h2 oracle for complete uploads, flow credit and reconnects.

Every DATA byte is compared to a nonconstant body. No success is returned until
END_STREAM, exact content length and full payload have been checked. Cleartext
runs also reconcile shb's send count with the complete received TCP stream.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time

import h2.config
import h2.connection
import h2.events
import h2.settings


def log_lines(path):
    # A regular-file read can end in the middle of a concurrent stderr write.
    # Parse only newline-terminated records; malformed complete records still fail.
    data = path.read_text()
    return data[:data.rfind('\n') + 1].splitlines()


def run_case(shb, directory, name, length, parallel=8, connections=2,
             count=16, window=4194304, max_frame=16384, reconnect=False,
             tls=False, change_settings=False):
    body = bytes(33 + i % 90 for i in range(length))
    body_file = directory / (name + '.body')
    body_file.write_bytes(body)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(32)
    listener.settimeout(0.1)
    port = listener.getsockname()[1]
    stop = threading.Event()
    failures, ledgers, threads = [], [], []
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / 'cert.pem', directory / 'key.pem')
        context.set_alpn_protocols(['h2'])

    def serve(raw):
        state = dict(requests=0, ends=0, body_bytes=0, received=0,
                     sent=0, teardown=0, frames=0, settings_changed=False)
        ledgers.append(state)
        try:
            raw.settimeout(15)
            conn = context.wrap_socket(raw, server_side=True) if tls else raw
            with conn:
                if tls:
                    assert conn.selected_alpn_protocol() == 'h2'
                h = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
                h.initiate_connection()
                h.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: window,
                                   h2.settings.SettingCodes.MAX_FRAME_SIZE: max_frame})
                h.increment_flow_control_window(32 * 1048576)
                closing = False
                bodies = {}
                wire = bytearray()
                preface = True
                while True:
                    pending = h.data_to_send()
                    if pending:
                        conn.sendall(pending)
                        state['sent'] += len(pending)
                    data = conn.recv(32768)
                    if not data:
                        break
                    state['received'] += len(data)
                    wire.extend(data)
                    if preface and len(wire) >= 24:
                        assert wire[:24] == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                        del wire[:24]
                        preface = False
                    while not preface and len(wire) >= 9:
                        size = int.from_bytes(wire[:3], 'big')
                        if len(wire) < size + 9:
                            break
                        if wire[3] == 7:
                            assert bytes(wire[:17]) == b'\x00\x00\x08\x07' + b'\x00' * 13
                            state['teardown'] += 17
                        state['frames'] += 1
                        del wire[:size + 9]
                    if closing:
                        continue
                    for event in h.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            headers = dict(event.headers)
                            assert headers[b':method'] == b'POST'
                            assert headers[b':path'] == b'/upload'
                            assert headers[b':scheme'] == (b'https' if tls else b'http')
                            assert headers[b'content-length'] == str(length).encode()
                            assert event.stream_id not in bodies
                            bodies[event.stream_id] = 0
                            state['requests'] += 1
                        elif isinstance(event, h2.events.DataReceived):
                            off = bodies[event.stream_id]
                            assert event.data == body[off:off + len(event.data)]
                            bodies[event.stream_id] += len(event.data)
                            state['body_bytes'] += len(event.data)
                            h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                            if change_settings and not state['settings_changed']:
                                h.update_settings({h2.settings.SettingCodes.MAX_FRAME_SIZE: 65536})
                                state['settings_changed'] = True
                        elif isinstance(event, h2.events.StreamEnded):
                            assert bodies.pop(event.stream_id) == length
                            state['ends'] += 1
                            h.send_headers(event.stream_id, [(b':status', b'200'),
                                                           (b'content-length', b'0')], end_stream=True)
                            if reconnect:
                                h.close_connection(last_stream_id=event.stream_id)
                                closing = True
                assert not wire and not preface
                assert not bodies, bodies
                assert state['ends'] == state['requests']
                if not reconnect:
                    assert state['teardown'] == 17
        except BaseException as exc:
            failures.append(repr(exc))
        finally:
            raw.close()

    def accept():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(target=serve, args=(conn,), daemon=True)
            threads.append(thread)
            thread.start()

    accepter = threading.Thread(target=accept, daemon=True)
    accepter.start()
    command = [str(shb), '--http2', '-n', str(count), '-c', str(connections),
               '-p', str(parallel), '-t', '1', '--timeout', '10s', '-j',
               '-d', '@' + str(body_file),
               f'{"https" if tls else "http"}://127.0.0.1:{port}/upload']
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    finally:
        stop.set()
        accepter.join(5)
        listener.close()
        for thread in threads:
            thread.join(20)
    assert all(not t.is_alive() for t in [accepter, *threads]), name
    assert not failures, (name, failures)
    assert result.returncode == 0, (name, result.stderr)
    report = json.loads(result.stdout)
    assert report['requests']['ok'] == count, (name, report)
    assert report['requests']['errors'] == report['requests']['connectErrors'] == 0
    assert report['statusCodes'] == {'200': count}
    assert sum(s['ends'] for s in ledgers) == count
    assert sum(s['body_bytes'] for s in ledgers) == count * length
    if not tls:
        assert report['bytesSent'] == sum(s['received'] - s['teardown'] for s in ledgers), (name, report, ledgers)
    if reconnect:
        assert len(ledgers) >= count
    if change_settings:
        assert all(s['settings_changed'] for s in ledgers)
    return dict(name=name, body_sha256=hashlib.sha256(body).hexdigest(),
                command=command, connections=ledgers, report=report)


def native_case(peer, directory, name, tls=None):
    """Use Python SSL + hyper-h2 to certify the native peer and its ledgers."""
    concurrent = name in ('concurrent', 'aborted-streams')
    length = 16384 if concurrent else 1048576
    connections, streams = (8, 8) if concurrent else (1, 1)
    expected = bytes(33 + i % 90 for i in range(length))
    stem = f'native-{tls or "clear"}-{name}'
    body_path = directory / (stem + '.body')
    body_path.write_bytes(expected)
    payload = bytearray(expected)
    if name == 'bad-payload':
        payload[0] ^= 1
    if name in ('truncated', 'truncated-frame'):
        payload.pop()
    command = [str(peer), '0', str(body_path)]
    if tls:
        command += ['--tls', tls, '--cert', str(directory / 'cert.pem'),
                    '--key', str(directory / 'key.pem')]
    log_path = directory / (stem + '.log')
    results, failures = [], []
    barrier = threading.Barrier(connections)
    with log_path.open('x') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert process.poll() is None, log_path.read_text()
                ready = [line for line in log_lines(log_path)
                         if line.startswith('READY ')]
                if ready:
                    port = int(ready[0].split()[1])
                    assert port != 0
                    break
                assert time.monotonic() < deadline, 'native peer readiness'
                time.sleep(0.01)

            def client():
                try:
                    context = None
                    if tls:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        version = (ssl.TLSVersion.TLSv1_2 if tls == 'tls12'
                                   else ssl.TLSVersion.TLSv1_3)
                        context.minimum_version = context.maximum_version = version
                        context.set_alpn_protocols(['h2'])
                    with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
                        conn = context.wrap_socket(raw, server_hostname='localhost') if tls else raw
                        with conn:
                            if tls:
                                assert conn.selected_alpn_protocol() == 'h2'
                                assert conn.version() == ('TLSv1.2' if tls == 'tls12' else 'TLSv1.3')
                            barrier.wait(timeout=10)
                            h = h2.connection.H2Connection()
                            h.initiate_connection()
                            ids = list(range(1, streams * 2, 2))
                            for sid in ids:
                                h.send_headers(sid, [(':method', 'POST'),
                                    (':scheme', 'https' if tls else 'http'),
                                    (':authority', f'127.0.0.1:{port}'), (':path', '/upload'),
                                    ('content-length', str(length))])
                            conn.sendall(h.data_to_send())
                            statuses, resets, ends, pings = {}, [], [], []
                            response = {sid: bytearray() for sid in ids}

                            def receive():
                                data = conn.recv(65536)
                                assert data, 'peer closed before reporting its result'
                                for event in h.receive_data(data):
                                    if isinstance(event, h2.events.ResponseReceived):
                                        assert event.stream_id not in statuses
                                        headers = dict(event.headers)
                                        assert headers[b'content-length'] == b'13'
                                        statuses[event.stream_id] = headers[b':status']
                                    elif isinstance(event, h2.events.DataReceived):
                                        response[event.stream_id].extend(event.data)
                                        h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                                    elif isinstance(event, h2.events.StreamEnded):
                                        ends.append(event.stream_id)
                                    elif isinstance(event, h2.events.StreamReset):
                                        resets.append(event.stream_id)
                                    elif isinstance(event, h2.events.PingAckReceived):
                                        pings.append(event.ping_data)
                                pending = h.data_to_send()
                                if pending:
                                    conn.sendall(pending)

                            while (h.outbound_flow_control_window < len(payload) * streams
                                   or any(h.local_flow_control_window(sid) < len(payload) for sid in ids)):
                                receive()
                            for sid in ids:
                                for at in range(0, len(payload), h.max_outbound_frame_size):
                                    h.send_data(sid, payload[at:at + h.max_outbound_frame_size])
                            # PING is an ordering fence, not a timing-based absence check.
                            h.ping(b'endcheck')
                            conn.sendall(h.data_to_send())
                            while b'endcheck' not in pings:
                                receive()
                            assert not statuses and not ends, 'peer answered before END_STREAM'
                            if name == 'truncated-frame':
                                # Declare one last DATA byte with END_STREAM, then close
                                # after its header. The final payload byte never arrives.
                                conn.sendall(b'\x00\x00\x01\x00\x01\x00\x00\x00\x01')
                            elif name != 'aborted-streams':
                                for sid in ids:
                                    if sid not in resets:
                                        h.send_data(sid, b'', end_stream=True)
                                wire = h.data_to_send()
                                if name == 'split-end-frame':
                                    for piece in (wire[:3], wire[3:8], wire[8:]):
                                        conn.sendall(piece)
                                elif wire:
                                    conn.sendall(wire)
                                while len(ends) + len(resets) < streams:
                                    receive()
                                if name in ('complete', 'concurrent', 'split-end-frame'):
                                    assert statuses == {sid: b'200' for sid in ids}
                                    assert sorted(ends) == ids and not resets
                                    assert all(bytes(response[sid]) == b'Hello, World!' for sid in ids)
                                else:
                                    assert sorted(resets) == ids and not statuses and not ends
                                h.close_connection()
                                conn.sendall(h.data_to_send())
                            results.append(dict(ends=ends, resets=resets,
                                                response_bytes=sum(map(len, response.values()))))
                except BaseException as exc:
                    failures.append(repr(exc))
                    barrier.abort()

            threads = [threading.Thread(target=client, daemon=True) for _ in range(connections)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(30)
            assert all(not thread.is_alive() for thread in threads), stem
            assert not failures, (stem, failures, log_path.read_text())
            # Do not kill the process before the per-connection tasks retire.
            deadline = time.monotonic() + 10
            while True:
                output = log_path.read_text()
                ledgers = [json.loads(line[7:]) for line in log_lines(log_path)
                           if line.startswith('LEDGER ')]
                if len(ledgers) == connections:
                    break
                assert process.poll() is None and time.monotonic() < deadline, output
                time.sleep(0.01)
            successful = name in ('complete', 'concurrent', 'split-end-frame')
            assert len({r['connection'] for r in ledgers}) == connections
            for ledger in ledgers:
                assert ledger['requests'] == (streams if successful else 0), ledger
                assert ledger['body_bytes'] == (streams * length if successful else 0), ledger
                assert ledger['pending'] == 0, ledger
                assert ledger['rejected'] == (0 if successful else streams), ledger
            assert 'panicked' not in output, output
            if name == 'bad-payload':
                assert 'request DATA differs' in output, output
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return dict(name=stem, payload_bytes=len(payload), connections=ledgers,
                results=results, command=command,
                body_sha256=hashlib.sha256(expected).hexdigest())


def native_tls_rejection(peer, directory, tls, fault):
    """Reject a wrong TLS version or an absent/incompatible ALPN protocol."""
    body = directory / 'rejection.body'
    body.write_bytes(b'x')
    command = [str(peer), '0', str(body), '--tls', tls,
               '--cert', str(directory / 'cert.pem'), '--key', str(directory / 'key.pem')]
    log_path = directory / f'{tls}-{fault}.log'
    with log_path.open('x') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                ready = [line for line in log_lines(log_path) if line.startswith('READY ')]
                if ready:
                    port = int(ready[0].split()[1])
                    break
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            version = ssl.TLSVersion.TLSv1_2 if tls == 'tls12' else ssl.TLSVersion.TLSv1_3
            if fault == 'wrong-version':
                version = ssl.TLSVersion.TLSv1_3 if tls == 'tls12' else ssl.TLSVersion.TLSv1_2
            context.minimum_version = context.maximum_version = version
            if fault != 'no-alpn':
                context.set_alpn_protocols(['http/1.1' if fault == 'wrong-alpn' else 'h2'])
            rejected = False
            with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                try:
                    with context.wrap_socket(raw, server_hostname='localhost') as conn:
                        # TLS with no ALPN can finish, but H2 must not start.
                        rejected = conn.recv(1) == b''
                except (ssl.SSLError, ConnectionResetError):
                    rejected = True
            assert rejected, (tls, fault)
            while 'TLS_ERROR' not in log_path.read_text():
                assert time.monotonic() < deadline
                time.sleep(0.01)
            assert 'LEDGER ' not in log_path.read_text()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return dict(tls=tls, fault=fault, rejected=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', type=Path, required=True)
    parser.add_argument('--peer', type=Path, help='also verify the h2-upload-server example')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='shb-h2-uploads-') as tmp:
        directory = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(directory / 'key.pem'), '-out', str(directory / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost'], capture_output=True, check=True)
        cases = [
            ('below-threshold', 16383, {}),
            ('16k', 16384, {}),
            ('1m', 1048576, {}),
            ('1m-64k-frames', 1048576, dict(max_frame=65536)),
            ('1m-setting-change', 1048576, dict(change_settings=True)),
            ('1m-small-credit', 1048576, dict(window=3072, count=8)),
            ('1m-goaway', 1048576, dict(reconnect=True, parallel=1, connections=1, count=8)),
            ('tls-16k', 16384, dict(tls=True)),
            ('tls-1m', 1048576, dict(tls=True)),
        ]
        native = [native_case(args.peer.resolve(), directory, name, tls)
                  for tls in [None, 'tls12', 'tls13']
                  for name in ['complete', 'bad-payload', 'truncated', 'split-end-frame',
                               'truncated-frame', 'concurrent', 'aborted-streams']] if args.peer else []
        tls_rejections = [native_tls_rejection(args.peer.resolve(), directory, tls, fault)
                          for tls in ['tls12', 'tls13']
                          for fault in ['wrong-version', 'wrong-alpn', 'no-alpn']] if args.peer else []
        records = []
        for name, size, options in cases:
            records.append(run_case(args.shb.resolve(), directory, name, size, **options))
        print(json.dumps(dict(h2_version=h2.__version__, binary_sha256=hashlib.sha256(args.shb.read_bytes()).hexdigest(), cases=records, native=native, tls_rejections=tls_rejections), indent=2))


if __name__ == '__main__':
    main()
