#!/usr/bin/env python3
"""Independent hyper-h2 peer: fragmented/coalesced responses over TCP and TLS.

Run with a Python environment containing h2==4.3.0, hpack==4.1.0 and
hyperframe==6.1.0. Requires openssl and a built shb binary.
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

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded

REQUESTS = 64
PARALLEL = 8
REQUEST_BODY = b"q" * 6001
RESPONSE_BODY = b"r" * 33003
# Low repetition makes the encoded block span HEADERS and CONTINUATION.
LONG_HEADER = "".join(hashlib.sha256(str(n).encode()).hexdigest() for n in range(626))


def exercise(binary, context, fragmented):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(15)
    port = listener.getsockname()[1]
    result = {"tls": context is not None, "fragmented": fragmented,
              "requests": 0, "request_body_bytes": 0, "response_body_bytes": 0,
              "continuations": 0, "application_writes": 0}
    failures = []

    def peer():
        try:
            with listener:
                sock, _ = listener.accept()
            sock.settimeout(15)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if context:
                sock = context.wrap_socket(sock, server_side=True)
                assert sock.selected_alpn_protocol() == "h2"
            with sock:
                conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
                conn.initiate_connection()
                bodies, ready = {}, []
                step = 0

                def flush():
                    nonlocal step
                    wire = conn.data_to_send()
                    offset = 0
                    while offset < len(wire):
                        size = int.from_bytes(wire[offset:offset + 3], "big") + 9
                        assert offset + size <= len(wire)
                        result["continuations"] += int(wire[offset + 3] == 9)
                        offset += size
                    offset = 0
                    while offset < len(wire):
                        size = [1, 8, 9, 53, 16384][step % 5] if fragmented else len(wire)
                        end = min(offset + size, len(wire))
                        sock.sendall(wire[offset:end])
                        result["application_writes"] += 1
                        offset = end
                        step += 1
                        if fragmented and offset < len(wire):
                            time.sleep(0.001)

                flush()
                while result["requests"] < REQUESTS:
                    data = sock.recv(65536)
                    assert data, "client closed before all requests arrived"
                    for event in conn.receive_data(data):
                        if isinstance(event, RequestReceived):
                            headers = dict(event.headers)
                            assert headers[":method"] == "POST" and headers[":path"] == "/fragmentation"
                            bodies[event.stream_id] = bytearray()
                        elif isinstance(event, DataReceived):
                            bodies[event.stream_id].extend(event.data)
                            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        elif isinstance(event, StreamEnded):
                            body = bodies.pop(event.stream_id)
                            assert body == REQUEST_BODY
                            result["request_body_bytes"] += len(body)
                            ready.append(event.stream_id)
                    if len(ready) == PARALLEL:
                        for stream in reversed(ready):
                            status = "200" if ((stream - 1) // 2) % 2 == 0 else "201"
                            conn.send_headers(stream, [(":status", "103"), ("link", "</test>")])
                            conn.send_headers(stream, [(":status", status), ("content-length", str(len(RESPONSE_BODY))), ("x-fragments", LONG_HEADER)])
                            for offset in range(0, len(RESPONSE_BODY), conn.max_outbound_frame_size):
                                end = min(offset + conn.max_outbound_frame_size, len(RESPONSE_BODY))
                                conn.send_data(stream, RESPONSE_BODY[offset:end], end_stream=end == len(RESPONSE_BODY))
                            result["requests"] += 1
                            result["response_body_bytes"] += len(RESPONSE_BODY)
                        ready.clear()
                    flush()
                assert not bodies and not ready
                assert result["continuations"] >= REQUESTS
                # Drain final acknowledgements until the fixed-budget client closes.
                while True:
                    try:
                        if not sock.recv(65536):
                            break
                    except (ConnectionResetError, ssl.SSLEOFError):
                        break
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=peer, daemon=True)
    thread.start()
    command = [str(binary), "-j", "--http2", "-c", "1", "-t", "1", "-p", str(PARALLEL),
               "-n", str(REQUESTS), "--timeout", "10s", "-d", REQUEST_BODY.decode(),
               f'{"https" if context else "http"}://127.0.0.1:{port}/fragmentation']
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=60)
    finally:
        thread.join(timeout=20)
        listener.close()
    assert not thread.is_alive(), "peer did not finish"
    if failures:
        raise failures[0]
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["requests"]["total"] == report["requests"]["ok"] == REQUESTS, report
    assert report["requests"]["errors"] == report["requests"]["connectErrors"] == 0, report
    assert report["statusCodes"] == {"200": REQUESTS // 2, "201": REQUESTS // 2}, report
    assert result["request_body_bytes"] == REQUESTS * len(REQUEST_BODY)
    assert result["response_body_bytes"] == REQUESTS * len(RESPONSE_BODY)
    result["report"] = report
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shb", type=Path, required=True)
    args = parser.parse_args()
    binary = args.shb.resolve()
    with tempfile.TemporaryDirectory(prefix="shb-h2-fragments-") as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["h2"])
        results = [exercise(binary, tls, fragmented)
                   for tls in [None, context] for fragmented in [False, True]]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
