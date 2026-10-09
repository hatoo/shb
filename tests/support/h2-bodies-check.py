#!/usr/bin/env python3
"""Independent hyper-h2 POST checks with delayed credit and early responses.

Requires h2==4.3.0, hpack==4.1.0, hyperframe==6.1.0 and openssl.
"""
import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, PingAckReceived, RequestReceived, StreamEnded
from h2.settings import SettingCodes


def exercise(binary, context, delayed):
    body = b"q" * (100_000 if delayed else 16)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(15)
    port = listener.getsockname()[1]
    result = {"tls": context is not None, "delayed": delayed, "requests": 0,
              "complete_bodies": 0, "body_bytes": 0, "early_responses": 0,
              "blocked_ping_acks": 0}
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
                bodies, ended = {}, set()

                def flush():
                    wire = conn.data_to_send()
                    if wire:
                        sock.sendall(wire)

                def receive(blocked=False):
                    wire = sock.recv(65536)
                    assert wire, "client closed before the workload finished"
                    events = conn.receive_data(wire)
                    for event in events:
                        if isinstance(event, RequestReceived):
                            headers = dict(event.headers)
                            assert headers[":method"] == "POST"
                            assert headers[":path"] == "/bodies"
                            assert int(headers["content-length"]) == len(body)
                            assert event.stream_id not in bodies
                            bodies[event.stream_id] = bytearray()
                            result["requests"] += 1
                        elif isinstance(event, DataReceived):
                            assert not blocked, "DATA sent without stream credit"
                            assert event.stream_id not in ended
                            bodies[event.stream_id].extend(event.data)
                            result["body_bytes"] += len(event.data)
                        elif isinstance(event, StreamEnded):
                            assert event.stream_id not in ended, "duplicate END_STREAM"
                            assert bodies[event.stream_id] == body
                            ended.add(event.stream_id)
                            result["complete_bodies"] += 1
                    flush()
                    return events

                def ping_barrier(token):
                    conn.ping(token)
                    flush()
                    while True:
                        events = receive(blocked=True)
                        if any(isinstance(e, PingAckReceived) and e.ping_data == token for e in events):
                            result["blocked_ping_acks"] += 1
                            return

                flush()
                while len(bodies) < 8 or (not delayed and len(ended) < 8):
                    receive()
                assert sorted(bodies) == list(range(1, 16, 2))
                if delayed:
                    assert not ended
                    assert result["body_bytes"] == 65535
                    conn.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 0})
                    ping_barrier(b"blocked!")
                    # End a request whose body is still blocked, then send the
                    # reset commonly sent by servers that do not read bodies.
                    conn.send_headers(15, [(":status", "200")], end_stream=True)
                    conn.reset_stream(15, error_code=0)
                    result["early_responses"] = 1
                    conn.increment_flow_control_window(1_000_000)
                    ping_barrier(b"connonly")
                    for stream in reversed(range(1, 14, 2)):
                        conn.increment_flow_control_window(len(body), stream_id=stream)
                    flush()
                    while len(ended) < 7:
                        receive()
                    assert ended == set(range(1, 14, 2))
                    assert not bodies[15]
                else:
                    # All small bodies have ended; control receives must not
                    # cause any extra DATA while responses remain outstanding.
                    ping_barrier(b"all-sent")
                for stream in sorted(ended, reverse=True):
                    conn.send_headers(stream, [(":status", "200")], end_stream=True)
                flush()
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
    command = [str(binary), "-j", "--http2", "-c", "1", "-t", "1", "-p", "8",
               "-n", "8", "--timeout", "10s", "-d", body.decode(),
               f'{"https" if context else "http"}://127.0.0.1:{port}/bodies']
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
    assert report["requests"]["total"] == report["requests"]["ok"] == 8, report
    assert report["requests"]["errors"] == report["requests"]["connectErrors"] == 0, report
    assert report["statusCodes"] == {"200": 8}, report
    assert result["complete_bodies"] == (7 if delayed else 8)
    assert result["body_bytes"] == result["complete_bodies"] * len(body)
    result["report"] = report
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shb", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="shb-h2-bodies-") as directory:
        cert, key = Path(directory)/"cert.pem", Path(directory)/"key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["h2"])
        results = [exercise(args.shb.resolve(), tls, delayed)
                   for tls in [None, context] for delayed in [False, True]]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
