#!/usr/bin/env python3
"""Independent request oracle (python-hpack 4.1.0 and hyper-h2 4.3.0).

Decode every static name and unknown/duplicate/empty/UTF-8 field, then exercise
real shb with exact ordered headers, body data and transport-byte accounting.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading

import hpack
import h2.config
import h2.connection
import h2.events
import h2.settings

def run_probe(probe):
    names = list(dict.fromkeys(name.decode() for name, _ in hpack.table.HeaderTable.STATIC_TABLE))
    values = ["", "a", "br", "héllo日本語", "a" * 126, "a" * 127, "a" * 128, "a" * 40000]
    requests = []
    for name in names + ["x-custom", "accept-encoding-extra", "", "Accept"]:
        for value in values:
            requests.append(dict(method="POST", scheme="https", authority="www.example.com:443",
                                 path="/api/items?q=hello&n=1234", headers=[(name, value), ("x-repeat", "1"), (name, "other")], body_len=1234))
    requests += [dict(method=m, scheme="http", authority="127.0.0.1:18778", path=p,
                      headers=hs, body_len=0) for m, p, hs in [
                          ("GET", "/", []), ("CUSTOM", "/~", [("x-symbols", "~|^{}")]),
                          ("GET", "/" + "abc0123" * 5000, []),
                          ("GET", "/", [(n, "v") for n in names]),
                          ("GET", "/", [("accept", "application/json"), ("user-agent", "shb"), ("cookie", "a=b")])]]
    result = subprocess.run([str(probe)], input="".join(json.dumps(x) + "\n" for x in requests),
                            text=True, capture_output=True, timeout=60, check=True)
    outputs = [json.loads(x) for x in result.stdout.splitlines()]
    assert len(outputs) == len(requests)
    sizes = []
    for request, output in zip(requests, outputs):
        encoded = bytes(output["encoded"])
        want = [(b":method", request["method"].encode()), (b":scheme", request["scheme"].encode()),
                (b":authority", request["authority"].encode()), (b":path", request["path"].encode())]
        want += [(k.encode(), v.encode()) for k, v in request["headers"]]
        if request["body_len"]:
            want.append((b"content-length", str(request["body_len"]).encode()))
        decoder = hpack.Decoder(max_header_list_size=200000)
        decoder.max_allowed_table_size = 0
        for _ in range(3):
            assert decoder.decode(b"\x20" + encoded, raw=True) == want, request
            assert not decoder.header_table.dynamic_entries
        sizes.append(dict(method=request["method"], path_length=len(request["path"]),
                          header_names=[n for n, _ in request["headers"]],
                          header_lengths=[len(v.encode()) for _, v in request["headers"]], encoded_bytes=len(encoded)))
    return dict(static_names=len(names), request_cases=len(requests), sizes=sizes)


def live_case(shb, name, headers, body="", path="/", method="GET"):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    count = 32
    state = dict(requests=0, bodies=0, received_bytes=0, sent_bytes=0, teardown_bytes=0, continuations=0)
    failures = []

    def serve():
        try:
            listener.settimeout(15)
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(15)
                h = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, normalize_inbound_headers=False))
                h.initiate_connection()
                h.update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 0,
                                   h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: 200000})
                opening = h.data_to_send()
                conn.sendall(opening)
                state["sent_bytes"] += len(opening)
                bodies = {}
                wire = bytearray()
                preface = True
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    state["received_bytes"] += len(data)
                    wire.extend(data)
                    if preface and len(wire) >= 24:
                        assert wire[:24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                        del wire[:24]
                        preface = False
                    while not preface and len(wire) >= 9:
                        length = int.from_bytes(wire[:3], "big")
                        if len(wire) < 9 + length:
                            break
                        if wire[3] == 9:
                            state["continuations"] += 1
                        if wire[3] == 7:
                            # shb's graceful GOAWAY is outside the measured
                            # run. Validate its exact shape before excluding it.
                            assert state["teardown_bytes"] == 0
                            assert bytes(wire[:17]) == b"\x00\x00\x08\x07" + b"\x00" * 13
                            state["teardown_bytes"] = 17
                        del wire[:9 + length]
                    for event in h.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            want = [(b":method", method.encode()), (b":scheme", b"http"),
                                    (b":authority", f"127.0.0.1:{port}".encode()), (b":path", path.encode())]
                            want += [(k.lower().encode(), v.encode()) for k, v in headers]
                            if body:
                                if not any(k.lower() == "content-type" for k, _ in headers):
                                    want.append((b"content-type", b"application/x-www-form-urlencoded"))
                                want.append((b"content-length", str(len(body.encode())).encode()))
                            elif method == "POST":
                                want.append((b"content-length", b"0"))
                            assert event.headers == want, (name, event.headers, want)
                            bodies[event.stream_id] = bytearray()
                            state["requests"] += 1
                        elif isinstance(event, h2.events.DataReceived):
                            bodies[event.stream_id].extend(event.data)
                            h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        elif isinstance(event, h2.events.StreamEnded):
                            actual = bytes(bodies.pop(event.stream_id))
                            assert actual == body.encode(), name
                            state["bodies"] += len(actual)
                            h.send_headers(event.stream_id, [(b":status", b"200"), (b"content-length", b"0")], end_stream=True)
                    output = h.data_to_send()
                    if output:
                        conn.sendall(output)
                        state["sent_bytes"] += len(output)
                assert not bodies
                assert not wire and not preface
                assert state["teardown_bytes"] == 17
                assert state["requests"] == count, state
                assert state["bodies"] == count * len(body.encode())
                assert not h.decoder.header_table.dynamic_entries
        except BaseException as exc:
            failures.append(repr(exc))
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    args = [str(shb), "--http2", "-n", str(count), "-c", "1", "-p", "8", "-t", "1", "--timeout", "5s", "-j",
            "-m", method]
    for key, value in headers:
        args += ["-H", key + ": " + value]
    if body:
        args += ["-d", body]
    args += [f"http://127.0.0.1:{port}{path}"]
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    thread.join(20)
    assert not thread.is_alive(), name
    assert not failures, (name, failures, result.stderr)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["requests"]["ok"] == count, report
    assert report["requests"]["errors"] == 0, report
    assert report["requests"]["connectErrors"] == 0, report
    assert report["statusCodes"] == {"200": count}, report
    assert report["bytesSent"] == state["received_bytes"] - state["teardown_bytes"], (name, report, state)
    assert report["bytesReceived"] == state["sent_bytes"], (name, report, state)
    if "continuation" in name:
        assert state["continuations"] >= count, (name, state)
    return dict(name=name, wire=state, report=report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--shb", type=Path, required=True)
    args = parser.parse_args()
    result = dict(probe=run_probe(args.probe.resolve()), versions=dict(hpack=hpack.__version__, h2=h2.__version__))
    legal_names = [name.decode() for name, _ in hpack.table.HeaderTable.STATIC_TABLE
                   if not name.startswith(b":") and name not in (b"content-length", b"host", b"transfer-encoding")]
    cases = [
        ("ordinary", []),
        ("all-legal-names", [(n, "value") for n in legal_names]),
        ("nonempty-static-value", [("Accept-Encoding", "br")]),
        ("duplicates", [("accept", "one"), ("x-custom", "value"), ("accept", "two"), ("cookie", "a=b"), ("cookie", "c=d")]),
        ("empty", [("accept", ""), ("x-custom", "")]),
        ("utf8", [("user-agent", "héllo日本語"), ("x-custom", "héllo日本語")]),
        ("continuation-known", [("user-agent", "a" * 40000)]),
        ("continuation-unknown", [("x-custom", "a" * 40000)]),
        ("continuation-path", [("accept", "value")], "", "/" + "abc0123" * 5000),
        ("post-body", [("content-type", "application/json"), ("user-agent", "test")], "abc0123" * 10000, "/upload", "POST"),
        ("post-empty", [("accept", "value")], "", "/", "POST"),
        ("post-auto-content-type", [("accept", "value")], "body", "/", "POST"),
    ]
    cases += [(f"prefix-{n}", [("user-agent", "a" * n)]) for n in (126, 127, 128, 255, 256)]
    result["live"] = [live_case(args.shb.resolve(), *case) for case in cases]
    result["sha256"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.probe, args.shb)}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
