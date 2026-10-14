#!/usr/bin/env python3
"""Independent HPACK status-name oracle. Requires hpack==4.1.0.

Each case uses a fresh cleartext HTTP/2 connection. Huffman bytes come from
python-hpack and every valid response block is checked by its full decoder.
--expect-unsupported records the old client's failure on Huffman literal names.
Timings are incidental; this is a correctness test, not a throughput benchmark.
"""

import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading

import hpack
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH

HUFFMAN = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)


def string(value, huffman):
    data = HUFFMAN.encode(value) if huffman else value
    assert len(data) < 127
    return bytes([len(data) | (128 if huffman else 0)]) + data


def literal(status, mode, name_huffman, value_huffman):
    block = bytes([mode]) + string(b":status", name_huffman)
    block += string(str(status).encode(), value_huffman)
    decoder = hpack.Decoder()
    decoder.max_allowed_table_size = 0
    assert decoder.decode(b"\x20" + block) == [(":status", str(status))]
    assert decoder.header_table_size == 0
    return block


def frame(kind, flags, stream, body):
    return len(body).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + body


def headers(block, end=True, split=None):
    if split is None:
        return frame(1, 4 | int(end), 1, block)
    return (frame(1, int(end), 1, block[:split])
            + frame(9, 0, 1, b"") + frame(9, 4, 1, block[split:]))


def cases():
    for mode in [0x00, 0x10, 0x40]:
        for name_huffman in [False, True]:
            for value_huffman in [False, True]:
                for status in [201, 404, 503]:
                    block = literal(status, mode, name_huffman, value_huffman)
                    name = f"literal-{mode:02x}-name{int(name_huffman)}-value{int(value_huffman)}-{status}"
                    yield name, headers(b"\x20" + block), status, name_huffman
    yield "indexed", headers(b"\x20\x88"), 200, False
    block = literal(503, 0, True, True)
    for split in range(len(block) + 1):
        yield f"fragment-{split}", headers(b"\x20" + block, split=split), 503, True
    early = literal(103, 0x10, True, True)
    yield "informational", headers(b"\x20" + early, end=False) + headers(block), 503, True
    trailers = b"\x00" + string(b"x-trailer", True) + string(b"done", True)
    assert hpack.Decoder().decode(trailers) == [("x-trailer", "done")]
    yield "trailers", headers(b"\x20" + block, end=False) + frame(0, 0, 1, b"abc") + headers(trailers), 503, True
    # None of these names can become a successful status; malformed string
    # lengths/values remain errors. Validation of ignored fields is unchanged.
    for name in [b"status", b":Status", b":statu", b":statusx"]:
        invalid = b"\x00" + string(name, True) + string(b"200", False)
        yield "wrong-name-" + name.decode(), headers(invalid), None, False
    for name, invalid in [
        ("truncated-name", b"\x00\x85\xb8\x84"),
        ("truncated-value", block[:-1]),
        ("bad-value-padding", block[:-1] + b"\xfe"),
        ("bad-name-padding", b"\x00\x86\xb8\x84\x8d\x36\xa3\xff\x03" + b"200"),
    ]:
        yield name, headers(invalid), None, False


def run(client, name, response, status, unsupported, expect_unsupported):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(10)
    port = listener.getsockname()[1]
    ledger = dict(received=0, sent=0, requests=0, goaways=0)
    errors = []

    def peer():
        try:
            with listener, listener.accept()[0] as sock:
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                def read(n):
                    data = b""
                    while len(data) < n:
                        part = sock.recv(n - len(data))
                        assert part, "EOF inside a frame"
                        data += part
                        ledger["received"] += len(part)
                    return data

                def send(data):
                    sock.sendall(data)
                    ledger["sent"] += len(data)

                assert read(24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                send(frame(4, 0, 0, b""))
                ack = False
                while not ack or not ledger["requests"]:
                    h = read(9)
                    body = read(int.from_bytes(h[:3], "big"))
                    kind, flags, stream = h[3], h[4], int.from_bytes(h[5:], "big")
                    if kind == 4 and flags == 0:
                        send(frame(4, 1, 0, b""))
                    elif kind == 4 and flags == 1:
                        assert not body and not ack
                        ack = True
                    elif kind == 1:
                        assert flags == 5 and stream == 1 and ledger["requests"] == 0
                        request = dict(hpack.Decoder().decode(body))
                        assert request[":method"] == "GET" and request[":path"] == "/"
                        ledger["requests"] += 1
                    else:
                        assert (kind, flags, stream, len(body)) == (8, 0, 0, 4)
                send(response)
                tail = b""
                while True:
                    part = sock.recv(4096)
                    if not part:
                        break
                    tail += part
                    ledger["received"] += len(part)
                while tail:
                    assert len(tail) >= 9
                    length = int.from_bytes(tail[:3], "big")
                    assert len(tail) >= 9 + length
                    assert tail[3:9] == bytes([7, 0, 0, 0, 0, 0]) and length == 8
                    ledger["goaways"] += 1
                    tail = tail[9 + length:]
        except BaseException as error:
            errors.append(repr(error))

    thread = threading.Thread(target=peer)
    thread.start()
    command = [str(client), "--http2", "-j", "-t", "1", "-c", "1", "-p", "1",
               "-n", "1", "--timeout", "5s", f"http://127.0.0.1:{port}/"]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
    thread.join(12)
    assert not thread.is_alive() and not errors, (name, errors)
    assert completed.returncode == 0, (name, completed.stderr)
    report = json.loads(completed.stdout)
    success = status is not None and not (expect_unsupported and unsupported)
    assert report["requests"] == dict(total=1, ok=int(success), errors=int(not success), connectErrors=0), (name, report)
    assert report["statusCodes"] == ({str(status): 1} if success else {}), (name, report)
    assert (report["latencySeconds"] is not None) == success, (name, report)
    assert ledger["requests"] == 1
    assert report["bytesReceived"] == ledger["sent"], (name, report, ledger)
    assert report["bytesSent"] == ledger["received"] - 17 * ledger["goaways"], (name, report, ledger)
    return dict(case=name, command=command, response_hex=response.hex(), report=report, wire=ledger,
                expected_old_failure=bool(unsupported), stderr=completed.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expect-unsupported", action="store_true")
    args = parser.parse_args()
    client = args.client.resolve()
    result = dict(client=str(client), sha256=hashlib.sha256(client.read_bytes()).hexdigest(),
                  hpack_version=hpack.__version__, expect_unsupported=args.expect_unsupported, cases=[])
    for case in cases():
        result["cases"].append(run(client, *case, args.expect_unsupported))
    with args.out.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(f"PASS {len(result['cases'])} cases; independent HPACK, requests, statuses and wire byte ledgers")


if __name__ == "__main__":
    main()
