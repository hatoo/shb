#!/usr/bin/env python3
"""Compare immutable clients against one fixed hfast, including a held response.

Run primary and confirmation separately; the latter reverses cases and pair
order. Every file is created exclusively, so an earlier run cannot be replaced.
The held mode delays stream 1 until all younger responses arrive, then delivers
it too. Client timing and latency reports include that delay and every request.
"""

import argparse
import json
import os
from pathlib import Path
import resource
import selectors
import socket
import statistics
import subprocess
import time


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)


def relay(listener, upstream_port, client, requests):
    """Forward frames unchanged, buffering only the first response's frames."""
    listener.settimeout(10)
    down, _ = listener.accept()
    up = socket.create_connection(("127.0.0.1", upstream_port), timeout=10)
    buffers = {down: bytearray(), up: bytearray()}
    pending = bytearray()
    held = bytearray()
    completed = 0
    released = False
    first_finished = False
    begun = time.monotonic()
    with down, up, selectors.DefaultSelector() as selector:
        for sock in [down, up]:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setblocking(False)
            selector.register(sock, selectors.EVENT_READ)
        while client.poll() is None:
            assert time.monotonic() - begun < 90, "relay timed out"
            for key, events in selector.select(0.02):
                sock = key.fileobj
                if events & selectors.EVENT_READ:
                    try:
                        data = sock.recv(262144)
                    except BlockingIOError:
                        data = None
                    except ConnectionResetError:
                        assert completed == requests and released, "early reset"
                        selector.unregister(sock)
                        continue
                    if data == b"":
                        assert completed == requests and released, "early EOF"
                        selector.unregister(sock)
                        continue
                    if data:
                        if sock is down:
                            buffers[up].extend(data)
                        else:
                            pending.extend(data)
                            pos = 0
                            while len(pending) - pos >= 9:
                                length = int.from_bytes(pending[pos:pos + 3], "big")
                                end = pos + 9 + length
                                if len(pending) < end:
                                    break
                                kind, flags = pending[pos + 3:pos + 5]
                                stream = int.from_bytes(pending[pos + 5:pos + 9], "big") & 0x7fffffff
                                destination = held if stream == 1 else buffers[down]
                                destination.extend(pending[pos:end])
                                if kind in (0, 1) and flags & 1:
                                    completed += 1
                                    if stream == 1:
                                        assert not first_finished
                                        first_finished = True
                                pos = end
                            del pending[:pos]
                            if completed == requests and not released:
                                assert first_finished and held and not pending
                                buffers[down].extend(held)
                                held.clear()
                                released = True
                            assert completed <= requests
                if events & selectors.EVENT_WRITE:
                    try:
                        sent = sock.send(buffers[sock])
                    except BlockingIOError:
                        sent = 0
                    del buffers[sock][:sent]
                for peer in [down, up]:
                    if peer.fileno() in selector.get_map():
                        mask = selectors.EVENT_READ
                        if buffers[peer]:
                            mask |= selectors.EVENT_WRITE
                        selector.modify(peer, mask)
        assert completed == requests and released and not held
        assert not buffers[down], "client exited before all response bytes were sent"
    return completed


def run(args, server_port, binary, stem, connections, parallel, requests, timeout, held):
    listener = socket.socket() if held else None
    if listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
    port = listener.getsockname()[1] if listener else server_port
    command = ["taskset", "-c", str(args.client_cpu), str(binary), "--http2", "-j",
               "-c", str(connections), "-p", str(parallel), "-t", "1", "-n", str(requests)]
    if timeout:
        command += ["--timeout", "10s"]
    command += [f"http://127.0.0.1:{port}/"]
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    proxy_started = time.process_time()
    with (args.output / f"{stem}.json").open("x") as stdout, (args.output / f"{stem}.stderr").open("x") as stderr:
        client = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            replies = relay(listener, server_port, client, requests) if held else None
            assert client.wait(timeout=90) == 0, "client failed"
        finally:
            if client.poll() is None:
                client.kill()
                client.wait()
            if listener:
                listener.close()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    report = json.loads((args.output / f"{stem}.json").read_text())
    assert report["requests"] == dict(ok=requests, errors=0, connectErrors=0, total=requests), report
    assert report["statusCodes"] == {"200": requests} and report["latencySeconds"] is not None
    audit = None
    for line in (args.output / f"{stem}.stderr").read_text().splitlines():
        if line.startswith("C91_AUDIT "):
            audit = json.loads(line.removeprefix("C91_AUDIT "))
            assert audit["samples"] == audit["status_total"] == requests
            assert audit["errors"] == audit["connect_errors"] == 0
    return dict(command=command, report=report, wire_replies=replies, audit=audit,
                wall_seconds=time.monotonic() - started,
                proxy_cpu_seconds=time.process_time() - proxy_started,
                client_cpu_seconds=after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["baseline", "candidate", "hfast", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--phase", choices=["primary", "confirmation", "audit"], required=True)
    parser.add_argument("--mode", choices=["direct", "held"], required=True)
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--case", action="append", help="Select a case ID (repeatable)")
    parser.add_argument("--client-cpu", type=int, default=2)
    parser.add_argument("--proxy-cpu", type=int, default=3)
    args = parser.parse_args()
    os.sched_setaffinity(0, {args.proxy_cpu})
    args.output.mkdir(parents=True, exist_ok=True)
    cases = ([(1, 1, 65536, True), (1, 64, 4194304, True),
              (1, 128, 4194304, True), (1, 4096, 4194304, True),
              (16, 128, 4194304, True), (1, 1, 65536, False),
              (1, 4096, 4194304, False)] if args.mode == "direct"
             else [(1, 128, n, True) for n in [16384, 65536, 131072]])
    if args.case:
        selected = set(args.case)
        available = {f"c{c}-p{p}-n{n}-t{int(t)}" for c, p, n, t in cases}
        assert selected <= available, selected - available
        cases = [(c, p, n, t) for c, p, n, t in cases
                 if f"c{c}-p{p}-n{n}-t{int(t)}" in selected]
    if args.phase == "confirmation":
        cases.reverse()
    rows = []
    port = unused_port()
    prefix = f"c91-{args.mode}-{args.phase}"
    with (args.output / f"{prefix}-hfast.log").open("x") as log:
        server = subprocess.Popen([str(args.hfast), "--tcp", str(port), "--quic", "0", "--threads", "1"], stdout=log, stderr=subprocess.STDOUT)
        try:
            time.sleep(0.2)
            assert server.poll() is None
            for pair in range(args.pairs):
                for connections, parallel, requests, timeout in cases:
                    case = f"c{connections}-p{parallel}-n{requests}-t{int(timeout)}"
                    order = ["baseline", "candidate"]
                    if (pair + (args.phase == "confirmation")) % 2:
                        order.reverse()
                    for variant in order:
                        stem = f"{prefix}-{case}-pair{pair}-{variant}"
                        common = (args, port, getattr(args, variant))
                        warm = run(*common, stem + "-warm", connections, parallel, 8192, timeout, args.mode == "held")
                        measured = run(*common, stem + "-measured", connections, parallel, requests, timeout, args.mode == "held")
                        row = dict(case=case, pair=pair, variant=variant, warm=warm, measured=measured)
                        save(args.output / f"{stem}-result.json", row)
                        rows.append(row)
                        print(stem, measured["report"]["requestsPerSec"], flush=True)
        finally:
            server.terminate()
            server.wait(timeout=5)
    save(args.output / f"{prefix}-results.json", rows)
    summary = {}
    for case in sorted({row["case"] for row in rows}):
        changes = []
        for pair in range(args.pairs):
            results = {row["variant"]: row["measured"] for row in rows if row["case"] == case and row["pair"] == pair}
            changes.append(100 * (results["candidate"]["report"]["requestsPerSec"] / results["baseline"]["report"]["requestsPerSec"] - 1))
        summary[case] = dict(median_percent=statistics.median(changes), changes_percent=changes)
    save(args.output / f"{prefix}-summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
