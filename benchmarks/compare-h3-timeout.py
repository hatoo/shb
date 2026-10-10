#!/usr/bin/env python3
"""Compare immutable shb clients with a fixed hfast or a held Quinn response.

Run primary and confirmation separately. Confirmation reverses case and pair
order. All responses, including the held one, must complete; neither that delay
nor any latency sample is excluded from the client's normal report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import socket
import statistics
import subprocess
import time


def save(path, value):
    with path.open("x") as file:
        json.dump(value, file, indent=2)


def run(args, port, binary, stem, connections, parallel, count, timeout):
    peer = None
    peer_log = None
    try:
        if args.mode in ["held", "post-peer"]:
            peer_log = (args.output / f"{stem}-peer.stderr").open("x")
            peer = subprocess.Popen(
                ["taskset", "-c", "0,1", str(args.peer)] +
                (["hold", str(count)] if args.mode == "held" else [str(args.body_bytes)]),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=peer_log, text=True)
            address = peer.stdout.readline().strip()
            assert address.startswith("127.0.0.1:"), address
        else:
            address = f"127.0.0.1:{port}"
        command = ["taskset", "-c", str(args.client_cpu), str(binary), "--http3", "-j",
                   "-n", str(count), "-c", str(connections), "-p", str(parallel), "-t", "1"]
        if timeout:
            command += ["--timeout", "10s"]
        if args.body_bytes:
            command += ["-d", "@" + str(args.output / f"{args.prefix}-body.bin")]
        command += [f"https://{address}/"]
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        begun = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        wall = time.monotonic() - begun
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        with (args.output / f"{stem}.json").open("x") as file:
            file.write(result.stdout)
        with (args.output / f"{stem}.stderr").open("x") as file:
            file.write(result.stderr)
        result.check_returncode()
        report = json.loads(result.stdout)
        assert report["requests"]["ok"] == report["requests"]["total"] == count, report
        assert report["requests"]["errors"] == report["requests"]["connectErrors"] == 0, report
        assert report["statusCodes"] == {"200": count}, report
        assert report["latencySeconds"] is not None, report
        row = dict(command=command, report=report, wall_seconds=wall,
                   client_cpu_seconds=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime)
        if peer:
            output, _ = peer.communicate("done\n", timeout=5)
            assert peer.returncode == 0
            row["peer"] = json.loads(output)
            expected = (dict(responses=count, connections=1, cancellations=0)
                        if args.mode == "held" else dict(responses=count))
            assert row["peer"] == expected, row
            assert peer_log.tell() == 0, "peer reported an unexpected error"
        save(args.output / f"{stem}-metrics.json", row)
        return row
    finally:
        if peer and peer.poll() is None:
            peer.terminate()
            peer.wait(timeout=5)
        if peer_log:
            peer_log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["baseline", "candidate", "hfast", "output"]:
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--peer", type=Path)
    parser.add_argument("--build-manifest", type=Path, required=True,
                        help="JSON from check-release-inputs.py; both binary hashes must match")
    parser.add_argument("--mode", choices=["direct", "held", "post-peer"], required=True)
    parser.add_argument("--phase", choices=["primary", "confirmation", "audit"], required=True)
    parser.add_argument("--prefix", default="c92")
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--client-cpu", type=int, default=2)
    parser.add_argument("--held-counts", default="16384,65536,131072")
    parser.add_argument("--body-bytes", type=int, default=0)
    parser.add_argument("--cases", help="Comma-separated case names, e.g. c1-p128-n1048576-t1")
    args = parser.parse_args()
    build = json.loads(args.build_manifest.read_text())
    assert build["baseline"]["configuration"] == build["candidate"]["configuration"]
    for name in ["baseline", "candidate"]:
        assert hashlib.sha256(getattr(args, name).read_bytes()).hexdigest() == build[name]["sha256"], name
    assert args.mode == "direct" or args.peer
    assert args.mode != "post-peer" or args.body_bytes > 0
    cases = ([(1, 1, 65536, True), (1, 128, 1048576, True),
              (16, 128, 1048576, True), (1, 4096, 1048576, True),
              (1, 1, 65536, False), (1, 4096, 1048576, False)]
             if args.mode == "direct" else
             [(1, 128, int(n), True) for n in args.held_counts.split(",")]+[(1, 128, 65536, False)])
    if args.body_bytes:
        assert args.mode != "held"
        cases = ([(1, 1, 256, True), (1, 8, 512, True), (1, 8, 512, False)]
                 if args.mode == "post-peer" else
                 [(1, 1, 1024, True), (1, 8, 2048, True), (1, 8, 2048, False)])
    if args.phase == "confirmation":
        cases.reverse()
    rows = []
    args.output.mkdir(parents=True, exist_ok=True)
    prefix = f"{args.prefix}-{args.mode}-{args.phase}"
    if args.body_bytes:
        body_path = args.output / f"{args.prefix}-body.bin"
        if not body_path.exists():
            with body_path.open("xb") as file:
                file.write(b"x" * args.body_bytes)
        assert body_path.read_bytes() == b"x" * args.body_bytes
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = None
    with (args.output / f"{prefix}-hfast.log").open("x") as log:
        try:
            if args.mode == "direct":
                server = subprocess.Popen(["taskset", "-c", "0,1", str(args.hfast), "--tcp", "0",
                                           "--quic", str(port), "--threads", "1"], stdout=log, stderr=subprocess.STDOUT)
                time.sleep(.2)
                assert server.poll() is None
            for pair in range(args.pairs):
                for c, p, n, timeout in cases:
                    case = f"c{c}-p{p}-n{n}-t{int(timeout)}"
                    if args.cases and case not in args.cases.split(","):
                        continue
                    order = ["baseline", "candidate"]
                    if (pair+(args.phase == "confirmation")) % 2:
                        order.reverse()
                    for variant in order:
                        stem = f"{prefix}-{case}-pair{pair}-{variant}"
                        common = (args, port, getattr(args, variant))
                        warm = run(*common, stem+"-warm", c, p, 32 if args.body_bytes else 8192, timeout)
                        measured = run(*common, stem+"-measured", c, p, n, timeout)
                        row = dict(case=case, pair=pair, variant=variant, warm=warm, measured=measured)
                        save(args.output / f"{stem}-result.json", row)
                        rows.append(row)
                        print(stem, measured["report"]["requestsPerSec"], flush=True)
        finally:
            if server:
                server.terminate()
                server.wait(timeout=5)
    save(args.output / f"{prefix}-results.json", rows)
    summary = {}
    for case in sorted({row["case"] for row in rows}):
        rps, cpu = [], []
        for pair in range(args.pairs):
            pair_rows = {row["variant"]:row["measured"] for row in rows if row["case"]==case and row["pair"]==pair}
            a, b = pair_rows["baseline"], pair_rows["candidate"]
            rps.append(100*(b["report"]["requestsPerSec"]/a["report"]["requestsPerSec"]-1))
            cpu.append(100*(b["client_cpu_seconds"]/a["client_cpu_seconds"]-1))
        summary[case] = dict(rps_pct=rps, median_rps_pct=statistics.median(rps),
                             cpu_pct=cpu, median_cpu_pct=statistics.median(cpu))
    save(args.output / f"{prefix}-summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
