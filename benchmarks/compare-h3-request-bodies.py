#!/usr/bin/env python3
"""Compare immutable production shb clients against a fixed HTTP/3 peer.

Cases are JSON objects with name, body, parallel, count, connections, and mode
(hfast or quinn). The Quinn peer validates every body byte before returning 200.
Use separate primary and confirmation invocations; confirmation reverses order.
All raw files are created exclusively, and build fingerprints must match.
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


def save(path, data):
    with path.open("x") as file:
        json.dump(data, file, indent=2)


def body_bytes(length):
    state = 0xA73DC91B0E62F845
    data = bytearray(length)
    for i in range(length):
        state ^= (state << 13) & ((1 << 64) - 1)
        state ^= state >> 7
        state ^= (state << 17) & ((1 << 64) - 1)
        byte = state & 255
        # Match the peer without introducing CR/LF that -d @file strips.
        data[i] = byte + 1 if byte in (10, 13) else byte
    return data


def run(args, case, count, variant, stem, port):
    peer = None
    with (args.output / (stem + "-peer.stderr")).open("x") as peer_log:
        try:
            address = f"127.0.0.1:{port}"
            if case["mode"] == "quinn":
                peer = subprocess.Popen(
                    ["taskset", "-c", "0,1", str(args.peer), str(case["body"]),
                     str(case.get("window", 2048)), str(case.get("connection_window", 4096))],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=peer_log, text=True)
                address = peer.stdout.readline().strip()
                assert address.startswith("127.0.0.1:"), address
            command = ["taskset", "-c", "2", str(getattr(args, variant)), "--http3",
                       "-j", "-n", str(count), "-c", str(case["connections"]),
                       "-p", str(case["parallel"]), "-t", "1", "--timeout", "30s"]
            if case["body"]:
                command += ["-d", "@" + str(args.output / f"{args.prefix}-body-{case['body']}.bin")]
            command += [f"https://{address}/"]
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            start = time.monotonic()
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            wall = time.monotonic() - start
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            with (args.output / (stem + ".json")).open("x") as file:
                file.write(result.stdout)
            with (args.output / (stem + ".stderr")).open("x") as file:
                file.write(result.stderr)
            result.check_returncode()
            report = json.loads(result.stdout)
            assert report["requests"]["ok"] == report["requests"]["total"] == count, report
            assert report["requests"]["errors"] == report["requests"]["connectErrors"] == 0, report
            assert report["statusCodes"] == {"200": count}, report
            assert report["latencySeconds"] is not None, report
            row = dict(command=command, report=report, wall_seconds=wall,
                       client_cpu_seconds=after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime)
            if args.audit:
                audits = [json.loads(line.split(" ", 1)[1]) for line in result.stderr.splitlines()
                          if line.startswith("C96_AUDIT ")]
                assert len(audits) == 1, result.stderr
                audit = audits[0]
                assert audit["samples"] == audit["completed"] == audit["status_total"] == count, audit
                assert audit["errors"] == audit["connect_errors"] == 0, audit
                row["audit"] = audit
            if peer:
                output, _ = peer.communicate("done\n", timeout=5)
                assert peer.returncode == 0
                row["peer"] = json.loads(output)
                assert row["peer"] == dict(responses=count, validated_body_bytes=count * case["body"]), row
                assert peer_log.tell() == 0, "independent peer reported an error"
            save(args.output / (stem + "-metrics.json"), row)
            return row
        finally:
            if peer and peer.poll() is None:
                peer.terminate()
                peer.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["baseline", "candidate", "hfast", "peer", "output", "cases", "build_manifest"]:
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--phase", choices=["pilot", "primary", "confirmation", "audit"], required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--audit", action="store_true")
    args = parser.parse_args()
    build = json.loads(args.build_manifest.read_text())
    assert build["baseline"]["configuration"] == build["candidate"]["configuration"]
    for variant in ["baseline", "candidate"]:
        assert hashlib.sha256(getattr(args, variant).read_bytes()).hexdigest() == build[variant]["sha256"]
    args.output.mkdir(parents=True, exist_ok=True)
    cases = json.loads(args.cases.read_text())
    for size in {case["body"] for case in cases if case["body"]}:
        data = body_bytes(size)
        path = args.output / f"{args.prefix}-body-{size}.bin"
        if not path.exists():
            with path.open("xb") as file:
                file.write(data)
        assert path.read_bytes() == data
    if args.phase == "confirmation":
        cases.reverse()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    prefix = args.prefix + "-" + args.phase
    rows = []
    server = None
    with (args.output / (prefix + "-hfast.log")).open("x") as log:
        try:
            if any(case["mode"] == "hfast" for case in cases):
                server = subprocess.Popen(
                    ["taskset", "-c", "0,1", str(args.hfast), "--tcp", "0", "--quic",
                     str(port), "--threads", "1"], stdout=log, stderr=subprocess.STDOUT)
                time.sleep(.2)
                assert server.poll() is None
            for pair in range(args.pairs):
                for case in cases:
                    order = ["baseline", "candidate"]
                    if (pair + (args.phase == "confirmation")) % 2:
                        order.reverse()
                    for variant in order:
                        stem = f"{prefix}-{case['name']}-p{pair}-{variant}"
                        warm_count = case.get("warmup", 8192 if case["body"] == 0 else 8)
                        warm = run(args, case, warm_count, variant, stem + "-warm", port)
                        measured = run(args, case, case["count"], variant, stem + "-measured", port)
                        row = dict(case=case, pair=pair, variant=variant, warm=warm, measured=measured)
                        save(args.output / (stem + "-result.json"), row)
                        rows.append(row)
                        print(stem, measured["report"]["requestsPerSec"], flush=True)
        finally:
            if server:
                server.terminate()
                server.wait(timeout=5)
    save(args.output / (prefix + "-results.json"), rows)
    summary = {}
    for case in cases:
        rps, cpu = [], []
        for pair in range(args.pairs):
            found = {row["variant"]: row["measured"] for row in rows
                     if row["case"] == case and row["pair"] == pair}
            left, right = found["baseline"], found["candidate"]
            rps.append(100 * (right["report"]["requestsPerSec"] / left["report"]["requestsPerSec"] - 1))
            cpu.append(100 * (right["client_cpu_seconds"] / left["client_cpu_seconds"] - 1))
        summary[case["name"]] = dict(case=case, rps_pct=rps, median_rps_pct=statistics.median(rps),
                                    cpu_pct=cpu, median_cpu_pct=statistics.median(cpu))
    save(args.output / (prefix + "-summary.json"), summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
