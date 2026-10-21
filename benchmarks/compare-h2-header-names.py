#!/usr/bin/env python3
"""Compare frozen shb binaries against a fixed Node/nghttp2 decoding peer.

Every request is decoded and checked, including warmups. Only counted runs
are used, and peer/client totals must agree after every client exits.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parent


def cpu(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().split()
    return (int(fields[13]) + int(fields[14])) / os.sysconf("SC_CLK_TCK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workload", choices=["ordinary", "common", "many", "unknown"], default="common")
    parser.add_argument("--requests", type=int, default=131072)
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--client-cpu", type=int, default=8)
    parser.add_argument("--server-cpu", type=int, default=0)
    parser.add_argument("--port", type=int, default=18778)
    args = parser.parse_args()
    assert args.requests > 0 and args.pairs > 0
    binaries = {label: path.resolve() for label, path in [("baseline", args.baseline), ("candidate", args.candidate)]}
    workloads = ROOT / "h2-header-workloads.json"
    headers = json.loads(workloads.read_text())[args.workload]
    peer = ROOT / "h2-header-peer.cjs"
    log = args.output.with_suffix(".server.log")
    assert not args.output.exists() and not log.exists()
    server_cmd = ["taskset", "-c", str(args.server_cpu), "node", str(peer), str(args.port), str(workloads), args.workload]
    samples = []
    completed = 0
    with args.output.open("x") as output, log.open("x") as logf:
        def record(value):
            output.write(json.dumps(value) + "\n")
            output.flush()

        def check_peer():
            deadline = time.monotonic() + 5
            while True:
                snapshots = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
                if snapshots and snapshots[-1]["requests"] == completed and snapshots[-1]["sessions"] == snapshots[-1]["closed"]:
                    assert snapshots[-1]["failures"] == 0, snapshots[-1]
                    return snapshots[-1]
                assert time.monotonic() < deadline, (snapshots, completed)
                assert server.poll() is None, log.read_text()
                time.sleep(0.001)

        server = subprocess.Popen(server_cmd, stdout=logf, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while "ready" not in log.read_text():
                assert server.poll() is None, log.read_text()
                assert time.monotonic() < deadline, "server readiness timeout"
                time.sleep(0.01)
            record({"metadata": dict(
                config={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                server_command=server_cmd,
                node=subprocess.check_output(["node", "--version"], text=True).strip(),
                hashes={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [*binaries.values(), peer, workloads]},
            )})

            def run(label, phase, rep):
                nonlocal completed
                count = args.requests if phase == "measure" else min(32768, args.requests)
                cmd = ["taskset", "-c", str(args.client_cpu), str(binaries[label]), "--http2", "-t", "1", "-c", "16", "-p", "64", "--batch-linger", "1", "--timeout", "3s", "-j", "-n", str(count)]
                for key, value in headers:
                    cmd += ["-H", key + ": " + value]
                cmd += [f"http://127.0.0.1:{args.port}/"]
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                start_cpu, start = cpu(server.pid), time.monotonic()
                result = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
                wall, server_cpu = time.monotonic() - start, cpu(server.pid) - start_cpu
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                assert result.returncode == 0, (result.returncode, result.stderr)
                report = json.loads(result.stdout)
                sample = dict(phase=phase, rep=rep, label=label, report=report, wall=wall,
                              server_cpu=server_cpu,
                              client_cpu=after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
                              client_command=cmd, stderr=result.stderr)
                record(sample)
                assert report["requests"]["ok"] == report["requests"]["total"] == count, sample
                assert report["requests"]["errors"] == report["requests"]["connectErrors"] == 0, sample
                assert report["statusCodes"] == {"200": count}, sample
                completed += count
                record({"peer": check_peer()})
                if phase == "measure":
                    samples.append(sample)

            order = ["candidate", "baseline"] if args.reverse else ["baseline", "candidate"]
            for label in order:
                run(label, "warmup", -1)
            for rep in range(args.pairs):
                for label in order if rep % 2 == 0 else order[::-1]:
                    run(label, "measure", rep)
            pairs = []
            for rep in range(args.pairs):
                baseline = next(s for s in samples if s["rep"] == rep and s["label"] == "baseline")
                candidate = next(s for s in samples if s["rep"] == rep and s["label"] == "candidate")
                pairs.append(dict(
                    rps=100 * (candidate["report"]["requestsPerSec"] / baseline["report"]["requestsPerSec"] - 1),
                    client_cpu_per_request=100 * (candidate["client_cpu"] / baseline["client_cpu"] - 1),
                    server_cpu_per_request=100 * (candidate["server_cpu"] / baseline["server_cpu"] - 1),
                ))
            summary = dict(pairs=pairs, medians={k: statistics.median(p[k] for p in pairs) for k in pairs[0]}, responses=completed)
            record({"summary": summary})
            print(json.dumps(summary))
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
            final = json.loads(log.read_text().splitlines()[-1])
            assert server.returncode == 0 and final["failures"] == 0, final
            assert final["requests"] == completed and final["sessions"] == final["closed"], final


if __name__ == "__main__":
    main()
