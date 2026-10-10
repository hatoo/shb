#!/usr/bin/env python3
"""Compare immutable clients against one fixed Quinn response peer.

Application writes do not guarantee QUIC receive boundaries. Splitting is a
workload property, not proof that a particular parser path ran on the network.
Use the whole-reader replay for deterministic fragmentation/copy measurements.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import resource
import select
import statistics
import subprocess
import tempfile


# Header-value bytes, body bytes, split HEADERS tail, measured requests.
CASES = {
    "ordinary": (0, 13, False, 1048576),
    "body64k": (0, 65536, False, 32768),
    "body64k-split": (0, 65536, True, 32768),
    "headers1k-body64k-split": (1024, 65536, True, 32768),
    "headers64k": (65536, 1024, False, 32768),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--candidate-first", action="store_true")
    parser.add_argument("--client-cpu", type=int)
    parser.add_argument("--server-cpus")
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--requests", type=int, help="Override counts for a pilot")
    args = parser.parse_args()
    assert args.pairs > 0
    assert args.requests is None or args.requests > 0
    binaries = {v: getattr(args, v).resolve() for v in ["baseline", "candidate"]}
    peer_path = args.peer.resolve()
    rows = []
    with args.output.open("x") as output:
        def save(row):
            output.write(json.dumps(row) + "\n")
            output.flush()

        save({"kind": "metadata", "platform": platform.platform(),
              "client_cpu": args.client_cpu, "server_cpus": args.server_cpus,
              "pairs": args.pairs, "candidate_first": args.candidate_first,
              "binaries": {v: {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                           for v, p in dict(binaries, peer=peer_path).items()}})
        for pair in range(args.pairs):
            for name in args.cases:
                header, body, split, count = CASES[name]
                if args.requests is not None:
                    count = args.requests
                command = [str(peer_path), "0", str(header), str(body), str(int(split))]
                if args.server_cpus is not None:
                    command = ["taskset", "-c", args.server_cpus] + command
                with tempfile.TemporaryFile(mode="w+") as log:
                    peer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True)
                    try:
                        assert select.select([peer.stdout], [], [], 10)[0], "peer did not start"
                        address = peer.stdout.readline().strip()
                        assert address.startswith("127.0.0.1:"), address
                        order = ["baseline", "candidate"]
                        if bool(pair % 2) != args.candidate_first:
                            order.reverse()
                        for variant in order:
                            for warmup in [True, False]:
                                requests = min(1024, count) if warmup else count
                                client = [str(binaries[variant]), "-j", "-n", str(requests),
                                          "-c", "4", "-t", "1", "--http3", "-p", "32",
                                          "--timeout", "10s", f"https://{address}/"]
                                if args.client_cpu is not None:
                                    client = ["taskset", "-c", str(args.client_cpu)] + client
                                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                                result = subprocess.run(client, capture_output=True, text=True, timeout=300)
                                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                                row = {"kind": "run", "case": name, "pair": pair,
                                       "variant": variant, "warmup": warmup,
                                       "command": client, "peer": command,
                                       "cpu_user_s": after.ru_utime - before.ru_utime,
                                       "cpu_system_s": after.ru_stime - before.ru_stime,
                                       "returncode": result.returncode,
                                       "stdout": result.stdout, "stderr": result.stderr}
                                save(row)
                                result.check_returncode()
                                report = json.loads(result.stdout)
                                assert report["requests"]["total"] == report["requests"]["ok"] == requests, report
                                assert report["requests"]["errors"] == report["requests"]["connectErrors"] == 0, report
                                assert report["statusCodes"] == {"200": requests}, report
                                assert report["latencySeconds"] is not None, report
                                assert peer.poll() is None, "peer exited during the workload"
                                rows.append(dict(row, report=report))
                                if not warmup:
                                    print(pair, name, variant, report["requestsPerSec"], flush=True)
                    finally:
                        peer.terminate()
                        peer.wait(timeout=5)
                        log.seek(0)
                        peer_log = log.read()
                        save({"kind": "peer", "case": name, "pair": pair, "log": peer_log})
                    assert not peer_log, peer_log
        for name in args.cases:
            selected = {v: {r["pair"]: r for r in rows if r["case"] == name
                            and r["variant"] == v and not r["warmup"]}
                        for v in binaries}
            throughput, cpu = [], []
            for pair in range(args.pairs):
                a, b = selected["baseline"][pair], selected["candidate"][pair]
                throughput.append(100 * (b["report"]["requestsPerSec"] / a["report"]["requestsPerSec"] - 1))
                cpu.append(100 * ((b["cpu_user_s"] + b["cpu_system_s"]) /
                                  (a["cpu_user_s"] + a["cpu_system_s"]) - 1))
            summary = {"kind": "summary", "case": name, "rps_paired_pct": throughput,
                       "cpu_paired_pct": cpu, "rps_median_paired_pct": statistics.median(throughput),
                       "cpu_median_paired_pct": statistics.median(cpu)}
            save(summary)
            print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
