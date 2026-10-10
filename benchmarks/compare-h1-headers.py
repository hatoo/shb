#!/usr/bin/env python3
"""Alternate immutable shb binaries against one fixed raw response-header peer."""

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
import time


CASES = {
    "ordinary": ("fields", 64, 65536),
    "fields1k": ("fields", 1024, 65536),
    "fields64k": ("fields", 65536, 16384),
    "fields1m": ("fields", 1048576, 2048),
    "line1m": ("line", 1048576, 2048),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("server", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--candidate-first", action="store_true")
    parser.add_argument("--client-cpu", type=int)
    parser.add_argument("--server-cpus")
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    args = parser.parse_args()
    assert args.pairs > 0
    binaries = {v: getattr(args, v).resolve() for v in ["baseline", "candidate"]}
    server_path = args.server.resolve()
    rows = []
    with args.output.open("x") as output:
        def save(row):
            output.write(json.dumps(row) + "\n")
            output.flush()

        save({"kind": "metadata", "platform": platform.platform(),
              "client_cpu": args.client_cpu, "server_cpus": args.server_cpus,
              "pairs": args.pairs, "candidate_first": args.candidate_first,
              "binaries": {v: {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                           for v, p in dict(binaries, server=server_path).items()}})
        for pair in range(args.pairs):
            for name in args.cases:
                pattern, size, count = CASES[name]
                command = [str(server_path), "127.0.0.1:0", str(size), pattern]
                if args.server_cpus is not None:
                    command = ["taskset", "-c", args.server_cpus] + command
                with tempfile.TemporaryFile(mode="w+") as log:
                    server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True)
                    try:
                        assert select.select([server.stdout], [], [], 5)[0], "peer did not start"
                        peer = json.loads(server.stdout.readline())
                        order = ["baseline", "candidate"]
                        if bool(pair % 2) != args.candidate_first:
                            order.reverse()
                        for variant in order:
                            for warmup in [True, False]:
                                requests = min(1024, count // 8) if warmup else count
                                client = [str(binaries[variant]), "-j", "-n", str(requests),
                                          "-c", "1", "-t", "1", "--timeout", "10s",
                                          f"http://127.0.0.1:{peer['port']}/"]
                                if args.client_cpu is not None:
                                    client = ["taskset", "-c", str(args.client_cpu)] + client
                                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                                result = subprocess.run(client, capture_output=True, text=True, timeout=180)
                                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                                row = {"kind": "run", "case": name, "pair": pair, "variant": variant,
                                       "warmup": warmup, "command": client, "server": command,
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
                                assert report["bytesReceived"] == requests * peer["wire_bytes"], report
                                assert report["latencySeconds"] is not None, report
                                rows.append(dict(row, report=report))
                                if not warmup:
                                    print(pair, name, variant, report["requestsPerSec"], flush=True)
                        # The peer logs each connection only after observing
                        # EOF; kernel teardown can outlive client process exit.
                        # This wait is outside every measurement interval.
                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline:
                            log.seek(0)
                            if len(log.read().splitlines()) == 4:
                                break
                            time.sleep(0.01)
                    finally:
                        server.terminate()
                        server.wait(timeout=5)
                        log.seek(0)
                        peer_log = log.read()
                        save({"kind": "peer", "case": name, "pair": pair, "log": peer_log,
                              "all_connections_logged": len(peer_log.splitlines()) == 4})
        for name in args.cases:
            medians = {}
            for variant in binaries:
                selected = [r for r in rows if r["case"] == name and r["variant"] == variant and not r["warmup"]]
                medians[variant] = {
                    "rps": statistics.median(r["report"]["requestsPerSec"] for r in selected),
                    "cpu_s": statistics.median(r["cpu_user_s"] + r["cpu_system_s"] for r in selected),
                }
            save({"kind": "summary", "case": name, "medians": medians,
                  "rps_change_pct": 100 * (medians["candidate"]["rps"] / medians["baseline"]["rps"] - 1),
                  "cpu_change_pct": 100 * (medians["candidate"]["cpu_s"] / medians["baseline"]["cpu_s"] - 1)})


if __name__ == "__main__":
    main()
