#!/usr/bin/env python3
"""Alternate immutable binaries built from latency-summary.rs; retain every result."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--seed", type=int, default=73)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--candidate-first", action="store_true")
    parser.add_argument("--sizes", type=int, nargs="+", default=[0, 1, 32, 1024, 1000000, 10000000])
    parser.add_argument("--patterns", nargs="+", default=["random", "duplicates", "sorted", "reverse", "equal", "skewed", "runs"])
    args = parser.parse_args()
    binaries = {v: getattr(args, v).resolve() for v in ["baseline", "candidate"]}
    assert args.pairs > 0 and args.repeats > 0
    env = dict(os.environ, SUMMARY_WARMUPS="3")
    with args.output.open("x") as output:
        def save(row):
            output.write(json.dumps(row) + "\n")
            output.flush()

        save({"kind": "metadata", "platform": platform.platform(), "cpu": args.cpu,
              "warmups": 3, "pairs": args.pairs, "repeats": args.repeats,
              "binaries": {v: {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                           for v, p in binaries.items()}})
        for pair in range(args.pairs):
            for size in args.sizes:
                for pattern in args.patterns:
                    order = ["baseline", "candidate"]
                    if bool(pair % 2) != args.candidate_first:
                        order.reverse()
                    runs = {}
                    for variant in order:
                        command = [str(binaries[variant]), pattern, str(size), str(args.repeats), str(args.seed)]
                        if args.cpu is not None:
                            command = ["taskset", "-c", str(args.cpu)] + command
                        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=300)
                        row = {"kind": "run", "pair": pair, "variant": variant,
                               "command": command, "returncode": result.returncode,
                               "stdout": result.stdout, "stderr": result.stderr}
                        save(row)
                        result.check_returncode()
                        runs[variant] = [json.loads(line) for line in result.stdout.splitlines()]
                        assert len(runs[variant]) == args.repeats
                    expected = runs["baseline"][0]["summary_bits"]
                    assert all(row["summary_bits"] == expected for run in runs.values() for row in run)
                    medians = {v: {metric: statistics.median(row[metric] for row in rows)
                                   for metric in ["wall_ns", "cpu_ns"]}
                               for v, rows in runs.items()}
                    save({"kind": "pair", "pair": pair, "pattern": pattern, "len": size,
                          "seed": args.seed, "medians": medians})
                    change = 100 * (medians["candidate"]["cpu_ns"] / medians["baseline"]["cpu_ns"] - 1)
                    print(f"pair={pair} {pattern} n={size}: summary CPU {change:+.2f}%", flush=True)


if __name__ == "__main__":
    main()
