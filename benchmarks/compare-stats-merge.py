#!/usr/bin/env python3
"""Alternate immutable binaries; preserve every observation and full report.

Build the same stats-merge example with each revision's src/stats.rs, compiler,
allocator feature, and release flags. This compares reporting, not HTTP rates.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("--sizes", default="1,1024,1000000,10000000")
    parser.add_argument("--workers", default="1,4,16")
    parser.add_argument("--modes", default="merge,json")
    parser.add_argument("--capacities", default="grown")
    parser.add_argument("--patterns", default="random")
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--seed", type=int, default=85)
    parser.add_argument("--cpu", type=int, default=8)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--count", action="store_true")
    args = parser.parse_args()
    args.output.mkdir()
    binaries = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    manifest = {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for name, path in binaries.items()}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    env = dict(os.environ)
    env.pop("STATS_COUNT", None)
    env["STATS_WARMUPS"] = "0" if args.count else "3"
    if args.count:
        env["STATS_COUNT"] = "1"
    with (args.output / "results.jsonl").open("x") as results:
        for pair in range(args.pairs):
            for mode in args.modes.split(","):
                for capacity in args.capacities.split(","):
                    for pattern in args.patterns.split(","):
                        for size in map(int, args.sizes.split(",")):
                            for workers in map(int, args.workers.split(",")):
                                order = ["baseline", "candidate"]
                                if (pair % 2 == 1) != args.reverse:
                                    order.reverse()
                                reports = {}
                                for variant in order:
                                    binary = binaries[variant]
                                    assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest[variant]["sha256"]
                                    command = ["taskset", "-c", str(args.cpu), str(binary), mode,
                                               str(size), str(workers), str(args.repeats), str(args.seed), capacity, pattern]
                                    run = subprocess.run(command, env=env, capture_output=True, timeout=180)
                                    stem = f"{pair}-{mode}-{capacity}-{pattern}-{size}-{workers}-{variant}"
                                    (args.output / f"{stem}.stdout").write_bytes(run.stdout)
                                    (args.output / f"{stem}.stderr").write_bytes(run.stderr)
                                    run.check_returncode()
                                    rows = [json.loads(line) for line in run.stderr.splitlines()]
                                    assert len(rows) == args.repeats
                                    for row in rows:
                                        assert row["counted"] == args.count
                                        row.update(pair=pair, variant=variant, command=command)
                                        results.write(json.dumps(row) + "\n")
                                    results.flush()
                                    reports[variant] = run.stdout
                                assert reports["baseline"] == reports["candidate"], "report changed"
                                print(pair, mode, capacity, pattern, size, workers, "PASS", flush=True)


if __name__ == "__main__":
    main()
