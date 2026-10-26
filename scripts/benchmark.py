#!/usr/bin/env python3
"""Measure the README cases against an already-running benchmarks/nginx.conf."""
import argparse
import json
import os
from pathlib import Path
import re
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shb", default="target/release/shb")
    parser.add_argument("--h2load", default="h2load")
    parser.add_argument("--wrk", default="wrk")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1 or args.seconds < 1:
        parser.error("--runs and --seconds must be positive")
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [
        ("h1", 16, 1000, 1), ("h2", 16, 32, 32),
        ("h2", 16, 100, 100), ("h3", 16, 32, 32),
        ("h3", 16, 16, 128), ("h1", 1, 64, 1),
        ("h2", 1, 4, 32), ("h3", 1, 4, 32),
    ]
    results = []
    for protocol, threads, connections, streams in cases:
        url = "https://127.0.0.1:3453/" if protocol == "h3" else "http://127.0.0.1:3010/"
        common = ["-c", str(connections), "-t", str(threads)]
        commands = {
            "shb": [args.shb, "-j", "-z", f"{args.seconds}s", *common],
            "h2load": [args.h2load, "-D", str(args.seconds), *common],
        }
        if protocol == "h1":
            commands["h2load"] += ["--h1"]
            commands["wrk"] = [args.wrk, "-d", f"{args.seconds}s", *common]
        else:
            commands["shb"] += ["--http2" if protocol == "h2" else "--http3", "-p", str(streams)]
            commands["h2load"] += ["-m", str(streams)]
            if protocol == "h3":
                commands["h2load"] += ["--h3"]
        for command in commands.values():
            command.append(url)
        case = dict(protocol=protocol, threads=threads, connections=connections,
                    streams=streams, commands=commands, runs={tool: [] for tool in commands})
        # Rotate clients between rounds to reduce ordering bias.
        names = list(commands)
        for run in range(args.runs):
            for tool in names[run % len(names):] + names[:run % len(names)]:
                command = commands[tool]
                result = subprocess.run(command, capture_output=True, text=True,
                                        timeout=args.seconds + 30)
                stem = f"{protocol}-t{threads}-c{connections}-p{streams}-{tool}-{run + 1}"
                (args.output / f"{stem}.stdout").write_text(result.stdout)
                (args.output / f"{stem}.stderr").write_text(result.stderr)
                if result.returncode:
                    raise RuntimeError(f"{stem}: exit {result.returncode}; see raw output")
                if tool == "shb":
                    report = json.loads(result.stdout)
                    assert report["requests"]["errors"] == 0, stem
                    assert report["statusCodes"] == {"200": report["requests"]["ok"]}, stem
                    rate = report["requestsPerSec"]
                elif tool == "h2load":
                    assert "0 failed, 0 errored, 0 timeout" in result.stdout, stem
                    assert re.search(r"status codes: [1-9]\d* 2xx, 0 3xx, 0 4xx, 0 5xx", result.stdout), stem
                    rate = float(re.search(r"finished in .*?, ([\d.]+) req/s", result.stdout)[1])
                else:
                    assert "Socket errors:" not in result.stdout, stem
                    assert "Non-2xx or 3xx responses:" not in result.stdout, stem
                    rate = float(re.search(r"Requests/sec:\s+([\d.]+)", result.stdout)[1])
                assert rate > 0, stem
                case["runs"][tool].append(rate)
                print(f"{stem}: {rate:,.0f} req/s", flush=True)
        case["median"] = {tool: statistics.median(rates) for tool, rates in case["runs"].items()}
        results.append(case)
        summary = dict(seconds=args.seconds, repetitions=args.runs,
                       library_path=os.environ.get("LD_LIBRARY_PATH", ""), cases=results)
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
