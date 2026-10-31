"""Fixed eight-client GOAWAY cohort; every child must pass the same oracle.

Pass frozen release client/peer binaries via the command line.
The denominator spans first client launch through last observed client exit.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse
import hashlib
import ipaddress
import json
import math
import os
import signal
import subprocess
import time

BINARIES = {}
HASHES = {}
CLIENT_CPU = 8
PEER_CPUS = (1, 2)
CLIENTS = 8
WINDOW = 4096
LIMIT = 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def frozen():
    actual = {name: hashlib.sha256(BINARIES[name].read_bytes()).hexdigest()
              for name in HASHES}
    require(actual == HASHES, "immutable binary hash mismatch")
    return actual


def cpu(path):
    fields = list(map(float, path.read_text().split()))
    require(len(fields) == 4 and all(math.isfinite(x) and x >= 0 for x in fields),
            f"invalid CPU report: {path}")
    return dict(zip(("user", "system", "wall", "maxrss_kb"), fields))


def validate_child(folder, child, n):
    stem = folder / f"child-{child['index']}"
    require(child["client_exit"] == child["peer_exit"] == 0, "failed child process")
    report = json.loads(stem.with_suffix(".json").read_text())
    raw = stem.with_suffix(".peer.raw").read_text().splitlines()
    require(raw[0] == child["address"], "wrong peer address")
    records = [json.loads(line) for line in raw[1:]]
    require(len(records) >= 2, "missing peer ledger")
    rows, final = records[:-1], records[-1]
    require(final == {"done": n, "connections": len(rows)}, "incomplete peer")
    remain = n
    total = {key: 0 for key in ("headers", "accepted", "rejected", "body_bytes",
                               "bytes_read", "bytes_sent", "client_goaway_bytes", "goaways")}
    for row in rows:
        require(remain > 0, "extra peer connection")
        accepted, headers = min(remain, LIMIT), min(remain, WINDOW)
        require(row["accepted"] == accepted and row["headers"] == headers,
                "incorrect acceptance window")
        require(row["rejected"] == headers - accepted, "incorrect retry count")
        require(row["complete_bodies"] == accepted and row["body_bytes"] == 0,
                "incomplete request body")
        require(row["goaways"] == int(headers > accepted), "incorrect GOAWAY count")
        require(all(type(row[k]) is int and row[k] >= 0 for k in total),
                "invalid peer counter")
        require(row["bytes_read"] >= row["client_goaway_bytes"], "invalid teardown bytes")
        for key in total:
            total[key] += row[key]
        remain -= accepted
    require(remain == 0 and total["accepted"] == n, "missing responses")
    require(report["requests"] == dict(total=n, ok=n, errors=0, connectErrors=0),
            "incorrect request/error totals")
    require(report["latencySamples"] == n and report["statusCodes"] == {"200": n},
            "incorrect sample/status totals")
    require(report["protocol"] == "HTTP/2" and report["threads"] == 1
            and report["connections"] == 1, "incorrect client configuration")
    require(report["url"] == "http://" + child["address"] + "/", "incorrect target")
    require(report["bytesReceived"] == total["bytes_sent"], "received byte mismatch")
    require(report["bytesSent"] == total["bytes_read"] - total["client_goaway_bytes"],
            "sent byte mismatch")
    latency = report["latencySeconds"]
    percentiles = latency["percentiles"]
    keys = ["p10", "p25", "p50", "p75", "p90", "p95", "p99", "p99.9", "p99.99"]
    require(set(percentiles) == set(keys), "missing latency percentiles")
    ordered = [latency["min"]] + [percentiles[k] for k in keys] + [latency["max"]]
    require(all(math.isfinite(v) and v >= 0 for v in ordered + [latency["mean"]]),
            "invalid latency")
    require(ordered == sorted(ordered) and latency["min"] <= latency["mean"] <= latency["max"],
            "unordered latency")
    require(math.isfinite(report["durationSeconds"]) and report["durationSeconds"] > 0,
            "invalid client interval")
    require(math.isclose(report["requestsPerSec"], n / report["durationSeconds"], rel_tol=1e-10),
            "invalid client rate")
    require(child["launch_ns"] < child["complete_ns"], "invalid child interval")
    require(report["durationSeconds"] <= (child["complete_ns"] - child["launch_ns"]) / 1e9,
            "client duration exceeds observed interval")
    return dict(**child, report=report, ledger=total,
                cpu=cpu(stem.with_suffix(".cpu")), peer_cpu=cpu(stem.with_suffix(".peer.cpu")))


def validate_cohort(folder, metadata):
    children = metadata["children"]
    require(len(children) == CLIENTS and {c["index"] for c in children} == set(range(CLIENTS)),
            "missing/duplicate cohort child")
    require(len({c["address"] for c in children}) == CLIENTS, "duplicate peer listener")
    require(all(c["peer_core"] == PEER_CPUS[c["index"] % 2] for c in children),
            "incorrect peer CPU layout")
    start, end = metadata["start_ns"], metadata["end_ns"]
    require(start > 0 and end > start, "invalid cohort interval")
    require(all(start <= c["launch_ns"] < c["complete_ns"] <= end for c in children),
            "child outside common interval")
    require(end == max(c["complete_ns"] for c in children), "cohort must end at last child exit")
    rows = [validate_child(folder, c, metadata["requests_per_child"]) for c in children]
    wall = (end - start) / 1e9
    requests = CLIENTS * metadata["requests_per_child"]
    client_cpu = sum(c["cpu"]["user"] + c["cpu"]["system"] for c in rows)
    peer_cores = {str(core): sum(c["peer_cpu"]["user"] + c["peer_cpu"]["system"]
                               for c in rows if c["peer_core"] == core) / wall for core in PEER_CPUS}
    return dict(metadata=metadata, rows=rows, requests=requests, latency_samples=requests,
                errors=0, wall=wall, requests_per_sec=requests / wall,
                client_cpu_seconds=client_cpu, client_cores=client_cpu / wall,
                peer_cores=peer_cores,
                completion_spread_seconds=(max(c["complete_ns"] for c in children)
                                           - min(c["complete_ns"] for c in children)) / 1e9)


def stop(processes):
    # The wrapper may have exited before a descendant; signal every owned group.
    for process in processes:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for process in processes:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


def run(binary, folder, n, timeout=180):
    folder.mkdir()
    frozen()
    metadata = dict(binary=str(binary), hashes=HASHES, requests_per_child=n, children=[])
    peers, clients, all_processes = [], [], []
    with ExitStack() as stack:
        try:
            for index in range(CLIENTS):
                stem = folder / f"child-{index}"
                core = PEER_CPUS[index % 2]
                command = ["/usr/bin/time", "-o", str(stem.with_suffix(".peer.cpu")),
                           "-f", "%U %S %e %M", "taskset", "-c", str(core),
                           str(BINARIES["peer"]), str(n), str(WINDOW), str(LIMIT),
                           "0", "tcp", "single"]
                peer = subprocess.Popen(command,
                    stdout=stack.enter_context(stem.with_suffix(".peer.raw").open("x")),
                    stderr=stack.enter_context(stem.with_suffix(".peer.stderr").open("x")),
                    start_new_session=True)
                peers.append(peer)
                all_processes.append(peer)
                metadata["children"].append(dict(index=index, peer_core=core,
                                                 peer_command=command, peer_pid=peer.pid))
            until = time.monotonic() + 5
            for child, peer in zip(metadata["children"], peers):
                path = folder / f"child-{child['index']}.peer.raw"
                while "\n" not in path.read_text():
                    require(peer.poll() is None and time.monotonic() < until, "peer readiness failed")
                    time.sleep(.002)
                address = path.read_text().splitlines()[0]
                host, port = address.rsplit(":", 1)
                require(ipaddress.ip_address(host).is_loopback and 0 < int(port) < 65536,
                        "invalid peer listener")
                child["address"] = address
            metadata["start_ns"] = time.monotonic_ns()
            for child in metadata["children"]:
                stem = folder / f"child-{child['index']}"
                command = ["/usr/bin/time", "-o", str(stem.with_suffix(".cpu")),
                           "-f", "%U %S %e %M", "taskset", "-c", str(CLIENT_CPU), str(binary),
                           "--http2", "-j", "-t", "1", "-c", "1", "-p", str(WINDOW),
                           "-n", str(n), "--timeout", "10s", "http://" + child["address"] + "/"]
                child["launch_ns"] = time.monotonic_ns()
                process = subprocess.Popen(command,
                    stdout=stack.enter_context(stem.with_suffix(".json").open("x")),
                    stderr=stack.enter_context(stem.with_suffix(".stderr").open("x")),
                    start_new_session=True)
                child.update(command=command, client_pid=process.pid)
                clients.append(process)
                all_processes.append(process)
            until = time.monotonic() + timeout
            pending = set(range(CLIENTS))
            while pending:
                require(time.monotonic() < until, "cohort timed out")
                for index in tuple(pending):
                    result = clients[index].poll()
                    if result is not None:
                        metadata["children"][index].update(client_exit=result, complete_ns=time.monotonic_ns())
                        require(result == 0, f"client {index} failed: {result}")
                        pending.remove(index)
                if pending:
                    time.sleep(.002)
            metadata["end_ns"] = max(c["complete_ns"] for c in metadata["children"])
            until = time.monotonic() + 10
            for child, peer in zip(metadata["children"], peers):
                child["peer_exit"] = peer.wait(timeout=max(.01, until - time.monotonic()))
            write_json(folder / "metadata.json", metadata)
            result = validate_cohort(folder, metadata)
            frozen()
            write_json(folder / "summary.json", result)
            print(folder.name, json.dumps({k: result[k] for k in ["requests", "wall", "requests_per_sec",
                         "client_cores", "peer_cores", "completion_spread_seconds"]}), flush=True)
            return result
        except BaseException as error:
            write_json(folder / "failure.json", dict(error=repr(error), metadata=metadata))
            raise
        finally:
            stop(all_processes)


def main():
    global BINARIES, HASHES, CLIENT_CPU, PEER_CPUS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--peer", type=Path, required=True)
    parser.add_argument("--client-cpu", type=int, default=8)
    parser.add_argument("--peer-cpus", type=int, nargs=2, default=[1, 2])
    parser.add_argument("phase", choices=["qualification", "primary", "confirm", "controls"])
    parser.add_argument("--requests", type=int, default=4194304)
    parser.add_argument("--pairs", type=int, default=4)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    require(args.requests > 0 and args.pairs > 0, "counts must be positive")
    BINARIES = {key: getattr(args, key).resolve() for key in ("baseline", "candidate", "peer")}
    HASHES = {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in BINARIES.items()}
    CLIENT_CPU, PEER_CPUS = args.client_cpu, tuple(args.peer_cpus)
    require(len({CLIENT_CPU, *PEER_CPUS}) == 3 and
            {CLIENT_CPU, *PEER_CPUS} <= os.sched_getaffinity(0), "choose three available distinct CPUs")
    dest = Path(args.output).resolve()
    dest.mkdir()
    results = []
    for pair in range(1 if args.phase == "qualification" else args.pairs):
        order = ["baseline", "candidate"]
        if (pair + int(args.phase == "confirm")) % 2:
            order.reverse()
        for variant in order:
            binary = BINARIES["baseline" if variant == "baseline" or args.phase == "controls"
                              else "candidate"]
            results.append(run(binary, dest / f"{pair}-{variant}-warm", 131072))
            result = run(binary, dest / f"{pair}-{variant}", args.requests)
            results.append(result)
            if args.phase != "qualification":
                require(result["wall"] >= 10 and result["client_cores"] >= .85
                        and max(result["peer_cores"].values()) <= .8, "workload no longer qualifies")
    write_json(dest / "summary.json", dict(phase=args.phase, rows=results, hashes=frozen()))


if __name__ == "__main__":
    main()
