#!/usr/bin/env python3
"""Compare immutable clients against a fixed native byte-complete TLS H2 peer."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import statistics
import subprocess
import time


def log_lines(path):
    # A regular-file read can end in the middle of a concurrent stderr write.
    # Parse only newline-terminated records; malformed complete records still fail.
    data = path.read_text()
    return data[:data.rfind('\n') + 1].splitlines()


def cpu_time():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def ledgers(path):
    return [json.loads(line[7:]) for line in log_lines(path)
            if line.startswith('LEDGER ')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'candidate', 'peer', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--requests', type=int, default=32768)
    parser.add_argument('--warmup', type=int, default=512)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--client-cpu', default='2')
    parser.add_argument('--server-cpus', default='8,10,12,14')
    args = parser.parse_args()
    if args.requests < 512 or args.warmup < 512 or args.rounds < 1:
        parser.error('requests and warmup must be at least 512; rounds at least 1')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binaries = {name: getattr(args, name).resolve()
                for name in ['baseline', 'candidate', 'peer']}
    body = out / 'body'
    body.write_bytes(bytes(33 + i % 90 for i in range(16384)))
    cert, key = out / 'cert.pem', out / 'key.pem'
    with (out / 'certificate.log').open('x') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-days', '1'],
                       stdout=log, stderr=log, check=True)
    inputs = {**binaries, 'body': body}
    hashes = {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in inputs.items()}
    manifest = dict(arguments={k: str(v) if isinstance(v, Path) else v
                               for k, v in vars(args).items()}, hashes=hashes)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows = []
    for pair in range(args.rounds):
        for tls in (['tls12', 'tls13'] if args.reverse else ['tls13', 'tls12']):
            variants = (['baseline', 'candidate'] if (pair % 2 == 0) != args.reverse
                        else ['candidate', 'baseline'])
            for variant in variants:
                for warmup in [True, False]:
                    count = args.warmup if warmup else args.requests
                    stem = f'{pair}-{tls}-{variant}' + ('-warmup' if warmup else '')
                    peer_command = ['taskset', '-c', args.server_cpus,
                                    str(binaries['peer']), '0', str(body), '--tls', tls,
                                    '--cert', str(cert), '--key', str(key)]
                    peer_log = out / (stem + '.peer.log')
                    with peer_log.open('x') as log:
                        peer = subprocess.Popen(peer_command, stdout=log, stderr=log)
                        try:
                            deadline = time.monotonic() + 10
                            while True:
                                assert peer.poll() is None, peer_log.read_text()
                                ready = [s for s in log_lines(peer_log)
                                         if s.startswith('READY ')]
                                if ready:
                                    port = int(ready[0].split()[1])
                                    break
                                assert time.monotonic() < deadline, 'native peer startup'
                                time.sleep(0.01)
                            command = ['taskset', '-c', args.client_cpu, str(binaries[variant]),
                                       '--http2', '-j', '-t', '1', '-c', '8', '-p', '8',
                                       '--batch-linger', '10', '-n', str(count), '--timeout', '10s',
                                       '-d', '@' + str(body), f'https://127.0.0.1:{port}/upload']
                            before = cpu_time()
                            run = subprocess.run(command, capture_output=True, text=True, timeout=120)
                            client_cpu = cpu_time() - before
                            (out / (stem + '.stdout')).write_text(run.stdout)
                            (out / (stem + '.stderr')).write_text(run.stderr)
                            assert run.returncode == 0, run.stderr
                            report = json.loads(run.stdout)
                            assert report['requests'] == dict(ok=count, errors=0, connectErrors=0, total=count)
                            assert report['statusCodes'] == {'200': count}
                            assert report['bytesSent'] >= count * 16384
                            deadline = time.monotonic() + 10
                            while len(ledgers(peer_log)) < 8:
                                assert peer.poll() is None and time.monotonic() < deadline, peer_log.read_text()
                                time.sleep(0.01)
                            ledger = ledgers(peer_log)
                            assert len(ledger) == len({r['connection'] for r in ledger}) == 8, ledger
                            assert sum(r['requests'] for r in ledger) == count, ledger
                            assert sum(r['body_bytes'] for r in ledger) == count * 16384, ledger
                            assert all(r['pending'] == r['rejected'] == 0 and r['requests'] > 0 for r in ledger), ledger
                            assert not any(s in peer_log.read_text() for s in ['UPLOAD_ERROR', 'TLS_ERROR', 'panicked']), peer_log.read_text()
                            before = cpu_time()
                            peer.terminate()
                            peer.wait(timeout=5)
                            peer_cpu = cpu_time() - before
                            row = dict(pair=pair, tls=tls, variant=variant, warmup=warmup,
                                       count=count, command=command, peer_command=peer_command,
                                       report=report, ledgers=ledger,
                                       client_cpu_ns=1e9 * client_cpu / count,
                                       peer_cpu_ns=1e9 * peer_cpu / count)
                            rows.append(row)
                            (out / (stem + '.json')).write_text(json.dumps(row, indent=2) + '\n')
                        finally:
                            if peer.poll() is None:
                                peer.terminate()
                            try:
                                peer.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                peer.kill()
                                peer.wait()
    assert hashes == {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in inputs.items()}
    summary = {}
    for tls in ['tls12', 'tls13']:
        pairs = []
        for pair in range(args.rounds):
            b, c = [next(r for r in rows if r['tls'] == tls and r['pair'] == pair
                         and r['variant'] == v and not r['warmup']) for v in ['baseline', 'candidate']]
            values = dict(rps=[r['report']['requestsPerSec'] for r in [b, c]],
                          client_cpu_ns=[r['client_cpu_ns'] for r in [b, c]],
                          peer_cpu_ns=[r['peer_cpu_ns'] for r in [b, c]])
            for key in ['p99', 'p99.9']:
                values[key] = [r['report']['latencySeconds']['percentiles'][key] for r in [b, c]]
            pairs.append({k: 100 * (v[1] / v[0] - 1) for k, v in values.items()})
        summary[tls] = dict(pairs=pairs, median={k: statistics.median(r[k] for r in pairs) for k in pairs[0]})
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
