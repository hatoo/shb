#!/usr/bin/env python3
"""Compare complete one-MiB HTTP/1 uploads against a fixed OpenSSL peer."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import select
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'candidate', 'peer', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--requests', type=int, default=8192)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--client-cpu', default='2')
    parser.add_argument('--server-cpus', default='8,10,12,14')
    args = parser.parse_args()
    if args.requests < 8 or args.rounds < 1:
        parser.error('requests must be at least 8 and rounds at least 1')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binaries = {name: getattr(args, name).resolve()
                for name in ['baseline', 'candidate', 'peer']}
    body = out / 'body'
    body.write_bytes(bytes(33 + i % 90 for i in range(1048576)))
    cert, key = out / 'cert.pem', out / 'key.pem'
    with (out / 'certificate.log').open('x') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-days', '1'],
                       stdout=log, stderr=log, check=True)
    manifest = dict(arguments={k: str(v) if isinstance(v, Path) else v
                               for k, v in vars(args).items()},
                    hashes={k: hashlib.sha256(v.read_bytes()).hexdigest()
                            for k, v in {**binaries, 'body': body}.items()})
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows = []
    for pair in range(args.rounds):
        for tls in (['12', '13'] if args.reverse else ['13', '12']):
            variants = (['baseline', 'candidate'] if (pair % 2 == 0) != args.reverse
                        else ['candidate', 'baseline'])
            for variant in variants:
                for warmup in [True, False]:
                    count = 64 if warmup else args.requests
                    stem = f'{pair}-{tls}-{variant}' + ('-warmup' if warmup else '')
                    peer_command = ['taskset', '-c', args.server_cpus,
                                    str(binaries['peer']), str(cert), str(key),
                                    tls, str(count), str(body), '0']
                    with (out / (stem + '.peer.stderr')).open('x') as log:
                        peer = subprocess.Popen(peer_command, stdout=subprocess.PIPE,
                                                stderr=log, text=True)
                        try:
                            assert select.select([peer.stdout], [], [], 10)[0], 'peer startup'
                            ready = peer.stdout.readline()
                            port = json.loads(ready)['port']
                            command = ['taskset', '-c', args.client_cpu,
                                       str(binaries[variant]), '-j', '-t', '1', '-c', '8',
                                       '-n', str(count), '--timeout', '10s', '-d', '@' + str(body),
                                       f'https://127.0.0.1:{port}/']
                            before = resource.getrusage(resource.RUSAGE_CHILDREN)
                            run = subprocess.run(command, capture_output=True, text=True,
                                                 timeout=120)
                            after = resource.getrusage(resource.RUSAGE_CHILDREN)
                            (out / (stem + '.stdout')).write_text(run.stdout)
                            (out / (stem + '.stderr')).write_text(run.stderr)
                            assert run.returncode == 0, run.stderr
                            report = json.loads(run.stdout)
                            assert report['requests'] == dict(ok=count, errors=0,
                                                              connectErrors=0, total=count)
                            assert report['statusCodes'] == {'200': count}
                            assert report['bytesSent'] >= count * 1048576
                            peer_output = peer.communicate(timeout=30)[0]
                            (out / (stem + '.peer.stdout')).write_text(ready + peer_output)
                            assert peer.returncode == 0, 'upload oracle failed'
                            ledger = json.loads(peer_output)
                            assert ledger['requests'] == count and ledger['connections'] == 8
                            assert ledger['body_bytes'] == count * 1048576
                            cpu_ns = 1e9 * (after.ru_utime + after.ru_stime
                                            - before.ru_utime - before.ru_stime) / count
                            row = dict(pair=pair, tls=tls, variant=variant, warmup=warmup,
                                       count=count, command=command, peer_command=peer_command,
                                       report=report, ledger=ledger, cpu_ns=cpu_ns)
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
    summary = {}
    for tls in ['12', '13']:
        pairs = []
        for pair in range(args.rounds):
            b, c = [next(r for r in rows if r['tls'] == tls and r['pair'] == pair
                         and r['variant'] == v and not r['warmup'])
                    for v in ['baseline', 'candidate']]
            values = dict(rps=[r['report']['requestsPerSec'] for r in [b, c]],
                          cpu_ns=[r['cpu_ns'] for r in [b, c]])
            for key in ['p99', 'p99.9']:
                values[key] = [r['report']['latencySeconds']['percentiles'][key] for r in [b, c]]
            pairs.append({k: 100 * (v[1] / v[0] - 1) for k, v in values.items()})
        summary[tls] = dict(pairs=pairs,
                            median={k: statistics.median(r[k] for r in pairs) for k in pairs[0]})
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
