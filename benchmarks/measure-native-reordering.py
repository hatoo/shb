#!/usr/bin/env python3
"""Measure frozen native QUIC binaries, retaining strict receipt/drop evidence.

No instrumented client, qlog reader, or Python datagram I/O is timed. Uses the
published correctness fixture as an explicit, hash-recorded dependency.
"""
import argparse
import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def resources(path):
    value = json.loads(path.read_text())
    require(value['exit'] == 0, 'measured process failed')
    for key in ('elapsed_s', 'user_s', 'system_s'):
        require(type(value[key]) in (int, float) and math.isfinite(value[key])
                and value[key] >= 0, 'invalid process resource measurement')
    require(value['elapsed_s'] > 0 and value['user_s'] + value['system_s'] > 0,
            'missing measured process work')
    return value


def thread_snapshot(pid):
    rows = {}
    for path in sorted((Path('/proc') / str(pid) / 'task').iterdir()):
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        rows[path.name] = dict(name=(path / 'comm').read_text().strip(),
                               user_ticks=int(fields[11]), system_ticks=int(fields[12]),
                               start_ticks=int(fields[19]),
                               affinity=sorted(os.sched_getaffinity(int(path.name))),
                               schedstat_ns=list(map(int, (path / 'schedstat').read_text().split())))
    return dict(clock_ticks=os.sysconf('SC_CLK_TCK'), threads=rows)


async def run(args):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    supervisor = Path(__file__).with_name('measure-process.py')
    config = dict(mode=args.mode, requests=args.requests, body_bytes=args.size,
                  chunk=args.chunk, client_cpu=args.client_cpu,
                  peer_cpus=args.peer_cpus, peer_workers=2,
                  connections=1, parallel=1, threads=1, timeout='5s',
                  run_deadline_s=args.deadline)
    inputs = dict(peer=args.peer, client=args.shb, supervisor=supervisor,
                  controller=Path(__file__),
                  receipts=args.fixture_dir / 'h3_response_flight.py',
                  schedule_oracle=args.fixture_dir / 'native_reordering.py',
                  accounting=args.fixture_dir / 'report_accounting.py')
    config['inputs'] = {k: dict(path=str(p.resolve()), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                        for k, p in inputs.items()}
    require(config['inputs']['client']['sha256'] == args.shb_sha256, 'wrong frozen client')
    require(config['inputs']['peer']['sha256'] == args.peer_sha256, 'wrong frozen peer')
    write(output / 'configuration.json', config)
    summary = dict(configuration=config, passed=False, udp_start=udp_snapshot())
    prefix = [sys.executable, str(supervisor), str(output / 'peer-resource.json'),
              'taskset', '-c', args.peer_cpus, 'env',
              f'SHB_NATIVE_REORDER={args.mode}:{args.size}:{args.chunk}']
    try:
        async with Peer(args.peer, output / 'peer', args.requests, args.size,
                        workers=2, deadline=args.deadline, prefix=prefix) as peer:
            peer_pid = int((output / 'peer-resource.pid').read_text())
            port = int(peer.address.split(':')[1])
            summary['socket_start'] = socket_evidence(peer_pid, port)
            summary['peer_affinity'] = sorted(os.sched_getaffinity(peer_pid))
            summary['peer_threads_start'] = thread_snapshot(peer_pid)
            command = [sys.executable, str(supervisor), str(output / 'client-resource.json'),
                       'taskset', '-c', str(args.client_cpu), str(args.shb),
                       '--http3', '-t', '1', '-c', '1', '-p', '1',
                       '-n', str(args.requests), '--timeout', '5s', '-j',
                       f'https://{peer.address}/response']
            write(output / 'client-command.json', command)
            begin = time.monotonic_ns()
            with (output / 'client.stdout').open('xb') as stdout, (output / 'client.stderr').open('xb') as stderr:
                process = await asyncio.create_subprocess_exec(*command, stdout=stdout, stderr=stderr,
                                                               start_new_session=True)
                try:
                    await asyncio.wait_for(process.wait(), args.deadline)
                finally:
                    if process.returncode is None:
                        await kill_group(process)
            summary['controller_client_elapsed_s'] = (time.monotonic_ns() - begin) / 1e9
            summary['client_exit'] = process.returncode
            report = json.loads((output / 'client.stdout').read_bytes())
            summary['report'] = report
            validate_client(report, process.returncode, args.requests, 1, 1)
            require('NATIVE_EXPOSURE ' not in (output / 'client.stderr').read_text(),
                    'instrumented observer cannot be a timing input')
            summary['client_resource'] = resources(output / 'client-resource.json')
            summary['socket_end'] = socket_evidence(peer_pid, port)
            summary['peer_threads_end'] = thread_snapshot(peer_pid)
            ledger, code = await peer.finish()
            summary.update(peer=ledger, peer_exit=code)
            validate_peer(ledger, code, args.requests, args.size, 1)
            summary['peer_resource'] = resources(output / 'peer-resource.json')
            summary['schedule'] = validate_schedule((peer.directory / 'peer.stderr').read_text(),
                                                   args.requests, args.size, args.chunk, args.mode)
            # Packet loss changes retransmission work; retain but exclude such runs.
            require(summary['schedule']['transport']['lost_packets'] == 0,
                    'transport packet loss makes this timing run ineligible')
        summary['udp_end'] = udp_snapshot()
        summary['udp_delta'] = validate_udp(summary['udp_start'], summary['udp_end'])
        summary['passed'] = True
    except BaseException as error:
        summary['error'] = repr(error)
        raise
    finally:
        if 'udp_end' not in summary:
            summary['udp_end'] = udp_snapshot()
            try:
                summary['udp_delta'] = validate_udp(summary['udp_start'], summary['udp_end'])
            except ValueError as error:
                summary['udp_error'] = str(error)
        write(output / 'summary.json', summary)
    print(json.dumps(dict(passed=True, mode=args.mode, requests=args.requests,
                         rps=report['requestsPerSec'],
                         client_cpu_s=sum(summary['client_resource'][k] for k in ('user_s', 'system_s')),
                         peer_cpu_s=sum(summary['peer_resource'][k] for k in ('user_s', 'system_s')))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--peer-sha256', required=True)
    parser.add_argument('--shb', type=Path, required=True)
    parser.add_argument('--shb-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('ordered', 'reverse', 'mixed', 'duplicates'), default='reverse')
    parser.add_argument('--requests', type=int, default=128)
    parser.add_argument('--size', type=int, default=513 * 1024)
    parser.add_argument('--chunk', type=int, default=1024)
    parser.add_argument('--client-cpu', type=int, default=2)
    parser.add_argument('--peer-cpus', default='4,6')
    parser.add_argument('--deadline', type=int, default=40)
    parser.add_argument('--namespace', choices=('user', 'sudo'), default='user')
    args = parser.parse_args()
    sys.path.insert(0, str(args.fixture_dir.resolve()))
    from h3_response_flight import Peer, kill_group, validate_client, validate_peer
    from native_reordering import require, socket_evidence, udp_snapshot, validate_schedule, validate_udp
    require(1 <= args.requests <= 512 and 64 <= args.chunk <= 1024, 'invalid bounded workload')
    require(2 * args.chunk <= args.size <= 16 * 1048576 and 1 <= args.deadline <= 120,
            'invalid body/deadline')
    peer_cpus = {int(c) for c in args.peer_cpus.split(',')}
    require(args.client_cpu not in peer_cpus and peer_cpus and
            peer_cpus | {args.client_cpu} <= os.sched_getaffinity(0), 'invalid CPU affinity')
    for name in ('peer', 'shb', 'output', 'fixture_dir'):
        setattr(args, name, getattr(args, name).resolve())
    if 'NATIVE_REORDER_PARENT_NETNS' not in os.environ:
        launcher = ['unshare', '-Urnpf', '--mount-proc', '--kill-child=KILL'] if args.namespace == 'user' else ['sudo', '-n', 'unshare', '--net', '--pid', '--fork', '--mount-proc', '--kill-child=KILL']
        command = [*launcher, 'sh', '-c', 'ip link set lo up && exec "$@"', 'native-timing',
                   'env', 'NATIVE_REORDER_PARENT_NETNS=' + os.readlink('/proc/self/ns/net'),
                   sys.executable, *sys.argv]
        raise SystemExit(subprocess.run(command).returncode)
    asyncio.run(run(args))
