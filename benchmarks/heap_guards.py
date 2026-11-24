#!/usr/bin/env python3
"""Bounded ordinary/small-response guards for frozen QUIC receive candidates.

No automatic acceptance. Each cell gets one identical-binary suitability screen,
then AB/BA/AB and reversed confirmation only if its preceding gate passes.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import time

from native_reordering import require, socket_evidence, udp_snapshot, validate_udp, validate_schedule
from h3_response_flight import validate_client, validate_peer
from report_accounting import validate_sample_accounting

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('native_measure', HERE / 'measure-native-reordering.py')
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)
measure.require = require
ERRORS = ('InErrors', 'RcvbufErrors', 'SndbufErrors', 'InCsumErrors',
          'NoPorts', 'MemErrors', 'IgnoredMulti')


def save(path, value):
    with Path(path).open('x') as out:
        json.dump(value, out, indent=2, allow_nan=False)
        out.write('\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def topology():
    rows = []
    for cpu in sorted(os.sched_getaffinity(0)):
        root = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
        rows.append(dict(cpu=cpu, core=int((root / 'core_id').read_text()),
                         socket=int((root / 'physical_package_id').read_text()),
                         siblings=(root / 'thread_siblings_list').read_text().strip()))
    return rows


def placement(rows):
    # Unmodified hfast's sole worker pins itself to CPU 0.
    server = next((r for r in rows if r['cpu'] == 0), None)
    require(server is not None, 'hfast CPU 0 is outside the allowed affinity')
    client = next((r for r in rows if (r['socket'], r['core']) !=
                   (server['socket'], server['core'])), None)
    require(client is not None, 'two distinct physical cores are required')
    return dict(server_cpu=0, client_cpu=client['cpu'])


def affinity(snapshot, cpu):
    require(snapshot['threads'] and all(r['affinity'] == [cpu]
            for r in snapshot['threads'].values()), 'process escaped its physical core')


def metrics(report, resource, peer_resource):
    validate_sample_accounting(report)
    count = report['requests']['ok']
    require(count > 0 and report['requests']['errors'] == report['requests']['connectErrors'] == 0,
            'unexpected client errors or empty population')
    require(report['statusCodes'] == {'200': count}, 'unexpected HTTP status')
    values = dict(rps=report['requestsPerSec'], seconds=report['durationSeconds'],
                  cpu_ns=(resource['user_s'] + resource['system_s']) * 1e9 / count,
                  peer_cpu_ns=(peer_resource['user_s'] + peer_resource['system_s']) * 1e9 / count,
                  p99=report['latencySeconds']['percentiles']['p99'],
                  p999=report['latencySeconds']['percentiles']['p99.9'])
    require(all(type(v) in (float, int) and math.isfinite(v) and v > 0 for v in values.values()),
            'missing/nonfinite timing evidence')
    require(math.isclose(values['rps'], count / values['seconds'], rel_tol=1e-9), 'RPS mismatch')
    return values | dict(samples=report['latencySamples'], completed=count)


def compare(a, b):
    return {k: 100 * (b[k] / a[k] - 1) for k in ('rps', 'cpu_ns', 'peer_cpu_ns', 'p99', 'p999')}


def suitable(pairs):
    # Engineering resolution bounds, not confidence intervals. Every pair must
    # meet them: a median cannot hide a noisy control or a tail excursion.
    return all(abs(p[k]) <= limit for p in pairs
               for k, limit in (('rps', 3), ('cpu_ns', 3), ('p99', 10), ('p999', 10)))


def guard_passes(pairs):
    return all(p['rps'] >= -3 and p['cpu_ns'] <= 3 and p['p99'] <= 10 and p['p999'] <= 10
               for p in pairs)


def udp_audit(before, after, traffic):
    if traffic:
        validate_udp(before, after)
    require(before['namespace'] == after['namespace'] != before['host_namespace'],
            'trial did not retain a private namespace')
    delta = {k: after['counters'][k] - v for k, v in before['counters'].items()}
    require(all(v >= 0 for v in delta.values()), 'UDP counters decreased')
    require(all(delta.get(k) == 0 for k in ERRORS), 'UDP error/drop counters changed or missing')
    return delta


def audit_native(row, config):
    require(row['passed'], 'native trial failed')
    cfg = row['configuration']
    for key in ('mode', 'body_bytes', 'chunk', 'requests'):
        require(cfg[key] == config[key], f'native workload changed: {key}')
    require(cfg['client_cpu'] == config['client_cpu'] and
            cfg['peer_cpus'] == str(config['server_cpu']) and cfg['peer_workers'] == 1,
            'native placement changed')
    require(cfg['inputs']['client']['sha256'] == config['inputs'][config['client']] and
            cfg['inputs']['peer']['sha256'] == config['inputs'][config['peer']], 'native binary changed')
    validate_client(row['report'], row['client_exit'], config['requests'], 1, 1)
    validate_peer(row['peer'], row['peer_exit'], config['requests'], config['body_bytes'], 1)
    require(row['schedule']['transport']['lost_packets'] == 0, 'transport loss')
    udp_audit(row['udp_start'], row['udp_end'], True)
    require(row['socket_start']['inode'] == row['socket_end']['inode'] and
            row['socket_start']['drops'] == row['socket_end']['drops'] == 0, 'socket identity/drop failure')
    for phase in ('start', 'end'):
        affinity(row['peer_threads_' + phase], config['server_cpu'])
    return metrics(row['report'], row['client_resource'], row['peer_resource'])


def ordinary_client(config, output, port):
    protocol = config['protocol']
    command = [sys.executable, str(HERE / 'measure-process.py'), str(output / 'client-resource.json'),
               'taskset', '-c', str(config['client_cpu']), config['client'],
               '-t', '1', '-c', '64', '-z', str(config['seconds']) + 's',
               '--timeout', '5s', '--batch-linger', '1', '-j']
    # Explicit --parallel requires an H2/H3 protocol in the production CLI.
    if protocol != 'h1':
        command += ['--http2' if protocol == 'h2' else '--http3', '-p', '32']
    command.append(('https' if protocol == 'h3' else 'http') + f'://127.0.0.1:{port}/')
    return command


def ordinary(config):
    output = Path(config['output'])
    output.mkdir(exist_ok=False)
    row = dict(configuration=config, passed=False, udp_start=udp_snapshot())
    server = None
    protocol = config['protocol']
    port = 18443 if protocol == 'h3' else 18083
    server_command = ['taskset', '-c', str(config['server_cpu']), config['hfast'],
                      '--threads', '1', '--tcp', '0' if protocol == 'h3' else str(port),
                      '--quic', str(port) if protocol == 'h3' else '0']
    save(output / 'server-command.json', server_command)
    try:
        with (output / 'server.stdout').open('x') as out, (output / 'server.stderr').open('x') as err:
            server = subprocess.Popen(server_command, stdout=out, stderr=err, start_new_session=True)
        deadline = time.monotonic() + 10
        # Read readiness from kernel socket tables without a test connection.
        while True:
            require(server.poll() is None, 'hfast exited during startup')
            table = 'udp' if protocol == 'h3' else 'tcp'
            lines = Path('/proc/net/' + table).read_text().splitlines()[1:]
            if any(int(line.split()[1].split(':')[1], 16) == port for line in lines):
                break
            require(time.monotonic() < deadline, 'hfast readiness timeout')
            time.sleep(.01)
        row['server_start'] = measure.thread_snapshot(server.pid)
        affinity(row['server_start'], config['server_cpu'])
        if protocol == 'h3':
            row['socket_start'] = socket_evidence(server.pid, port)
        command = ordinary_client(config, output, port)
        save(output / 'client-command.json', command)
        with (output / 'client.stdout').open('x') as out, (output / 'client.stderr').open('x') as err:
            client = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
            try:
                pid_file = output / 'client-resource.pid'
                deadline = time.monotonic() + 10
                while not pid_file.exists():
                    require(client.poll() is None and time.monotonic() < deadline, 'client startup failed')
                    time.sleep(.005)
                # Inherits taskset for its entire lifetime; also sample every live thread.
                time.sleep(.05)
                require(client.poll() is None, 'client exited before measurement; inspect client.stderr')
                row['client_affinity'] = measure.thread_snapshot(int(pid_file.read_text()))
                affinity(row['client_affinity'], config['client_cpu'])
                row['client_exit'] = client.wait(timeout=config['seconds'] + 20)
            finally:
                if client.poll() is None:
                    os.killpg(client.pid, signal.SIGKILL)
                    client.wait()
        require(row['client_exit'] == 0, 'client process failed')
        row['report'] = json.loads((output / 'client.stdout').read_text())
        report = row['report']
        require(report['protocol'] == {'h1': 'HTTP/1.1', 'h2': 'HTTP/2', 'h3': 'HTTP/3'}[protocol]
                and report['connections'] == 64 and report['threads'] == 1, 'ordinary workload changed')
        require(report['durationSeconds'] >= config['seconds'], 'request window ended early')
        row['client_resource'] = measure.resources(output / 'client-resource.json')
        require(server.poll() is None, 'server exited during trial')
        row['server_end'] = measure.thread_snapshot(server.pid)
        affinity(row['server_end'], config['server_cpu'])
        if protocol == 'h3':
            row['socket_end'] = socket_evidence(server.pid, port)
            require(row['socket_start']['inode'] == row['socket_end']['inode'], 'server socket changed')
        server.terminate()
        _, status, usage = os.wait4(server.pid, 0)
        server.returncode = os.waitstatus_to_exitcode(status)
        require(server.returncode == -signal.SIGTERM, 'unexpected server exit')
        row['peer_resource'] = dict(user_s=usage.ru_utime, system_s=usage.ru_stime,
                                    exit=server.returncode, max_rss_kib=usage.ru_maxrss)
        row['udp_end'] = udp_snapshot()
        row['udp_delta'] = udp_audit(row['udp_start'], row['udp_end'], protocol == 'h3')
        row['metrics'] = metrics(report, row['client_resource'], row['peer_resource'])
        require(row['metrics']['samples'] >= 10000, 'too few samples for tail guard')
        row['passed'] = True
    except BaseException as error:
        row['error'] = repr(error)
        raise
    finally:
        if server is not None and server.poll() is None:
            server.kill()
            server.wait()
        save(output / 'summary.json', row)


def launch(config, config_path):
    save(config_path, config)
    require(config['inputs'] == {p: digest(p) for p in config['inputs']}, 'frozen input changed')
    if config['kind'] == 'native':
        command = [sys.executable, str(HERE / 'measure-native-reordering.py'),
                   '--fixture-dir', str(HERE), '--peer', config['peer'],
                   '--peer-sha256', config['inputs'][config['peer']], '--shb', config['client'],
                   '--shb-sha256', config['inputs'][config['client']], '--output', config['output'],
                   '--mode', config['mode'], '--requests', str(config['requests']),
                   '--size', str(config['body_bytes']), '--chunk', str(config['chunk']),
                   '--client-cpu', str(config['client_cpu']), '--peer-cpus', str(config['server_cpu']),
                   '--peer-workers', '1', '--deadline', '120', '--namespace', 'sudo']
    else:
        command = ['unshare', '--net', '--pid', '--fork', '--mount-proc', '--kill-child=KILL',
                   'sh', '-c', 'ip link set lo up && exec "$@"', 'heap-guard',
                   'env', 'NATIVE_REORDER_PARENT_NETNS=' + os.readlink('/proc/self/ns/net'),
                   sys.executable, str(Path(__file__).resolve()), '--trial', str(config_path)]
    save(config_path.with_suffix('.command.json'), command)
    with config_path.with_suffix('.log').open('x') as log:
        # Namespace teardown kills owned descendants on an outer timeout.
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=150)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        save(config_path.with_suffix('.exit.json'), code)
        require(code == 0, f'trial failed; evidence retained at {config_path}')
    row = json.loads((Path(config['output']) / 'summary.json').read_text())
    if config['kind'] == 'native':
        # Replay the schedule against raw stderr, not only its summarized counts.
        schedule = validate_schedule((Path(config['output']) / 'peer/peer.stderr').read_text(),
                                     config['requests'], config['body_bytes'], config['chunk'], config['mode'])
        require(schedule == row['schedule'], 'schedule summary differs from raw evidence')
        return audit_native(row, config)
    require(row['passed'] and row['configuration'] == config, 'ordinary trial/config failed')
    return metrics(row['report'], row['client_resource'], row['peer_resource'])


def campaign(args):
    require(os.geteuid() == 0, 'owned network/PID namespaces require root')
    require(not any(k in os.environ for k in ('LD_PRELOAD', 'SHB_NATIVE_REORDER', 'NATIVE_REORDER_PARENT_NETNS')),
            'instrumented or nested campaign')
    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    inputs = {str(p): digest(p) for p in (args.baseline, args.candidate, args.peer, args.hfast)}
    rows = topology()
    save(output / 'environment.json', dict(topology=rows, kernel=platform.uname()._asdict(), inputs=inputs,
         namespace=os.readlink('/proc/self/ns/net'), argv=sys.argv, backend='native Linux loopback'))
    summary = dict(decision='AWAITING_PERFORMANCE_VALIDATION', cells=[])
    try:
        cpus = placement(rows)
        cells = [dict(name=p, kind='ordinary', protocol=p, seconds=5) for p in ('h1', 'h2', 'h3')]
        cells += [dict(name=f'{mode}-{size}', kind='native', mode=mode, body_bytes=size, chunk=chunk,
                       requests=10000) for size, chunk in ((128, 64), (4096, 256), (16384, 256))
                  for mode in ('ordered', 'reverse')]
        save(output / 'plan.json', dict(cells=cells, placement=cpus,
             phases=['control', 'primary', 'confirmation'], inputs=inputs,
             orders=['AB', 'BA', 'AB'], confirmation_orders=['BA', 'AB', 'BA'],
             control_limits_pct=dict(rps=3, cpu_ns=3, p99=10, p999=10),
             guard_limits_pct=dict(rps=-3, cpu_ns=3, p99=10, p999=10), retries=0))
        for cell in cells:
            entry = dict(cell=cell, phases={}, qualified=False)
            summary['cells'].append(entry)
            for phase in ('control', 'primary', 'confirmation'):
                orders = [('baseline', 'candidate'), ('candidate', 'baseline'), ('baseline', 'candidate')]
                if phase == 'confirmation':
                    orders = [order[::-1] for order in orders]
                schedule = [('warmup', 0, label) for label in orders[0]]
                schedule += [('measured', i, label) for i, order in enumerate(orders) for label in order]
                pairs, active = [], {}
                for kind, index, label in schedule:
                    name = f'{cell["name"]}-{phase}-{kind}-{index}-{label}'
                    client = str(args.baseline if phase == 'control' else getattr(args, label))
                    config = dict(cell, **cpus, client=client, peer=str(args.peer), hfast=str(args.hfast),
                                  inputs=inputs, output=str(output / name))
                    if kind == 'warmup':
                        if cell['kind'] == 'native':
                            config['requests'] = 128
                        else:
                            config['seconds'] = 1
                    result = launch(config, output / (name + '.json'))
                    if kind == 'measured':
                        require(result['samples'] >= 10000, 'insufficient measured tail samples')
                        active[label] = result
                        if len(active) == 2:
                            effect = compare(active['baseline'], active['candidate'])
                            pairs.append(effect)
                            save(output / f'{cell["name"]}-{phase}-pair{index}.json', dict(results=active, effect=effect))
                            active = {}
                entry['phases'][phase] = dict(pairs=pairs,
                    medians={k: statistics.median(p[k] for p in pairs) for k in pairs[0]})
                print(json.dumps(dict(cell=cell['name'], phase=phase, **entry['phases'][phase])), flush=True)
                save(output / f'{cell["name"]}-{phase}.json', entry['phases'][phase])
                if phase == 'control' and not suitable(pairs):
                    entry['deferred'] = 'identical binary cannot resolve this guard; no retry'
                    break
                if phase != 'control' and not guard_passes(pairs):
                    entry['deferred'] = 'guard screen failed; no regression or equivalence conclusion'
                    break
                if phase == 'confirmation':
                    entry['qualified'] = True
            save(output / (cell['name'] + '-summary.json'), entry)
        summary['all_guards_qualified'] = all(e['qualified'] for e in summary['cells'])
        require(inputs == {p: digest(p) for p in inputs}, 'frozen binary changed during campaign')
    except BaseException as error:
        summary['error'] = repr(error)
        raise
    finally:
        save(output / 'summary.json', summary)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--trial':
        ordinary(json.loads(Path(sys.argv[2]).read_text()))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        for name in ('baseline', 'candidate', 'peer', 'hfast', 'output'):
            parser.add_argument(name, type=lambda s: Path(s).resolve())
        campaign(parser.parse_args())
