"""Validate the distinct, promising large-response workload without changing small-response results."""
from pathlib import Path
import argparse, hashlib, json, math, os, signal, socket, statistics, subprocess, sys, time
parser = argparse.ArgumentParser(description=__doc__)
for name in ['baseline', 'candidate', 'output']:
    parser.add_argument('--' + name, required=True, type=lambda p: Path(p).resolve())
args = parser.parse_args()
DEST = args.output
DEST.mkdir()
BASELINE = args.baseline
CANDIDATE = args.candidate
PEER = Path(__file__).with_name('h1-close-peer.py')
N = 131072
WARM = 8192
PORT = 38791
hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [BASELINE, CANDIDATE, PEER]}
(DEST / 'inputs.json').open('x').write(json.dumps(dict(hashes=hashes, requests=N, warmup=WARM, body=65537, connections=1, client_cpu=8, server_cpu=1, primary_pairs=4, confirm_pairs=3, control_pairs=2, threshold_percent=3, control_median_limit=1.5, control_max_limit=3), indent=2) + '\n')

def dump(path, data):
    path.open('x').write(json.dumps(data, indent=2) + '\n')

def cpu(pid):
    stat = Path(f'/proc/{pid}/stat').read_text().split(') ')[1].split()
    tick = os.sysconf('SC_CLK_TCK')
    return [int(stat[11]) / tick, int(stat[12]) / tick]

def report(path, n):
    r = json.loads(path.read_text())
    assert r['requests'] == dict(total=n, ok=n, errors=0, connectErrors=0)
    assert r['latencySamples'] == n and r['statusCodes'] == {'200': n}
    assert r['bytesSent'] == 60 * n and r['bytesReceived'] == 65579 * n, (r['bytesSent'], r['bytesReceived'], n)
    assert r['protocol'] == 'HTTP/1.1' and r['connections'] == 1 and (r['threads'] == 1) and (r['url'] == f'http://127.0.0.1:{PORT}/')
    assert math.isclose(r['durationSeconds'] * r['requestsPerSec'], n, rel_tol=1e-10)
    return r

def client(binary, n, dest, label):
    cmd = ['taskset', '-c', '8', str(binary), '-j', '-t', '1', '-c', '1', '-n', str(n), '--disable-keepalive', '--batch-size', '1', '--timeout', '10s', f'http://127.0.0.1:{PORT}/']
    command = ['/usr/bin/time', '-f', '%U %S %e %M', '-o', str(dest / (label + '.cpu')), *cmd]
    start = time.monotonic_ns()
    with (dest / (label + '.json')).open('x') as out, (dest / (label + '.stderr')).open('x') as err:
        r = subprocess.run(command, stdout=out, stderr=err, timeout=180)
    stop = time.monotonic_ns()
    assert r.returncode == 0
    result = report(dest / (label + '.json'), n)
    usage = list(map(float, (dest / (label + '.cpu')).read_text().split()))
    assert len(usage) == 4 and all((v >= 0 for v in usage))
    assert result['durationSeconds'] <= (stop - start) / 1000000000.0
    return dict(command=command, start_ns=start, stop_ns=stop, report=result, cpu=usage)

def run(binary, dest):
    global PORT
    for attempt in range(100):
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            chosen = reserve.getsockname()[1]
        prior = [line for line in Path('/proc/net/tcp').read_text().splitlines()[1:] if any((int(line.split()[i].split(':')[1], 16) == chosen for i in [1, 2]))]
        if chosen not in used_ports and (not prior):
            break
    else:
        raise RuntimeError('no fresh destination port found')
    PORT = chosen
    used_ports.add(PORT)
    dest.mkdir()
    dump(dest / 'port.json', dict(port=PORT, prior_entries=prior, used_before=False))
    assert all((hashlib.sha256(Path(p).read_bytes()).hexdigest() == h for p, h in hashes.items()))
    with (dest / 'server.stderr').open('x') as err:
        process = subprocess.Popen([sys.executable, str(PEER), '--port', str(PORT), '--requests', str(N + WARM), '--ledger', str(dest / 'peer.json')], stdout=subprocess.PIPE, stderr=err, text=True, start_new_session=True)
        try:
            assert process.stdout.readline().strip() == 'READY'
            assert os.sched_getaffinity(process.pid) == {1}
            warm = client(binary, WARM, dest, 'warmup')
            before = cpu(process.pid)
            measured = client(binary, N, dest, 'measured')
            after = cpu(process.pid)
            deadline = time.monotonic() + 5
            while not (dest / 'peer.json').exists():
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
            ledger = json.loads((dest / 'peer.json').read_text())
            assert ledger == dict(requests=N + WARM, accepted=N + WARM, bytes_received=(N + WARM) * 60, bytes_sent=(N + WARM) * 65579, body_size=65537, response_size=65579), ledger
            row = dict(binary=str(binary), warmup=warm, measured=measured, peer=ledger, server_cpu=[b - a for a, b in zip(before, after)], server_alive=process.poll() is None)
            row['rate'] = measured['report']['requestsPerSec']
            row['client_cores'] = sum(measured['cpu'][:2]) / measured['report']['durationSeconds']
            row['server_cores'] = sum(row['server_cpu']) / measured['report']['durationSeconds']
            dump(dest / 'summary.json', row)
            return row
        finally:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
            process.stdout.close()
used_ports = set()
gate = dict(decision='AWAITING_PERFORMANCE_VALIDATION', workload='sequential plain HTTP/1 close-after-one, 65537-byte body, independent Python peer', phases={})
for phase, npairs in [('controls', 2), ('primary', 4), ('confirm', 3)]:
    folder = DEST / phase
    folder.mkdir()
    pairs = []
    rows = []
    for pair in range(npairs):
        order = ['baseline', 'candidate']
        if (pair + int(phase == 'confirm')) % 2:
            order.reverse()
        matched = {}
        for variant in order:
            binary = BASELINE if variant == 'baseline' or phase == 'controls' else CANDIDATE
            row = run(binary, folder / f'{pair}-{variant}')
            row.update(pair=pair, variant=variant)
            rows.append(row)
            matched[variant] = row
            print(phase, pair, variant, round(row['rate'], 3), 'client', round(row['client_cores'], 3), 'server', round(row['server_cores'], 3), flush=True)
        a, b = (matched['baseline'], matched['candidate'])
        assert a['peer'] == b['peer']
        pairs.append(dict(pair=pair, rps_percent=100 * (b['rate'] / a['rate'] - 1), cpu_percent=100 * (sum(b['measured']['cpu'][:2]) / sum(a['measured']['cpu'][:2]) - 1), p999_percent=100 * (b['measured']['report']['latencySeconds']['percentiles']['p99.9'] / a['measured']['report']['latencySeconds']['percentiles']['p99.9'] - 1)))
    summary = dict(rows=rows, pairs=pairs, median_rps_percent=statistics.median((p['rps_percent'] for p in pairs)))
    dump(folder / 'summary.json', summary)
    gate['phases'][phase] = {k: v for k, v in summary.items() if k != 'rows'}
    print(phase, gate['phases'][phase], flush=True)
    if phase != 'controls' and (summary['median_rps_percent'] < 3 or not all((p['rps_percent'] > 0 for p in pairs))):
        gate['reason'] = phase + ' did not reproduce the screening improvement'
        break
    if phase == 'controls':
        if abs(summary['median_rps_percent']) >= 1.5 or max((abs(p['rps_percent']) for p in pairs)) >= 3:
            gate['reason'] = 'identical controls failed; environment unsuitable for small comparisons'
            break
        gate['controls_passed'] = True
    if phase == 'confirm':
        gate['performance_passed'] = True
        gate['reason'] = 'fresh-port primary, independent confirmation and single control retry passed'
dump(DEST / 'gate.json', gate)
