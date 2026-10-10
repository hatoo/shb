#!/usr/bin/env python3
"""Transparent HTTP/2 response gate; fixed hfast constructs every response.
All connections first receive one request. Hold the first complete response
on inactive connections; release active connections together after setup.
Release held responses after the active group has consumed the remaining
counted budget. No request/response is dropped, rewritten or fabricated.
"""
from pathlib import Path
import argparse, json, os, resource, selectors, socket, subprocess, time, statistics
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--baseline', type=Path, required=True)
p.add_argument('--candidate', type=Path, required=True)
p.add_argument('--server', type=Path, required=True, help='Fixed hfast executable')
p.add_argument('--out', type=Path, required=True)
p.add_argument('--phase', choices=['primary', 'confirmation'], required=True)
p.add_argument('--pairs', type=int, default=3)
p.add_argument('--client-cpu', type=int, default=2)
p.add_argument('--proxy-cpu', type=int, default=4)
p.add_argument('--case', action='append', help='connections:active:requests; repeatable')
a = p.parse_args()
o = a.out.resolve()
o.mkdir(parents=True, exist_ok=True)
rows = []
binaries = {v: getattr(a, v).resolve() for v in ['baseline', 'candidate', 'server']}
assert all((v.is_file() for v in binaries.values()))
assert a.pairs > 0
os.sched_setaffinity(0, {a.proxy_cpu})
cases = [tuple(map(int, c.split(':'))) for c in a.case] if a.case else [(16384, 1, 32768), (16384, 8, 65536)]
assert all((0 < act <= c <= 1048576 and n >= c for c, act, n in cases))
if a.phase == 'confirmation':
    cases.reverse()
metadata = dict(binaries={k: {'path': str(v), 'sha256': __import__('hashlib').sha256(v.read_bytes()).hexdigest()} for k, v in binaries.items()}, cases=cases, pairs=a.pairs, client_cpu=a.client_cpu, proxy_cpu=a.proxy_cpu, phase=a.phase, kernel=os.uname().release, connect_timeout='30s', request_timeout=None, warmup_pair=-1)
with (o / f'{a.phase}-manifest.json').open('x') as f:
    json.dump(metadata, f, indent=2)

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]
server_port = port()

class Peer:

    def __init__(self, client, upstream, index, active):
        self.client, self.upstream, self.index, self.active = (client, upstream, index, active)
        self.up = bytearray()
        self.down = bytearray()
        self.frames = bytearray()
        self.responses = 0
        self.closed = False
with (o / f'h2-flush-{a.phase}-hfast.log').open('x') as server_log:
    server = subprocess.Popen([str(binaries['server']), '--tcp', str(server_port), '--quic', '0', '--threads', '1'], stdout=server_log, stderr=subprocess.STDOUT)
    try:
        time.sleep(0.2)
        assert server.poll() is None
        for pair in range(-1, a.pairs):
            for connections, active, requests in cases:
                for variant in ['candidate', 'baseline'] if (pair + (a.phase == 'confirmation')) % 2 else ['baseline', 'candidate']:
                    stem = f'h2-flush-{a.phase}-p{pair}-c{connections}-a{active}-{variant}'
                    sel = selectors.DefaultSelector()
                    listen = socket.socket()
                    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listen.bind(('127.0.0.1', 0))
                    listen.listen(32768)
                    listen.setblocking(False)
                    sel.register(listen, selectors.EVENT_READ, None)
                    peers = []
                    ready = 0
                    total_responses = 0
                    active_responses = 0
                    gate = None
                    held_released = None
                    goal = requests - (connections - active)
                    forwarded_down = 0
                    forwarded_up = 0
                    teardown_resets = 0
                    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
                    start = time.monotonic()
                    proxy_cpu = time.process_time()
                    command = ['taskset', '-c', str(a.client_cpu), str(binaries[variant]), '--http2', '--connect-timeout', '30s', '-j', '-c', str(connections), '-p', '1', '-t', '1', '-n', str(requests), f'http://127.0.0.1:{listen.getsockname()[1]}/']
                    with (o / f'{stem}-report.json').open('x') as stdout, (o / f'{stem}.stderr').open('x') as stderr:
                        client = subprocess.Popen(command, stdout=stdout, stderr=stderr)

                        def interest(peer, side):
                            sock = peer.client if side == 'client' else peer.upstream
                            events = selectors.EVENT_READ
                            if side == 'client' and peer.down and (gate is not None) and (peer.active or held_released is not None) or (side == 'upstream' and peer.up):
                                events |= selectors.EVENT_WRITE
                            sel.modify(sock, events, (peer, side))

                        def close(peer):
                            peer.closed = True
                            for sock in [peer.client, peer.upstream]:
                                sel.unregister(sock)
                                sock.close()
                        try:
                            while client.poll() is None:
                                assert time.monotonic() - start < 120, (stem, ready, total_responses, active_responses, gate)
                                for key, events in sel.select(0.01):
                                    if key.data is None:
                                        while True:
                                            try:
                                                down, _ = listen.accept()
                                            except BlockingIOError:
                                                break
                                            index = len(peers)
                                            assert index < connections
                                            up = socket.create_connection(('127.0.0.1', server_port), timeout=5)
                                            for sock in [down, up]:
                                                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                                                sock.setblocking(False)
                                            peer = Peer(down, up, index, index >= connections - active)
                                            peers.append(peer)
                                            sel.register(down, selectors.EVENT_READ, (peer, 'client'))
                                            sel.register(up, selectors.EVENT_READ, (peer, 'upstream'))
                                        continue
                                    peer, side = key.data
                                    if peer.closed:
                                        continue
                                    sock = key.fileobj
                                    if events & selectors.EVENT_READ:
                                        try:
                                            data = sock.recv(262144)
                                        except BlockingIOError:
                                            data = None
                                        except ConnectionResetError:
                                            # A counted run may reset sockets during teardown.
                                            # The complete client report must still prove delivery.
                                            assert total_responses == requests, (stem, 'early reset', side, peer.index, total_responses, requests)
                                            teardown_resets += 1
                                            close(peer)
                                            continue
                                        if data == b'':
                                            assert total_responses == requests, (stem, 'early EOF', side, total_responses, requests)
                                            close(peer)
                                            continue
                                        if data:
                                            if side == 'client':
                                                peer.up.extend(data)
                                                interest(peer, 'upstream')
                                            else:
                                                peer.down.extend(data)
                                                peer.frames.extend(data)
                                                pos = 0
                                                while len(peer.frames) - pos >= 9:
                                                    size = int.from_bytes(peer.frames[pos:pos + 3], 'big')
                                                    end = pos + 9 + size
                                                    if end > len(peer.frames):
                                                        break
                                                    kind, flags = peer.frames[pos + 3:pos + 5]
                                                    if kind in [0, 1] and flags & 1:
                                                        peer.responses += 1
                                                        total_responses += 1
                                                        if peer.responses == 1:
                                                            ready += 1
                                                        if peer.active:
                                                            active_responses += 1
                                                    pos = end
                                                del peer.frames[:pos]
                                                if ready == connections and gate is None:
                                                    gate = time.monotonic()
                                                    for pp in peers:
                                                        interest(pp, 'client')
                                                if gate is not None and active_responses >= goal and (held_released is None):
                                                    assert active_responses == goal
                                                    held_released = time.monotonic()
                                                    for pp in peers:
                                                        if not pp.closed:
                                                            interest(pp, 'client')
                                                interest(peer, 'client')
                                    if events & selectors.EVENT_WRITE:
                                        buf = peer.down if side == 'client' else peer.up
                                        try:
                                            sent = sock.send(buf)
                                        except BlockingIOError:
                                            sent = 0
                                        del buf[:sent]
                                        if side == 'client':
                                            forwarded_down += sent
                                        else:
                                            forwarded_up += sent
                                        interest(peer, side)
                            client.wait()
                            end = time.monotonic()
                            cpu = time.process_time() - proxy_cpu
                            assert client.returncode == 0, (o / f'{stem}.stderr').read_text()
                        finally:
                            if client.poll() is None:
                                client.kill()
                                client.wait()
                            for pp in peers:
                                if not pp.closed:
                                    close(pp)
                            sel.unregister(listen)
                            listen.close()
                            sel.close()
                    report = json.loads((o / f'{stem}-report.json').read_text())
                    assert report['requests'] == dict(ok=requests, errors=0, connectErrors=0, total=requests), report
                    assert report['statusCodes'] == {'200': requests} and report['latencySeconds'] is not None
                    assert total_responses == requests and ready == connections and (gate is not None) and (held_released is not None)
                    assert all((pp.responses == 1 for pp in peers if not pp.active))
                    after = resource.getrusage(resource.RUSAGE_CHILDREN)
                    row = dict(phase=a.phase, pair=pair, variant=variant, connections=connections, active=active, requests=requests, command=command, report=report, release_wall_s=end - gate, active_window_s=held_released - gate, setup_wall_s=gate - start, process_wall_s=end - start, client_cpu_s=after.ru_utime + after.ru_stime - (usage.ru_utime + usage.ru_stime), proxy_cpu_s=cpu, exact_hfast_responses=total_responses, held_responses=connections - active, teardown_resets=teardown_resets, forwarded_down=forwarded_down, forwarded_up=forwarded_up)
                    with (o / f'{stem}-result.json').open('x') as f:
                        json.dump(row, f, indent=2)
                    rows.append(row)
                    print(stem, 'release', round(row['release_wall_s'], 6), 'active', round(row['active_window_s'], 6), 'cpu', round(row['client_cpu_s'], 6), flush=True)
    finally:
        server.terminate()
        server.wait(timeout=5)
with (o / f'h2-flush-{a.phase}-results.json').open('x') as f:
    json.dump(rows, f, indent=2)
summary = {}
for c, act, n in cases:
    metrics = {}
    for metric in ['release_wall_s', 'active_window_s', 'client_cpu_s', 'process_wall_s']:
        changes = []
        for pair in range(a.pairs):
            r = {r['variant']: r for r in rows if r['connections'] == c and r['active'] == act and (r['pair'] == pair)}
            changes.append(100 * (r['candidate'][metric] / r['baseline'][metric] - 1))
        metrics[metric] = {'median_pct': statistics.median(changes), 'changes_pct': changes}
    summary[f'c{c}-a{act}'] = metrics
with (o / f'h2-flush-{a.phase}-summary.json').open('x') as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2), flush=True)
