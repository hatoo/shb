"""Matched production shb clients, one fixed native sparse-packet peer.

The peer verifies every injected packet in the client's wire ACKs. Only the
last packet in each batch elicits an ACK. No ACK-of-ACK is sent within a burst.
"""
import hashlib, json, pathlib, statistics, subprocess, sys
baseline, candidate, peer_path, output, phase = sys.argv[1:]
OUT = pathlib.Path(output).resolve()
OUT.mkdir(parents=True, exist_ok=True)
assert phase in ['smoke', 'primary', 'confirm']
clients = {'baseline': pathlib.Path(baseline).resolve(), 'candidate': pathlib.Path(candidate).resolve()}
peer = pathlib.Path(peer_path).resolve()
packets, requests, batch, pairs = {'smoke': (1024, 2, 32, 1), 'primary': (65536, 8, 32, 3), 'confirm': (65536, 8, 16, 3)}[phase]
(OUT / f'ack-storage-{phase}-manifest.json').open('x').write(json.dumps({name: dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for name,path in {**clients,'peer':peer}.items()}, indent=2)+'\n')

def run(variant, pair, warm=False):
    count = 2 if warm else requests
    size = 4096 if warm else packets
    stem = f'ack-storage-native-{phase}-{pair}-{variant}' + ('-warm' if warm else '')
    peer_cpu = OUT / (stem + '-peer-cpu.txt')
    client_cpu = OUT / (stem + '-client-cpu.txt')
    assert not peer_cpu.exists() and not client_cpu.exists()
    peer_command = ['/usr/bin/time','-o',str(peer_cpu),'-f','%U %S %e %M','taskset','-c','6',str(peer),str(size),str(count),str(batch)]
    with (OUT / (stem + '-peer.stderr')).open('x') as log:
        server = subprocess.Popen(peer_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        try:
            address = server.stdout.readline().strip()
            assert address.startswith('127.0.0.1:'), address
            command = ['/usr/bin/time','-o',str(client_cpu),'-f','%U %S %e %M','taskset','-c','8',str(clients[variant]),'--http3','-t','1','-c','1','-p','1','--batch-linger','1','--timeout','10s','-n',str(count),'-j','https://'+address+'/']
            result = subprocess.run(command, text=True, capture_output=True, timeout=150)
            (OUT / (stem + '.json')).open('x').write(result.stdout)
            (OUT / (stem + '.stderr')).open('x').write(result.stderr)
            stdout, _ = server.communicate(input='\n', timeout=15)
            (OUT / (stem + '-peer.json')).open('x').write(stdout)
            assert server.returncode == 0, log.name
            assert result.returncode == 0, result.stderr
            report = json.loads(result.stdout)
            peer_report = json.loads(stdout)
            assert report['requests'] == dict(total=count,ok=count,errors=0,connectErrors=0), report
            assert report['statusCodes'] == {'200':count} and report['latencySeconds'], report
            assert peer_report['responses'] == count and peer_report['sparse_packets'] == size*count and peer_report['errors'] == 0, peer_report
            user, system, wall, rss = map(float,client_cpu.read_text().split())
            return dict(phase=phase,pair=pair,variant=variant,warm=warm,report=report,peer=peer_report,user=user,system=system,wall=wall,maxrss_kb=rss,command=command,peer_command=peer_command)
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=10)

rows = []
for pair in range(pairs):
    order = ['baseline','candidate'] if (pair + (phase == 'confirm')) % 2 == 0 else ['candidate','baseline']
    for variant in order:
        if phase != 'smoke':
            rows.append(run(variant,pair,True))
        row = run(variant,pair)
        rows.append(row)
        print(json.dumps(dict(pair=pair,variant=variant,rps=row['report']['requestsPerSec'],cpu=row['user']+row['system'],rss=row['maxrss_kb'],sparse_packets=row['peer']['sparse_packets'])),flush=True)
(OUT / f'ack-storage-native-{phase}-results.json').open('x').write(json.dumps(rows,indent=2)+'\n')
rps, cpu, burst = [], [], []
for pair in range(pairs):
    r = {row['variant']: row for row in rows if row['pair']==pair and not row['warm']}
    rps.append(100*(r['candidate']['report']['requestsPerSec']/r['baseline']['report']['requestsPerSec']-1))
    cpu.append(100*((r['candidate']['user']+r['candidate']['system'])/(r['baseline']['user']+r['baseline']['system'])-1) if r['baseline']['user']+r['baseline']['system'] else None)
    burst.append(100*(sum(r['candidate']['peer']['burst_seconds'])/sum(r['baseline']['peer']['burst_seconds'])-1))
summary=dict(paired_rps_percent=rps,median_rps_percent=statistics.median(rps),paired_cpu_percent=cpu,median_cpu_percent=statistics.median([x for x in cpu if x is not None]) if any(x is not None for x in cpu) else None,paired_burst_seconds_percent=burst,requests=sum(row['report']['requests']['ok'] for row in rows),sparse_packets=sum(row['peer']['sparse_packets'] for row in rows),errors=0)
(OUT / f'ack-storage-native-{phase}-summary.json').open('x').write(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
