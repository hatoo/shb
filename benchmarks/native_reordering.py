"""Independent schedule, receipt and socket evidence checks."""
import json
import os
from pathlib import Path


def suite_cases(matrix):
    """A fixed, bounded plan; configured chunks are not observed queue depth."""
    require(matrix in ('large', 'small'), 'unknown reordering matrix')
    sizes = ((525312, 1024),) if matrix == 'large' else ((128, 64), (4096, 256), (16384, 256))
    modes = ('ordered', 'reverse', 'mixed', 'duplicates') if matrix == 'large' else ('ordered', 'reverse', 'mixed')
    cases = [dict(reader=reader, mode=mode, fault='none', requests=3, body_bytes=size, chunk=chunk)
             for size, chunk in sizes for mode in modes
             for reader in ('aioquic', 'shb', 'exposure')]
    faults = ('drop-once', 'missing-prefix', 'missing-fin', 'corrupt') if matrix == 'large' else ('missing-prefix', 'missing-fin', 'corrupt')
    size, chunk = sizes[0]
    cases += [dict(reader='aioquic', mode='reverse', fault=fault, requests=1, body_bytes=size, chunk=chunk)
              for fault in faults]
    for case in cases:
        prefix = '' if matrix == 'large' else f"{case['body_bytes']}-{case['chunk']}-"
        case['case'] = prefix + f"{case['reader']}-{case['mode']}-{case['fault']}"
    return cases


def suite_coverage(matrix, results):
    """Require each planned case once, and retain actual native/wire exposure."""
    expected = suite_cases(matrix)
    require(len(results) == len(expected), 'incomplete matrix coverage')
    coverage = []
    for case, result in zip(expected, results):
        require(result['case'] == case['case'], 'missing, duplicate or reordered matrix case')
        summary = result['summary']
        require(summary.get('passed') is True, 'matrix case did not pass')
        for key in ('mode', 'fault', 'requests', 'body_bytes', 'chunk'):
            require(summary.get(key) == case[key], f'matrix {key} mismatch')
        require(summary.get('reader') == ('aioquic' if case['reader'] == 'aioquic' else 'shb'),
                'matrix reader mismatch')
        row = dict(case)
        if case['fault'] in ('missing-prefix', 'missing-fin', 'corrupt'):
            require('rejected' in summary, 'negative control was not specifically rejected')
            rejected = summary['rejected']
            require(rejected.get('ended') is False, 'negative control completed unexpectedly')
            if case['fault'] == 'corrupt':
                require('wrong response bytes' in rejected.get('reason', '') and
                        0 <= rejected['body_bytes'] < case['body_bytes'],
                        'corruption missed the byte oracle')
            else:
                delivered = case['body_bytes'] if case['fault'] == 'missing-fin' else 0
                require(rejected.get('reason') == 'deadline' and rejected.get('body_bytes') == delivered,
                        'negative control reached the wrong blocked state')
            row['rejected'] = rejected
        else:
            require('rejected' not in summary, 'positive case was rejected')
            schedule = summary['schedule']
            row['configured_suffix_chunks'] = (case['body_bytes'] - 1) // case['chunk']
            row['ack_fences'] = len(schedule['fences'])
            if matrix == 'small':
                require(schedule['transport'].get('lost_packets') == 0, 'unexpected small-case packet loss')
            if case['reader'] == 'aioquic':
                require(summary.get('independent_completed') == case['requests'] and
                        summary.get('body_bytes_verified') == case['requests'] * case['body_bytes'],
                        'independent body/completion coverage mismatch')
                require(len(summary['wire']) == case['requests'], 'missing independent wire stream')
                row['wire'] = summary['wire']
            else:
                from h3_response_flight import validate_client
                validate_client(summary['report'], 0, case['requests'], 1, 1)
            if case['reader'] == 'exposure':
                exposure = summary['exposure']
                streams = exposure['streams']
                validate_observations(exposure['bodies'], streams, case['requests'],
                                      case['body_bytes'], case['chunk'], case['mode'])
                row['observed_peak_pending'] = [s['peak_pending'] for s in streams]
                row['observed_final_bytes'] = [s['final_size'] for s in streams]
                row['observed_credited_bytes'] = [s['credited_bytes'] for s in streams]
                row['observed_consumed_bytes'] = [s['read_offset'] for s in streams]
        coverage.append(row)
    return dict(matrix=matrix, timing_eligible=False, cases=coverage)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def covers(ranges, lo, hi):
    for start, end in sorted(ranges):
        if start > lo:
            return False
        lo = max(lo, end)
        if lo >= hi:
            return True
    return lo >= hi


def records(stderr, prefix):
    return [json.loads(line[len(prefix):]) for line in stderr.splitlines() if line.startswith(prefix)]


def validate_exposure(stderr, requests, size, chunk, mode):
    bodies = records(stderr, 'NATIVE_BODY ')
    streams = records(stderr, 'NATIVE_EXPOSURE ')
    return validate_observations(bodies, streams, requests, size, chunk, mode)


def validate_observations(bodies, streams, requests, size, chunk, mode):
    require(len(bodies) == requests and all(r == {'bytes': size} for r in bodies),
            'observer did not verify every response body byte')
    # Only completed request streams are retired into the pool. Control and
    # incomplete request streams cannot substitute for these records.
    require(len(streams) == requests, 'missing or duplicate retired stream')
    for stream in streams:
        require(stream['final_size'] is not None and stream['final_size'] > size,
                'missing response final size')
        require(stream['read_offset'] == stream['final_size'] == stream['credited_bytes'],
                'received/consumed/final-size credit mismatch')
        require(stream['ready'] == stream['pending'] == 0, 'unconsumed response bytes')
        if mode == 'ordered':
            require(stream['peak_pending'] == 0, 'ordered control unexpectedly queued fragments')
        else:
            require(stream['peak_pending'] >= (size - 1) // chunk, 'native queue exposure below target')
    return dict(bodies=bodies, streams=streams)


def validate_schedule(stderr, requests, size, chunk, mode):
    rows = records(stderr, 'NATIVE_REORDER ')
    arms = [r for r in rows if r['event'] == 'armed']
    fences = [r for r in rows if r['event'] == 'fence']
    require(len(arms) == requests, 'response body did not arm exactly one schedule per request')
    require(len(fences) == (0 if mode == 'ordered' else requests), 'missing or duplicate ACK fence')
    for arm in arms:
        require(arm['end'] - arm['start'] == size and arm['chunk'] == chunk and arm['mode'] == mode,
                'wrong armed workload')
    for fence, arm in zip(fences, arms):
        require((fence['start'], fence['end']) == (arm['start'], arm['end']), 'fence range mismatch')
        require(fence['suffix_bytes_acked'] == size - chunk, 'incomplete suffix ACK count')
        require(fence['distinct_chunks'] == (size - 1) // chunk, 'wrong fragment count')
    transports = records(stderr, 'NATIVE_TRANSPORT ')
    require(len(transports) == 1, 'one complete connection transport ledger required')
    for row in transports:
        for name in ('sent_datagrams', 'received_datagrams', 'sent_bytes', 'received_bytes'):
            require(type(row.get(name)) is int and row[name] > 0, f'missing transport {name}')
    return dict(armed=arms, fences=fences, transport=transports[0])


def validate_wire(qlog, streams, body_start, size, chunk, mode):
    """Use independently decoded wire frames and outgoing ACKs, not peer logs.

    Before the first withheld-prefix byte arrives, every suffix byte must have
    been received in a packet covered by a prior outgoing ACK. Packet-number
    ranges are inclusive in qlog; stream byte ranges are half-open.
    """
    require(len(qlog['traces']) == 1, 'exactly one qlog connection required')
    states = {sid: dict(suffix=[], acked=[], fenced=False, fin_before_prefix=False,
                        received_fin=False, distinct=set()) for sid in streams}
    ack_ranges = []
    for event in qlog['traces'][0]['events']:
        data = event['data']
        if event['name'] == 'transport:packet_sent':
            if data['header']['packet_type'] != '1RTT':
                continue
            for frame in data['frames']:
                if frame['frame_type'] == 'ack':
                    ack_ranges.extend((lo, hi + 1) for lo, hi in frame['acked_ranges'])
        elif event['name'] == 'transport:packet_received':
            if data['header']['packet_type'] != '1RTT':
                continue
            pn = int(data['header']['packet_number'])
            for frame in data['frames']:
                if frame['frame_type'] != 'stream' or frame['stream_id'] not in states:
                    continue
                state = states[frame['stream_id']]
                start, end = frame['offset'], frame['offset'] + frame['length']
                prefix_part = start < body_start + chunk and end > body_start
                if frame['fin']:
                    state['received_fin'] = True
                    if not state['fenced'] and not prefix_part:
                        state['fin_before_prefix'] = True
                if mode != 'ordered' and prefix_part and not state['fenced']:
                    acked = [(lo, hi) for lo, hi, packet in state['suffix']
                             if covers(ack_ranges, packet, packet + 1)]
                    require(covers(acked, body_start + chunk, body_start + size),
                            'prefix arrived before independent suffix ACK fence')
                    state['acked'] = acked
                    state['fenced'] = True
                if not state['fenced'] and end > body_start + chunk:
                    span = (max(start, body_start + chunk), min(end, body_start + size))
                    if span[0] < span[1]:
                        state['suffix'].append((*span, pn))
                        state['distinct'].add(span)
    result = {}
    for sid, state in states.items():
        require(state['received_fin'], 'missing wire FIN')
        if mode != 'ordered':
            require(state['fenced'], 'missing prefix release')
            require(len(state['distinct']) >= (size - 1) // chunk, 'insufficient distinct suffix fragments')
            require(state['fin_before_prefix'], 'FIN-before-gap case was not exercised')
        result[sid] = dict(distinct_suffix_frames=len(state['distinct']),
                           ack_fenced=state['fenced'], fin_before_prefix=state['fin_before_prefix'])
    return result


def socket_evidence(pid, port):
    """Require an owned, still-live UDP socket; never substitute a global row."""
    inodes = set()
    for path in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            target = path.readlink().as_posix()
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[8:-1])
    found = []
    for protocol in ('udp', 'udp6'):
        for line in (Path('/proc') / str(pid) / 'net' / protocol).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[9] in inodes and int(fields[1].split(':')[1], 16) == port:
                found.append(dict(pid=pid, inode=int(fields[9]), port=port,
                                  receive_queue=int(fields[4].split(':')[1], 16),
                                  drops=int(fields[-1]), row=line, protocol=protocol))
    require(len(found) == 1, 'missing or ambiguous owned UDP socket')
    require(found[0]['drops'] == 0, 'owned UDP socket dropped packets')
    return found[0]


def udp_snapshot():
    lines = Path('/proc/net/snmp').read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith('Udp:'):
            return dict(namespace=os.readlink('/proc/self/ns/net'),
                        host_namespace=os.environ['NATIVE_REORDER_PARENT_NETNS'],
                        counters=dict(zip(line.split()[1:], map(int, lines[i + 1].split()[1:]))))
    raise ValueError('missing UDP namespace counters')


def validate_udp(before, after):
    require(before['namespace'] == after['namespace'], 'network namespace changed')
    require(before['namespace'] != before['host_namespace'], 'private network namespace required')
    delta = {k: after['counters'][k] - v for k, v in before['counters'].items()}
    require(all(v >= 0 for v in delta.values()), 'UDP counters decreased')
    for key in ('InErrors', 'RcvbufErrors', 'SndbufErrors', 'InCsumErrors'):
        require(delta.get(key) == 0, f'UDP {key} must be available and zero: {delta}')
    require(delta['InDatagrams'] > 0 and delta['OutDatagrams'] > 0, 'missing UDP traffic')
    return delta
