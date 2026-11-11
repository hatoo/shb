"""Replayable checks for the independent encrypted HTTP/3 GOAWAY peer.

Only the standard library is needed to check recorded evidence. Negative
controls edit copies of a successful wire/report ledger, never the client.
"""
from copy import deepcopy
import math

from report_accounting import validate_sample_accounting
import h3_control_fragments as fragments

CASES = ('mixed', 'decreasing', 'no-suffix', 'zero', 'ordinary', 'blocked-upload', *fragments.CASES)


class GoawayFailure(ValueError):
    def __init__(self, code, detail):
        self.code = code
        super().__init__(f'{code}: {detail}')


def require(condition, code, detail):
    if not condition:
        raise GoawayFailure(code, detail)


def expected(case, parallel):
    if case == 'zero' or case in fragments.INVALID:
        return 0, parallel, {}, [parallel]
    if case == 'mixed':
        return 7, 1, {'200': 1, '201': 1, '202': 1, '203': 1, '205': 3}, [8, 3]
    if case == 'fragmented':
        return 7, 1, {'200': 1, '201': 1, '203': 1, '205': 4}, [8, 4]
    if case == 'decreasing':
        return 8, 0, {'200': 1, '201': 1, '205': 6}, [8, 6]
    if case == 'blocked-upload':
        return 8, 0, {'200': 4, '205': 4}, [8, 4]
    return parallel, 0, {'200': parallel}, [parallel]


def validate_result(row):
    """Require both real client completion and the independently observed peer.

    The driver records failures before invoking this function. A timeout,
    crash, failed handshake or peer exception cannot pass a semantic control.
    """
    case, parallel = row['case'], row['parallel']
    require(case in CASES and parallel in (
        [8] if case in ('mixed', 'decreasing', 'blocked-upload', 'fragmented') else [1, 64]),
        'workload', (case, parallel))
    require(row['client_exit'] == 0, 'client-exit', row['client_exit'])
    require(not row['failures'], 'peer-failure', row['failures'])
    peers, report = row['peers'], row['report']
    require(peers and all(p['tls'] is True for p in peers), 'handshake', peers)
    require(isinstance(report, dict), 'missing-report', report)
    ok, errors, statuses, attempts = expected(case, parallel)
    requests = dict(total=parallel, ok=ok, errors=errors, connectErrors=0)
    require(report['requests'] == requests, 'request-budget', report['requests'])
    require('latencySamples' in report, 'missing-samples', 'latencySamples absent')
    require(type(report['latencySamples']) is int and report['latencySamples'] == ok,
            'sample-count', (report['latencySamples'], ok))
    require(report['statusCodes'] == statuses, 'status-count', report['statusCodes'])
    try:
        validate_sample_accounting(report)
    except (KeyError, ValueError) as exc:
        raise GoawayFailure('report-accounting', str(exc)) from exc
    require(report['protocol'] == 'HTTP/3' and report['threads'] == 1
            and report['connections'] == 1, 'client-configuration', report)
    counts = [len(p['requests']) for p in peers]
    require(counts == attempts, 'retry-count', (counts, attempts))
    for index, (peer, count) in enumerate(zip(peers, attempts)):
        require(peer['index'] == index and sorted(peer['requests']) == list(range(0, count * 4, 4)),
                'request-ids', peer['requests'])
        require(all(code in (0, 0x100) for code in peer['closed']),
                'connection-close', peer['closed'])
    first = peers[0]
    require(first.get('scheduled') is True, 'incomplete-schedule', first)
    boundaries = {
        'mixed': [16] * 4, 'decreasing': [24, 24, 16, 8, 8],
        'no-suffix': [parallel * 4] * 5, 'zero': [0],
        'ordinary': [], 'blocked-upload': [16],
        'fragmented': [16, 16, 8, 8], **{case: [] for case in fragments.INVALID},
    }
    require(first['goaways'] == boundaries[case]
            and all(not p['goaways'] for p in peers[1:]),
            'goaway-boundaries', [p['goaways'] for p in peers])
    names = {
        'mixed': ['mixed'] + [f'repeated-{i}' for i in range(3)],
        'decreasing': [f'boundary-{i}' for i in range(5)],
        'no-suffix': ['no-suffix'] + [f'repeated-{i}' for i in range(4)],
        'zero': [], 'ordinary': [], 'blocked-upload': ['blocked-upload'],
        **{case: [name for name, _ in fragments.chunks(case) if name != 'invalid-final']
           for case in fragments.CASES},
    }
    require([p['name'] for p in first['phases']] == names[case],
            'phase-sequence', first['phases'])
    for phase in first['phases']:
        sent, acked = phase['sent'], phase['acknowledged']
        packets = {p['pn'] for p in first['packets'] if p['phase'] == phase['name']}
        require(sent and len(sent) == len(set(sent)) and sent == acked
                and set(sent) <= packets, 'ack-barrier', phase)
    if names[case] and case not in fragments.INVALID:
        maximum = report['latencySeconds']['max']
        require(isinstance(maximum, (float, int)) and math.isfinite(maximum)
                and maximum >= .08, 'held-latency', maximum)
    if case == 'blocked-upload':
        rejected = {16, 20, 24, 28}
        resets = first['client_resets']
        require({r[0] for r in resets} == rejected,
                'upload-cancellation', resets)
        require(all(r[1:] == [0x10c, 128] for r in resets),
                'cancellation-fields', resets)
        require(first.get('cancelled_before_response') == sorted(rejected),
                'cancellation-order', first.get('cancelled_before_response'))
        require(not first['complete_uploads']
                and sorted(peers[1]['complete_uploads']) == [0, 4, 8, 12],
                'retry-body', [p['complete_uploads'] for p in peers])
    if case == 'mixed':
        packets = [p for p in first['packets'] if p['phase'] == 'mixed']
        require(any(
            {first['control_stream_id'], 0, 4, 16, 24} <= {
                f['stream_id'] for f in p['frames'] if f['frame_type'] == 'stream'}
            and {8, 20} <= {
                f['stream_id'] for f in p['frames'] if f['frame_type'] == 'reset_stream'}
            for p in packets), 'mixed-packet', packets)
    if case in fragments.CASES:
        fragments.validate(row, require)


def negative_controls(row):
    """Reject each corrupted copy for its exact semantic reason, after a pass.

    Run on fresh live evidence in CI as well as on the small replay fixture.
    A different exception (including a process/handshake failure) is a failure
    of the control itself, not evidence that the intended fault was detected.
    """
    validate_result(row)
    controls = []

    def check(name, code, mutate):
        changed = deepcopy(row)
        mutate(changed)
        try:
            validate_result(changed)
        except GoawayFailure as exc:
            require(exc.code == code, 'wrong-control-failure', (name, code, exc.code))
        else:
            raise GoawayFailure('undetected-control', name)
        controls.append(dict(name=name, rejected_by=code))

    check('absent samples', 'missing-samples', lambda r: r['report'].pop('latencySamples'))
    check('extra sample', 'sample-count', lambda r: r['report'].__setitem__(
        'latencySamples', r['report']['latencySamples'] + 1))
    if row['report']['latencySamples']:
        check('dropped sample', 'sample-count', lambda r: r['report'].__setitem__(
            'latencySamples', r['report']['latencySamples'] - 1))
    check('wrong budget', 'request-budget', lambda r: r['report']['requests'].__setitem__(
        'total', r['parallel'] + 1))
    check('extra attempt', 'retry-count', lambda r: r['peers'][-1]['requests'].append(
        len(r['peers'][-1]['requests']) * 4))
    if len(row['peers']) > 1:
        check('missing retry', 'retry-count', lambda r: r['peers'][-1]['requests'].pop())
    if row['case'] == 'zero':
        check('all-rejected reconnected', 'retry-count', lambda r: r['peers'].append(
            deepcopy(r['peers'][0])))
    if row['peers'][0]['phases']:
        check('missing ACK', 'ack-barrier', lambda r: r['peers'][0]['phases'][0].__setitem__(
            'acknowledged', []))
        if row['case'] not in fragments.INVALID:
            check('lost held latency', 'held-latency', lambda r: r['report']['latencySeconds'].__setitem__(
                'max', .001))
    if row['case'] == 'blocked-upload':
        check('missing cancellation', 'upload-cancellation',
              lambda r: r['peers'][0].__setitem__('client_resets', []))
        check('late cancellation', 'cancellation-order',
              lambda r: r['peers'][0].pop('cancelled_before_response'))
        check('incomplete retry body', 'retry-body',
              lambda r: r['peers'][1]['complete_uploads'].pop())
    if row['case'] == 'mixed':
        def split_resets(r):
            packets = r['peers'][0]['packets']
            resets = []
            for packet in packets:
                if packet['phase'] == 'mixed':
                    resets.extend(f for f in packet['frames'] if f['frame_type'] == 'reset_stream')
                    packet['frames'] = [f for f in packet['frames']
                                        if f['frame_type'] != 'reset_stream']
            packets.append(dict(phase='mixed', pn=max(p['pn'] for p in packets) + 1, frames=resets))
        check('mixed events split across packets', 'mixed-packet', split_resets)
    if row['case'] in fragments.CASES:
        check('wrong error count', 'request-budget', lambda r: r['report']['requests'].__setitem__(
            'errors', r['report']['requests']['errors'] + 1))
        check('wrong boundary', 'goaway-boundaries', lambda r: r['peers'][0]['goaways'].append(0))
        check('missing cleanup', 'cleanup', lambda r: r.pop('cleanup'))
        check('changed append bytes', 'control-bytes', lambda r: r['peers'][0]['control_writes'][0].__setitem__(
            'data', '00'))
        check('changed append offset', 'control-offset', lambda r: r['peers'][0]['control_writes'][0].__setitem__(
            'offset', 0))

        def first_frame(r):
            peer = r['peers'][0]
            write = peer['control_writes'][0]
            return next(f for p in peer['packets'] for f in p['frames']
                        if p['phase'] == write['phase'] and f['frame_type'] == 'stream'
                        and f['stream_id'] == peer['control_stream_id'])

        check('changed wire bytes', 'wire-bytes', lambda r: first_frame(r).__setitem__('data', '00'))
        check('changed wire offset', 'wire-coverage', lambda r: first_frame(r).__setitem__('offset', 0))
        check('missing authenticated ACKs', 'authenticated-ack', lambda r: r['peers'][0].__setitem__(
            'acks', []))

        def unrelated_acks(r):
            for ack in r['peers'][0]['acks']:
                ack['ranges'] = [[999999, 999999]]
        check('ACK ranges name unsent packets', 'authenticated-ack', unrelated_acks)

        def early_fragment(r):
            peer = r['peers'][0]
            packet = next(p for p in peer['packets'] if p['phase'] == peer['control_writes'][1]['phase'])
            packet['sequence'] = -2
        check('next fragment before ACK', 'fragment-order', early_fragment)
        if row['case'] in fragments.INVALID:
            check('timeout masquerading as parser failure', 'parser-error',
                  lambda r: r.__setitem__('stderr', '[lost] timed out\n'))
            def remove_invalid_response(r):
                for packet in r['peers'][0]['packets']:
                    if packet['phase'] == 'invalid-final':
                        packet['frames'] = [f for f in packet['frames']
                                            if not (f['frame_type'] == 'stream' and f['stream_id'] == 0)]
            check('invalid control without colocated response', 'invalid-mixed-packet', remove_invalid_response)
        else:
            def split_fragment_resets(r):
                peer = r['peers'][0]
                packets = peer['packets']
                resets = []
                for packet in packets:
                    if packet['phase'] == 'wide-id-tail':
                        resets.extend(f for f in packet['frames'] if f['frame_type'] == 'reset_stream')
                        packet['frames'] = [f for f in packet['frames'] if f['frame_type'] != 'reset_stream']
                packets.append(dict(phase='wide-id-tail', pn=max(p['pn'] for p in packets) + 1,
                                    sequence=max(p['sequence'] for p in packets) + 1000, frames=resets))
            check('final fragment separated from resets', 'fragment-mixed-packet', split_fragment_resets)
    return controls
