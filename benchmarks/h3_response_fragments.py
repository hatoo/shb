"""Standard-library workload and replay checks for encrypted response fragments.

ACK records come from aioquic's authenticated packet_received events. Planned
writes are checked against emitted STREAM frames, including exact bytes and FIN.
This verifies receive boundaries and accounting, not throughput or body contents
exposed by the client (shb deliberately discards response bodies).
"""
from copy import deepcopy

from report_accounting import validate_sample_accounting

EARLY = bytes.fromhex('00003db8848d36a3820819')
TRAILER = bytes.fromhex('00002c42469b51820819')


def varint(value, width=None):
    width = width or next(w for w in (1, 2, 4, 8) if value < 1 << (8 * w - 2))
    assert width in (1, 2, 4, 8) and 0 <= value < 1 << (8 * width - 2)
    return (value | {1: 0, 2: 1 << 14, 4: 2 << 30, 8: 3 << 62}[width]).to_bytes(width, 'big')


def plan(workload):
    """Return named chunks; fragmented valid streams end with an empty FIN.

    Wide encodings are deliberately nonminimal. HEADERS are split inside the
    QPACK name/value; long opaque bodies are split into bounded chunks. Invalid
    sections reject only once complete, so their last bytes carry FIN directly.
    """
    section = bytes.fromhex(workload['section'])
    frames = []
    if workload['grease']:
        # Valid-looking HEADERS must never be interpreted inside ignored data.
        fake = b'\x01\x03\0\0\xd9'
        frames.append(('grease', 0x21, (fake + b'ignored') * 256))
    if workload['early_trailers']:
        frames.append(('early', 1, EARLY))
    frames.append(('final', 1, section))
    if workload['early_trailers']:
        frames += [('body', 0, b'body\x01\x03\0\0\xd9' if workload['grease'] else b'body'),
                   ('trailer', 1, TRAILER)]
    result = []
    for name, kind, payload in frames:
        kind = varint(kind, 4 if workload['wide'] else None)
        length = varint(len(payload), 8 if workload['wide'] else None)
        if not workload['fragmented']:
            result.append((name, kind + length + payload))
            continue
        for field, raw in [('type', kind), ('length', length)]:
            if len(raw) > 1:
                result.append((name + '-' + field + '-prefix', raw[:-1]))
            result.append((name + '-' + field + '-tail', raw[-1:]))
        # Three-byte cuts through the Huffman name and status, with the long
        # ignored field still present in each of the original four workloads.
        offset = 0
        while offset < len(payload):
            width = 3 if name != 'grease' and offset < 18 else 1024
            result.append((f'{name}-payload-{offset}', payload[offset:offset + width]))
            offset += width
    if not workload['fragmented']:
        return [('response', b''.join(data for _, data in result))]
    if workload['status'] is not None:
        result.append(('fin', b''))
    return result


class ResponseFailure(ValueError):
    def __init__(self, code, detail):
        self.code = code
        super().__init__(f'{code}: {detail}')


def require(condition, code, detail):
    if not condition:
        raise ResponseFailure(code, detail)


def delivery_proofs(peer):
    sent = {p['pn']: p['sequence'] for p in peer['packets']}
    proofs = {}
    for ack in peer['acks']:
        for lo, hi in ack['ranges']:
            require(0 <= lo <= hi and hi - lo < 65536, 'ack-range', (lo, hi))
            for pn in range(lo, hi + 1):
                if pn in sent and ack['sequence'] > sent[pn]:
                    proofs[pn] = min(proofs.get(pn, ack['sequence']), ack['sequence'])
    return proofs


def ack_proof(peer, sid, start, end, proofs=None):
    """Earliest authenticated proof for every byte; tolerate retransmissions.

    A retransmitted copy need not itself be acknowledged if an earlier copy
    already proves delivery. Packet-number spaces are filtered by the driver.
    """
    proofs = delivery_proofs(peer) if proofs is None else proofs
    covered = {}
    for packet in peer['packets']:
        sequence = proofs.get(packet['pn'])
        if sequence is None:
            continue
        for frame in packet['frames']:
            if frame['stream_id'] != sid:
                continue
            for offset in range(max(start, frame['offset']), min(end, frame['offset'] + frame['length'])):
                covered[offset] = min(covered.get(offset, sequence), sequence)
    if len(covered) != end - start:
        return None
    return max(covered.values(), default=0)


def validate_result(row):
    require(row['client_exit'] == 0, 'client-exit', row['client_exit'])
    require(not row['failures'] and 'execution_failure' not in row, 'peer-failure', row['failures'])
    require(row['cleanup'] == dict(client_reaped=True, tasks_joined=True, server_closed=True, connections_closed=True),
            'cleanup', row['cleanup'])
    workload, report, peer = row['workload'], row['report'], row['peer']
    require(peer['connections'] == 1 and peer['tls'], 'handshake', peer['connections'])
    count = workload['count']
    success = workload['status'] is not None and not (row['original'] and workload['broken_original'])
    expected = count if success else 0
    require(report['requests'] == dict(total=count, ok=expected, errors=count - expected, connectErrors=0),
            'request-budget', report['requests'])
    require(report.get('latencySamples') == expected and type(report.get('latencySamples')) is int,
            'sample-count', report.get('latencySamples'))
    require(report['statusCodes'] == ({str(workload['status']): count} if success else {}),
            'status-count', report['statusCodes'])
    try:
        validate_sample_accounting(report)
    except (KeyError, ValueError) as exc:
        raise ResponseFailure('report-accounting', str(exc)) from exc
    require(report['protocol'] == 'HTTP/3' and report['threads'] == report['connections'] == 1,
            'client-configuration', report)
    require(sorted(peer['requests']) == list(range(0, count * 4, 4)), 'request-ids', peer['requests'])
    require(not peer['premature_requests'], 'premature-completion', peer['premature_requests'])
    diagnostics = [s for s in row['stderr'].splitlines() if s.startswith(('[drive]', '[fail]', '[broken]', '[lost]'))]
    if success:
        expected_diagnostics = []
    elif workload['name'] in ('truncated-name', 'truncated-value', 'wide-truncated-name'):
        expected_diagnostics = ['[drive] truncated QPACK field section', '[broken] 1 requests in flight discarded']
    elif workload['name'] in ('bad-value-20', 'bad-value-2x0', 'bad-value-padding'):
        expected_diagnostics = ['[drive] malformed :status', '[broken] 1 requests in flight discarded']
    else:
        expected_diagnostics = [f'[fail] stream {sid} reset=None status=0' for sid in peer['requests']]
    require(sorted(diagnostics) == sorted(expected_diagnostics), 'parser-error', diagnostics)
    require(0 < report['bytesReceived'] <= sum(peer['server_datagram_bytes'])
            and report['bytesSent'] > 0, 'datagram-bytes', report)
    packets, acks, writes = peer['packets'], peer['acks'], peer['writes']
    require(len({p['pn'] for p in packets}) == len(packets), 'packet-number', packets)
    require(len({a['pn'] for a in acks}) == len(acks), 'ack-packet-number', acks)
    sequences = [e['sequence'] for e in packets + acks + writes]
    require(len(set(sequences)) == len(sequences), 'event-sequence', sequences)
    proofs = delivery_proofs(peer)
    chunks = plan(workload)
    wire = b''.join(data for _, data in chunks)
    require(peer['response_stream_bytes'] == len(wire) * count, 'response-bytes', peer['response_stream_bytes'])
    require(all(f['stream_id'] in peer['requests'] for p in packets for f in p['frames']),
            'response-stream', packets)
    for sid in peer['requests']:
        stream_writes = [w for w in writes if w['id'] == sid]
        require(len(stream_writes) == len(chunks), 'write-count', sid)
        start, previous_ack = 0, 0
        for index, (write, (name, data)) in enumerate(zip(stream_writes, chunks)):
            end, terminal = start + len(data), index == len(chunks) - 1
            require(write['phase'] == name and write['data'] == data.hex(), 'write-bytes', write)
            require(write['offset'] == start and write['fin'] == terminal, 'write-offset-fin', write)
            require(write['sequence'] > previous_ack, 'fragment-order', write)
            observed, fin = {}, False
            for packet in packets:
                for frame in packet['frames']:
                    if frame['stream_id'] != sid:
                        continue
                    raw = bytes.fromhex(frame['data'])
                    lo, hi = frame['offset'], frame['offset'] + len(raw)
                    belongs = (lo < end and hi > start) or (not data and lo == hi == start and frame['fin'])
                    if not belongs:
                        continue
                    require(start <= lo <= hi <= end, 'wire-offset', frame)
                    require(len(raw) == frame['length'] and wire[lo:hi] == raw, 'wire-bytes', frame)
                    require(packet['sequence'] > write['sequence'] > previous_ack, 'fragment-order', packet)
                    require(not frame['fin'] or (terminal and hi == len(wire)), 'wire-fin', frame)
                    fin |= frame['fin']
                    observed.update(enumerate(raw, lo))
            require(len(observed) == len(data) and bytes(observed[x] for x in range(start, end)) == data,
                    'wire-coverage', (sid, name))
            if terminal:
                require(fin, 'wire-fin', sid)
            else:
                proof = ack_proof(peer, sid, start, end, proofs)
                require(proof is not None, 'authenticated-ack', (sid, name))
                previous_ack = proof
            start = end
        stream_frames = [f for p in packets for f in p['frames'] if f['stream_id'] == sid]
        require(all(not f['fin'] or f['offset'] + f['length'] == len(wire) for f in stream_frames),
                'wire-fin', sid)
        require(all(0 <= f['offset'] <= f['offset'] + f['length'] <= len(wire)
                    and (f['length'] or f['fin']) for f in stream_frames), 'wire-offset', sid)


def negative_controls(row):
    """Every corrupted copy must fail for its own semantic reason."""
    validate_result(row)
    controls = []

    def check(name, code, mutate):
        bad = deepcopy(row)
        mutate(bad)
        try:
            validate_result(bad)
        except ResponseFailure as exc:
            require(exc.code == code, 'wrong-control-failure', (name, code, exc.code))
        else:
            raise ResponseFailure('undetected-control', name)
        controls.append(dict(name=name, rejected_by=code))

    check('wrong-status', 'status-count', lambda r: r['report'].__setitem__('statusCodes', {'599': 1}))
    check('lost-sample', 'sample-count', lambda r: r['report'].__setitem__('latencySamples', -1))
    check('lost-request', 'request-budget', lambda r: r['report']['requests'].__setitem__('total', 0))
    check('cleanup', 'cleanup', lambda r: r['cleanup'].__setitem__('tasks_joined', False))
    check('parser-error', 'parser-error', lambda r: r.__setitem__('stderr', '[drive] unrelated parser failure\n'))
    check('wrong-write', 'write-bytes', lambda r: r['peer']['writes'][0].__setitem__('data', 'ff'))
    check('wrong-offset', 'write-offset-fin', lambda r: r['peer']['writes'][0].__setitem__('offset', 1))

    def frame(r):
        return next(f for p in r['peer']['packets'] for f in p['frames'] if f['length'])

    check('wire-corruption', 'wire-bytes', lambda r: frame(r).__setitem__('data', 'ff' * frame(r)['length']))
    # Shifting a one-byte first phase removes its entire coverage; a longer
    # frame still overlaps that phase but crosses its end boundary.
    offset_code = 'wire-coverage' if len(plan(row['workload'])[0][1]) == 1 else 'wire-offset'
    check('wire-offset', offset_code, lambda r: frame(r).__setitem__('offset', frame(r)['offset'] + 1))

    def remove_fin(r):
        for p in r['peer']['packets']:
            for f in p['frames']:
                f['fin'] = False
    check('missing-fin', 'wire-fin', remove_fin)
    if row['workload']['fragmented']:
        check('unacknowledged', 'authenticated-ack', lambda r: r['peer'].__setitem__('acks', []))

        def wrong_ack(r):
            for ack in r['peer']['acks']:
                ack['ranges'] = [[999999, 999999]]
        check('unrelated-ack', 'authenticated-ack', wrong_ack)

        def ack_before_packet(r):
            for ack in r['peer']['acks']:
                ack['sequence'] = -ack['sequence']
        check('unauthenticated-order', 'authenticated-ack', ack_before_packet)
        check('coalesced-writes', 'fragment-order', lambda r: r['peer']['writes'][1].__setitem__('sequence', -1))
    return controls
