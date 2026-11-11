"""Wire workload and replay checks for fragmented peer control streams.

The workload uses nonminimal QUIC varints intentionally. It is independent of
the Rust parser; recorded STREAM bytes and authenticated ACKs must prove every
specified boundary before client reports can count as correctness evidence.
"""

INVALID = {
    'malformed-goaway': 'GOAWAY without a stream id',
    'oversized-goaway': 'GOAWAY longer than a stream id',
    'trailing-goaway': 'GOAWAY with trailing bytes',
}
CASES = ('fragmented', *INVALID)


def wide(value, width):
    assert width in (1, 2, 4, 8) and 0 <= value < 1 << (width * 8 - 2)
    return (value | {1: 0, 2: 1 << 14, 4: 2 << 30, 8: 3 << 62}[width]).to_bytes(width, 'big')


def chunks(case):
    """Each entry is one receive phase, separated by an authenticated ACK.

    Only the terminal malformed phase omits the barrier: rejection may close
    the socket before its ACK. Its exact parser error is required instead.
    """
    if case in INVALID:
        length, payload = {
            'malformed-goaway': (1, b'\x40'),
            'oversized-goaway': (9, b''),
            'trailing-goaway': (2, b'\0\0'),
        }[case]
        kind, size = wide(7, 4), wide(length, 4)
        return [('type-prefix', kind[:1]), ('type-tail', kind[1:]),
                ('length-prefix', size[:3]), ('invalid-final', size[3:] + payload)]
    assert case == 'fragmented'
    # A 4 KiB GREASE payload spans packets and contains false GOAWAY(0)s.
    # Interpreting any of these as control would reject the entire cohort.
    body = (b'\x07\x01\x00ignored' * 410)[:4096]
    kind, size = wide(0x21, 4), wide(len(body), 8)
    result = [('grease-type-prefix', kind[:1]), ('grease-type-tail', kind[1:]),
              ('grease-length-prefix', size[:3]), ('grease-length-tail', size[3:])]
    result += [(f'grease-body-{i}', body[start:start + 1024])
               for i, start in enumerate(range(0, len(body), 1024))]
    kind, size, boundary = wide(7, 8), wide(8, 4), wide(16, 8)
    result += [('wide-type-prefix', kind[:7]), ('wide-type-tail', kind[7:]),
               ('wide-length-prefix', size[:1]), ('wide-length-tail', size[1:]),
               ('wide-id-prefix', boundary[:7]), ('wide-id-tail', boundary[7:])]
    # Equal/decreasing boundaries arrive together, using every ID width.
    result.append(('adjacent', b''.join(wide(7, 2) + wide(width, 1) + wide(value, width)
                                       for value, width in [(16, 2), (8, 4), (8, 1)])))
    return result


def validate(row, require):
    peer = row['peers'][0]
    plan = chunks(row['case'])
    require(row.get('cleanup') == dict(client_reaped=True, tasks_joined=True, server_closed=True),
            'cleanup', row.get('cleanup'))
    # Exact bytes are from aioquic's emitted STREAM frames, including retries;
    # the append ledger alone cannot prove that they reached the wire.
    writes = peer['control_writes']
    require(len(writes) == len(plan), 'control-writes', writes)
    offset = peer['control_start']
    require(type(offset) is int and offset > 0, 'control-offset', offset)
    for write, (name, data) in zip(writes, plan):
        require(write['phase'] == name and write['data'] == data.hex(),
                'control-bytes', write)
        require(write['offset'] == offset, 'control-offset', write)
        offset += len(data)

    packets, acks = peer['packets'], peer['acks']
    require(len({p['pn'] for p in packets}) == len(packets), 'packet-number', packets)
    require(len({a['pn'] for a in acks}) == len(acks), 'ack-packet-number', acks)
    sequences = [p['sequence'] for p in packets] + [a['sequence'] for a in acks]
    require(len(set(sequences)) == len(sequences), 'event-sequence', sequences)
    previous_ack = -1
    for index, write in enumerate(writes):
        name, data = plan[index]
        start, end = write['offset'], write['offset'] + len(data)
        observed, carriers = {}, []
        for packet in packets:
            frames = [f for f in packet['frames'] if f['frame_type'] == 'stream'
                      and f['stream_id'] == peer['control_stream_id']
                      and f['offset'] < end and f['offset'] + f['length'] > start]
            if not frames:
                continue
            carriers.append(packet)
            require(packet['sequence'] > previous_ack,
                    'fragment-order', (name, packet, previous_ack))
            for frame in frames:
                raw = bytes.fromhex(frame['data'])
                require(len(raw) == frame['length'] and not frame['fin'],
                        'wire-bytes', frame)
                require(start <= frame['offset'] < frame['offset'] + len(raw) <= end,
                        'wire-offset', (write, frame))
                for at, byte in enumerate(raw, frame['offset']):
                    require(at not in observed or observed[at] == byte, 'wire-bytes', frame)
                    observed[at] = byte
        require(sorted(observed) == list(range(start, end)), 'wire-coverage', name)
        require(bytes(observed[at] for at in range(start, end)) == data, 'wire-bytes', name)
        if name == 'invalid-final':
            continue
        phase = next(p for p in peer['phases'] if p['name'] == name)
        require({p['pn'] for p in carriers} <= set(phase['sent']), 'phase-carriers', name)
        proofs = []
        for packet in carriers:
            confirming = [a['sequence'] for a in acks if a['sequence'] > packet['sequence']
                          and any(lo <= packet['pn'] <= hi for lo, hi in a['ranges'])]
            require(confirming, 'authenticated-ack', (name, packet['pn']))
            proofs.append(min(confirming))
        previous_ack = max(proofs)
    if row['case'] in INVALID:
        # A timeout can also produce all-error accounting. Require the intended
        # parser diagnostic, a clean process exit, and no reconnect attempts.
        errors = [line for line in row['stderr'].splitlines() if line.startswith('[drive] ')]
        require(errors == ['[drive] ' + INVALID[row['case']]], 'parser-error', errors)
        final = writes[-1]
        require(any(
            any(f['frame_type'] == 'stream' and f['stream_id'] == peer['control_stream_id']
                and f['offset'] == final['offset'] and f['data'] == final['data']
                for f in p['frames'])
            and any(f['frame_type'] == 'stream' and f['stream_id'] == 0 and f['fin']
                    for f in p['frames'])
            and (row['parallel'] == 1 or any(f['frame_type'] == 'reset_stream' and f['stream_id'] == 4
                                           for f in p['frames']))
            for p in packets), 'invalid-mixed-packet', packets)
    else:
        require(peer['closed'], 'connection-close', peer['closed'])
        final = next(w for w in writes if w['phase'] == 'wide-id-tail')
        require(any(
            any(f['frame_type'] == 'stream' and f['stream_id'] == peer['control_stream_id']
                and f['offset'] == final['offset'] and f['data'] == final['data']
                for f in p['frames'])
            and {0, 4, 16, 24} <= {f['stream_id'] for f in p['frames']
                                  if f['frame_type'] == 'stream'}
            and {8, 20} <= {f['stream_id'] for f in p['frames']
                           if f['frame_type'] == 'reset_stream'}
            for p in packets), 'fragment-mixed-packet', packets)
