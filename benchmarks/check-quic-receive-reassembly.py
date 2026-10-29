#!/usr/bin/env python3
"""Exact encrypted STREAM reassembly checks, not a throughput benchmark.

Uses the public-API quic-timer-peer adapter and pinned aioquic TLS/AEAD. All
commands, encrypted packets, patterned bodies and schedule seeds are retained.
Scripted response traffic deliberately withholds client ACKs from the peer;
there are no timeout calls or wall-clock performance assertions.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import random

spec = importlib.util.spec_from_file_location(
    'timer_oracle', Path(__file__).with_name('check-quic-timer.py'))
timer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timer)

CASES = ('ordered', 'duplicates', 'reverse', 'overlap', 'bridge', 'random')
FIN_MODES = ('before-prefix', 'with-tail', 'after-prefix')
FAULTS = {'missing-prefix': 'incomplete body', 'missing-fin': 'missing FIN',
          'corrupt-body': 'wrong response bytes'}


class DeliveryError(AssertionError):
    """An application-visible byte, stream or completion mismatch."""


def require(condition, message):
    if not condition:
        raise DeliveryError(message)


class Delivery:
    def __init__(self, sid, expected):
        self.sid, self.expected = sid, expected
        self.data = bytearray()
        self.fins = 0

    def observe(self, events, *, blocked=False, fin_sent=False):
        for event in events:
            require(event.get('sid') == self.sid, 'unexpected response stream')
            kind = event['type']
            require(kind in ('data', 'fin'), 'unexpected response event')
            require(not blocked, 'response before missing prefix')
            require(not self.fins, 'response event after FIN')
            if kind == 'data':
                data = bytes.fromhex(event['data'])
                require(bool(data), 'empty data event')
                end = len(self.data) + len(data)
                require(end <= len(self.expected), 'extra response bytes')
                require(data == self.expected[len(self.data):end], 'wrong response bytes')
                self.data.extend(data)
            else:
                require(fin_sent, 'FIN before peer sent it')
                require(len(self.data) == len(self.expected), 'FIN before complete body')
                self.fins += 1

    def complete(self):
        require(bytes(self.data) == self.expected, 'incomplete body')
        require(self.fins == 1, 'missing FIN')


def schedule(case, seed, copies=512):
    """Offsets cover the suffix; its prefix remains absent until explicit release."""
    assert case in CASES and 1 <= copies <= 512
    size = 2048 if case == 'duplicates' else 1024
    body = bytes((i * 31 + i // 7) % 256 for i in range(size))
    prefix = 1024 if case == 'duplicates' else 32
    rng = random.Random(seed)
    if case == 'ordered':
        prefix = 0
        spans = [(i, min(i + 128, size)) for i in range(0, size, 128)]
    elif case == 'duplicates':
        spans = [(prefix, size)] * copies
    elif case == 'bridge':
        prefix = 1
        spans = [(i, i + 1) for i in range(1, size, 2)] + [(1, size)]
    elif case == 'overlap':
        spans = [(i, min(i + 128, size)) for i in range(prefix, size, 64)]
        rng.shuffle(spans)
    else:
        spans = [(i, min(i + 32, size)) for i in range(prefix, size, 32)]
        if case == 'reverse':
            spans.reverse()
        else:
            for _ in range(48):
                lo = rng.randrange(prefix, size)
                spans.append((lo, min(lo + rng.randrange(1, 256), size)))
            rng.shuffle(spans)
    return body, prefix, spans


class Run(timer.Run):
    def prepare(self):
        initial = self.command('poll', 0)
        wires = [bytes.fromhex(w) for w in initial['datagrams']]
        assert wires
        self.make_peer(wires[0])
        self.drain(wires, 0)
        assert self.client_connected and self.peer_connected, 'full TLS handshake required'
        at = max(self.now, self.last_peer_time) + 1000
        request = b'reassembly-request'
        sid, wires = self.request(at, request)
        # Deliver and independently verify the request without the timer
        # fixture's automatic receipt response. No private shb state is read.
        actual = timer.StreamBytes()
        for wire in wires:
            self.observe(wire, at, True)
            self.peer.receive_datagram(wire, timer.ADDRESS, now=at / 1e6)
        while (event := self.peer.next_event()) is not None:
            if isinstance(event, timer.StreamDataReceived):
                assert event.stream_id == sid, 'unexpected request stream'
                actual.add(dict(offset=len(actual.data), data=event.data.hex(),
                                fin=event.end_stream))
            else:
                assert isinstance(event, (timer.ConnectionIdIssued, timer.ConnectionIdRetired)), event
        timer.complete(actual, request, 'request')
        self.result.update(handshake_complete=True, request_complete=True, sid=sid)
        # Settle the request ACK before starting the controlled response.
        for wire, _ in self.peer.datagrams_to_send(at / 1e6):
            self.log(direction='peer-request-ack', wire=wire.hex())
            response = self.command('receive', at + 10, wire=wire.hex())
            assert not response['events'], 'unexpected automatic response'
        assert not self.responses
        return sid

    def packet(self, sid, offset, data, fin):
        q = self.peer
        builder = timer.QuicPacketBuilder(host_cid=q.host_cid, peer_cid=q._peer_cid.cid,
            version=q._version, is_client=False, max_datagram_size=1200,
            packet_number=q._packet_number)
        builder.start_packet(timer.QuicPacketType.ONE_RTT, q._cryptos[timer.tls.Epoch.ONE_RTT])
        frame = builder.start_frame(0x0e | int(fin), capacity=len(data) + 32)
        frame.push_uint_var(sid)
        frame.push_uint_var(offset)
        frame.push_uint_var(len(data))
        frame.push_bytes(data)
        wires, packets = builder.flush()
        assert len(wires) == len(packets) == 1
        pn = packets[0].packet_number
        q._packet_number = builder.packet_number
        self.log(direction='scripted-peer', pn=pn, sid=sid, offset=offset,
                 data=data.hex(), fin=fin, wire=wires[0].hex())
        return wires[0], pn

    def execute_reassembly(self, seed, copies, key_update, fin_mode):
        sid = self.prepare()
        body, prefix, spans = schedule(self.case, seed, copies)
        self.result.update(seed=seed, copies=copies, key_update=key_update,
                           fin_mode=fin_mode, expected_bytes=len(body))
        self.log(schedule=dict(case=self.case, seed=seed, spans=spans, prefix=prefix,
                               expected=body.hex(), fin_mode=fin_mode, key_update=key_update))
        delivery = Delivery(sid, body)
        fin_sent = False
        prefix_released = prefix == 0
        pns, replays = [], 0

        def deliver(wire):
            response = self.command('receive', self.now + 10, wire=wire.hex())
            delivery.observe(response['events'], blocked=not prefix_released, fin_sent=fin_sent)
            # Responses already retain every outbound ACK in the command log.
            # Do not feed them to aioquic's unscripted recovery machinery.
            return response

        def send(offset, data=b'', fin=False):
            nonlocal fin_sent
            wire, pn = self.packet(sid, offset, data, fin)
            assert not pns or pn > pns[-1], 'fresh packet numbers required'
            pns.append(pn)
            fin_sent |= fin
            deliver(wire)
            return wire

        if fin_mode == 'before-prefix' and self.fault != 'missing-fin':
            send(len(body), fin=True)
        tail_fin = False
        first_wire = None
        for i, (lo, hi) in enumerate(spans):
            if key_update and i == len(spans) // 2:
                self.peer._cryptos[timer.tls.Epoch.ONE_RTT].update_key()
                self.log(key_update=True, before_span=i)
            fin = fin_mode == 'with-tail' and hi == len(body) and not tail_fin
            fin &= self.fault != 'missing-fin'
            tail_fin |= fin
            wire = send(lo, body[lo:hi], fin)
            if first_wire is None:
                first_wire = wire
            if i % 11 == 0:
                self.log(replay=True, wire=wire.hex())
                require(not deliver(wire)['events'], 'packet replay produced events')
                replays += 1
        if prefix and self.fault != 'missing-prefix':
            prefix_released = True
            data = body[:prefix]
            if self.fault == 'corrupt-body':
                data = bytes([data[0] ^ 1]) + data[1:]
            send(0, data)
        if fin_mode == 'after-prefix' and self.fault != 'missing-fin':
            send(len(body), fin=True)
        self.result['schedule_complete'] = True
        delivery.complete()
        # Exact replays (including an old key phase) and a fresh duplicate FIN
        # after completion must not resurrect a stream or emit extra events.
        self.log(replay=True, after_completion=True, wire=first_wire.hex())
        require(not deliver(first_wire)['events'], 'late replay produced events')
        send(len(body), fin=True)
        require(not self.command('poll', self.now + 10)['events'], 'extra queued events')
        delivery.complete()
        require(set(self.responses) == {sid}, 'missing/extra response streams')
        timer.complete(self.responses[sid], body, 'response')
        require(self.finished == {sid}, 'missing/extra finished streams')
        self.result.update(passed=True, exact_bytes=len(delivery.data), fins=delivery.fins,
                           fresh_packet_numbers=pns, packet_replays=replays + 1)


def check(adapter, output, case, seed=17, copies=512, key_update=False,
          fin_mode='before-prefix', fault=None):
    run = Run(adapter, output, case, fault)
    try:
        run.execute_reassembly(seed, copies, key_update, fin_mode)
    except Exception as error:
        run.result.update(error=f'{type(error).__name__}: {error}',
                          error_type=type(error).__name__)
    finally:
        run.close()
    return run.result


def negative_detected(row, fault):
    # An adapter crash, handshake failure or unrelated assertion is never an
    # oracle success. Missing data/FIN must reach the completed input schedule.
    return (not row['passed'] and row['adapter_exit'] == 0
            and row.get('handshake_complete') and row.get('request_complete')
            and row.get('error_type') == 'DeliveryError'
            and FAULTS[fault] in row.get('error', '')
            and (fault == 'corrupt-body' or row.get('schedule_complete', False)))


def main(args):
    assert timer.aioquic.__version__ == '1.3.0', 'private peer APIs require pinned aioquic'
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for case in ([args.case] if args.case else CASES):
        for fin_mode in FIN_MODES:
            for update, seed in ((False, 17), (True, 91)):
                name = f'{case}-{fin_mode}-key{int(update)}-seed{seed}'
                rows.append(check(args.adapter.resolve(), args.output / name, case,
                                  seed=seed, key_update=update, fin_mode=fin_mode))
    if not args.case:
        for copies in (1, 8, 64):
            rows.append(check(args.adapter.resolve(), args.output / f'duplicates-{copies}',
                              'duplicates', copies=copies, key_update=copies > 1))
    negatives = []
    for fault in FAULTS:
        row = check(args.adapter.resolve(), args.output / fault, 'duplicates',
                    copies=8, key_update=True, fault=fault)
        row['detected'] = bool(negative_detected(row, fault))
        negatives.append(row)
    result = dict(aioquic=timer.aioquic.__version__,
                  adapter_sha256=hashlib.sha256(args.adapter.read_bytes()).hexdigest(),
                  rows=rows, negatives=negatives)
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=sum(r['passed'] for r in rows), cases=len(rows),
                         negatives_detected=sum(r['detected'] for r in negatives))))
    return 0 if all(r['passed'] for r in rows) and all(r['detected'] for r in negatives) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES)
    raise SystemExit(main(parser.parse_args()))
