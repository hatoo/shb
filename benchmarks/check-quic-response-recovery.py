#!/usr/bin/env python3
"""Independent aioquic wire oracle for recovery after an ACK-only flight.

Correctness only. Authenticate each short packet before choosing whether to
deliver it. Drop two requests, then require their exact STREAM bytes and FIN in
new packet numbers, including after late, sparse and duplicate ACKs.
"""
import argparse
import asyncio
import datetime
import hashlib
import json
from pathlib import Path
import tempfile

import aioquic
from aioquic import tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicPacketType, pull_ack_frame, pull_quic_header, push_ack_frame
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.rangeset import RangeSet
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from report_accounting import validate_sample_accounting

CASES = ('ordinary', 'sparse', 'key-update')
BODY = bytes(range(256)) * 4096
UPLOAD = b'recovery-ownership-' * 16
REQUESTS = 4
TARGETS = (4, 8)
FLIGHT = 32


def contains(ranges, pn):
    return any(lo <= pn <= hi for lo, hi in ranges)


def decode_frames(payload):
    """Keep exact STREAM data, unlike qlog's length-only stream records.

    The parser is independent of shb; unsupported frames fail closed. ACK
    decoding and varints use the pinned peer's implementation.
    """
    buf, frames = Buffer(data=payload), []
    while not buf.eof():
        kind = buf.pull_uint_var()
        frame = dict(type=kind)
        if kind in (0, 1, 0x1e):
            if kind == 0 and frames and frames[-1]['type'] == 0:
                continue
        elif kind in (2, 3):
            ranges, delay = pull_ack_frame(buf)
            frame.update(ranges=[[r.start, r.stop - 1] for r in ranges], delay=delay)
            if kind == 3:
                frame['ecn'] = [buf.pull_uint_var() for _ in range(3)]
        elif 8 <= kind <= 15:
            sid = buf.pull_uint_var()
            offset = buf.pull_uint_var() if kind & 4 else 0
            length = buf.pull_uint_var() if kind & 2 else buf.capacity - buf.tell()
            frame.update(sid=sid, offset=offset, fin=bool(kind & 1),
                         data=buf.pull_bytes(length).hex())
        elif kind == 6:
            frame.update(offset=buf.pull_uint_var(),
                         data=buf.pull_bytes(buf.pull_uint_var()).hex())
        elif kind in (4, 5, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19):
            count = 3 if kind == 4 else 2 if kind in (5, 0x11, 0x15) else 1
            frame['values'] = [buf.pull_uint_var() for _ in range(count)]
        elif kind == 7:
            frame['token'] = buf.pull_bytes(buf.pull_uint_var()).hex()
        elif kind == 0x18:
            frame.update(sequence=buf.pull_uint_var(), retire=buf.pull_uint_var(),
                         cid=buf.pull_bytes(buf.pull_uint8()).hex(),
                         token=buf.pull_bytes(16).hex())
        elif kind in (0x1a, 0x1b):
            frame['token'] = buf.pull_bytes(8).hex()
        elif kind in (0x1c, 0x1d):
            frame['code'] = buf.pull_uint_var()
            if kind == 0x1c:
                frame['frame'] = buf.pull_uint_var()
            frame['reason'] = buf.pull_bytes(buf.pull_uint_var()).hex()
        else:
            raise AssertionError(f'unsupported client frame {kind:#x}')
        frames.append(frame)
    assert frames, 'empty protected payload'
    return frames


class StreamBytes:
    """An offset/byte/FIN reference model, allowing identical retransmissions."""

    def __init__(self):
        self.data = {}
        self.end = None

    def add(self, frame):
        offset, data = frame['offset'], bytes.fromhex(frame['data'])
        end = offset + len(data)
        assert 0 <= offset <= end <= 65536, 'unbounded request stream'
        if frame['fin']:
            assert self.end in (None, end), 'changed FIN offset'
            assert not self.data or max(self.data) < end, 'FIN before buffered bytes'
            self.end = end
        assert self.end is None or end <= self.end, 'data beyond FIN'
        for at, byte in enumerate(data, offset):
            assert at not in self.data or self.data[at] == byte, 'changed STREAM byte'
            self.data[at] = byte

    def complete(self):
        return self.end is not None and len(self.data) == self.end

    def report(self):
        return dict(end=self.end, offsets=sorted(self.data),
                    data=bytes(self.data[i] for i in sorted(self.data)).hex())


class Oracle:
    def __init__(self):
        self.packets = {}
        self.dropped = {}
        self.received = {}
        self.ack_only = []
        self.acks_sent = []
        self.actions = []

    def observe(self, pn, wire, phase, frames):
        digest = hashlib.sha256(wire).hexdigest()
        if pn in self.packets:
            row = self.packets[pn]
            assert (row['sha256'], row['phase'], row['frames']) == (digest, phase, frames), 'changed client packet'
            self.actions.append(dict(action='duplicate-client', pn=pn))
            return row['delivered']
        assert len(self.packets) < 20000, 'unbounded client packet ledger'
        row = dict(pn=pn, sha256=digest, phase=phase, frames=frames, delivered=True)
        streams = [f for f in frames if 'sid' in f]
        new = [f for f in streams if f['sid'] in TARGETS and f['sid'] not in self.dropped]
        if new:
            sid = new[0]['sid']
            assert all(f['sid'] == sid for f in streams), 'mixed target request packet'
            expected = StreamBytes()
            for frame in streams:
                expected.add(frame)
            # This deliberately small upload must be wholly in the selected
            # packet; otherwise this is not the intended recovery experiment.
            assert expected.complete(), 'target packet must contain whole request and FIN'
            flight = [n for n in self.ack_only if not any(
                contains(a['ranges'], n) for a in self.acks_sent)]
            if sid == TARGETS[0]:
                assert len(flight) >= FLIGHT, ('missing unacknowledged ACK-only flight', len(flight))
                assert len(self.acks_sent) == 1, 'ACK-only flight retired before target drop'
            self.dropped[sid] = dict(pn=pn, expected=expected.report(), flight=flight)
            row['delivered'] = False
            self.actions.append(dict(action='drop', sid=sid, pn=pn))
        if row['delivered']:
            for frame in streams:
                self.received.setdefault(frame['sid'], StreamBytes()).add(frame)
        if any(f['type'] in (2, 3) for f in frames) and all(f['type'] in (0, 2, 3) for f in frames):
            self.ack_only.append(pn)
        self.packets[pn] = row
        return row['delivered']

    def recovered(self, sid):
        return sid in self.received and self.received[sid].complete()

    def verify_recovery(self, sid):
        drop = self.dropped[sid]
        assert not self.packets[drop['pn']]['delivered'], 'target was delivered'
        assert self.recovered(sid), 'missing retransmitted STREAM bytes or FIN'
        assert self.received[sid].report() == drop['expected'], 'retransmission differs from dropped request'
        packets = [p for p in self.packets.values() if p['delivered']
                   and any(f.get('sid') == sid for f in p['frames'])]
        assert packets and all(p['pn'] > drop['pn'] for p in packets), 'recovery needs fresh packet numbers'
        return [p['pn'] for p in packets]

    def ack_for(self, pn):
        return next((p['pn'] for p in reversed(self.packets.values()) if p['delivered']
                     and any(f['type'] in (2, 3) and contains(f['ranges'], pn)
                             for f in p['frames'])), None)

    def response_for(self, token):
        return next((p['pn'] for p in reversed(self.packets.values()) if p['delivered']
                     and any(f['type'] == 0x1b and f['token'] == token.hex()
                             for f in p['frames'])), None)

    def authorize_ack(self, ranges):
        assert ranges and all(0 <= lo <= hi for lo, hi in ranges), 'invalid ACK ranges'
        for lo, hi in ranges:
            assert hi - lo < 20000, 'unbounded ACK range'
            for pn in range(lo, hi + 1):
                assert pn in self.packets and self.packets[pn]['delivered'], ('ACK of undelivered packet', pn)

    def report(self):
        return dict(packets=list(self.packets.values()), dropped=self.dropped,
                    received={sid:stream.report() for sid, stream in self.received.items()},
                    ack_only=self.ack_only, acks_sent=self.acks_sent, actions=self.actions)


class Failures:
    def __init__(self):
        self.errors = []

    def record(self, error):
        self.errors.append(repr(error))

    def check(self):
        assert not self.errors, ('peer callback failure', self.errors)


async def until(predicate, failures, label, timeout=5):
    try:
        async with asyncio.timeout(timeout):
            while True:
                failures.check()
                if predicate():
                    return
                await asyncio.sleep(.001)
    except TimeoutError as error:
        raise AssertionError(f'timed out waiting for {label}') from error


def cancel_callbacks(peer):
    for attr in ('_timer', '_transmit_task'):
        handle = getattr(peer, attr)
        if handle is not None:
            handle.cancel()
            setattr(peer, attr, None)


async def check(binary, config, case):
    oracle, failures = Oracle(), Failures()
    ledger = dict(case=case, requests=[], headers={}, responses=[], updates=[],
                  controls=[], recoveries=[], closes=[], server_stream_packets=[])
    peers, jobs = [], []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: failures.record(
        context.get('exception', context['message'])))

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.h3 = H3Connection(self._quic)
            self.scripted = False
            self.generation = 0
            self.cursor = 0
            self.uploads = {}
            write_ack = self._quic._write_ack_frame

            def ack(builder, space, now):
                if self.scripted and space is self._quic._spaces[tls.Epoch.ONE_RTT]:
                    space.ack_at = None
                else:
                    write_ack(builder, space, now)
            self._quic._write_ack_frame = ack
            datagrams = self._quic.datagrams_to_send

            def send(now):
                result = datagrams(now)
                events = list(self._quic._quic_logger._events)
                for event in events[self.cursor:]:
                    if event['name'] != 'transport:packet_sent':
                        continue
                    packet = event['data']
                    if packet['header']['packet_type'] != '1RTT':
                        continue
                    for frame in packet['frames']:
                        if self.scripted:
                            assert frame['frame_type'] != 'ack', 'unscripted application ACK'
                        if frame['frame_type'] == 'stream' and frame['stream_id'] == 0:
                            ledger['server_stream_packets'].append(dict(
                                pn=packet['header']['packet_number'], **frame))
                self.cursor = len(events)
                return result
            self._quic.datagrams_to_send = send
            peers.append(self)
            if len(peers) != 1:
                failures.record('unexpected second connection')

        def datagram_received(self, data, addr):
            try:
                if not data[0] & 0x80:
                    q = self._quic
                    buf = Buffer(data=data)
                    pull_quic_header(buf, host_cid_length=len(q.host_cid))
                    # CryptoContext.decrypt_packet is a nonmutating peek: it
                    # authenticates next-phase keys without installing them.
                    # Only super().datagram_received may accept a packet or
                    # advance the peer's crypto, ACK and stream state.
                    head, payload, pn, _update = q._cryptos[tls.Epoch.ONE_RTT].recv.decrypt_packet(
                        data, buf.tell(), q._spaces[tls.Epoch.ONE_RTT].expected_packet_number)
                    if not oracle.observe(pn, data, (head[0] >> 2) & 1, decode_frames(payload)):
                        return
                super().datagram_received(data, addr)
            except Exception as error:
                failures.record(error)

        def send_wire(self, wire):
            self._transport.sendto(wire, self._quic._network_paths[0].addr)

        def packet(self, label, ranges=None, token=None):
            q = self._quic
            builder = QuicPacketBuilder(host_cid=q.host_cid, peer_cid=q._peer_cid.cid,
                version=q._version, is_client=False, max_datagram_size=1200,
                packet_number=q._packet_number, quic_logger=q._quic_logger)
            builder.start_packet(QuicPacketType.ONE_RTT, q._cryptos[tls.Epoch.ONE_RTT])
            if ranges:
                oracle.authorize_ack(ranges)
                ack_ranges = RangeSet()
                for lo, hi in ranges:
                    ack_ranges.add(lo, hi + 1)
                push_ack_frame(builder.start_frame(2, capacity=128), ack_ranges, 0)
            if token is None:
                builder.start_frame(1, capacity=1)
            else:
                assert len(token) == 8
                q._local_challenges[token] = q._network_paths[0]
                builder.start_frame(0x1a, capacity=9).push_bytes(token)
            wires, packets = builder.flush()
            assert len(wires) == len(packets) == 1
            q._packet_number = builder.packet_number
            sent = packets[0]
            sent.sent_time = loop.time()
            q._loss.on_packet_sent(packet=sent, space=q._spaces[sent.epoch])
            q._network_paths[0].bytes_sent += len(wires[0])
            row = dict(pn=sent.packet_number, label=label, ranges=ranges or [],
                       generation=self.generation, wire=wires[0].hex())
            ledger['controls'].append(row)
            if ranges:
                oracle.acks_sent.append(row)
            self.send_wire(wires[0])
            self.transmit()
            return row

        async def barrier(self, label, ranges=None, token=None):
            row = self.packet(label, ranges, token)
            await until(lambda: oracle.ack_for(row['pn']) is not None and (
                token is None or oracle.response_for(token) is not None), failures, label)
            row['client_ack_pn'] = oracle.ack_for(row['pn'])
            return row

        def observe_crypto(self):
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            update = crypto._update_key

            def updated(trigger):
                old = crypto.send.key_phase
                update(trigger)
                assert crypto.send.key_phase != old
                self.generation += 1
                ledger['updates'].append(dict(trigger=trigger, old=old,
                    new=crypto.send.key_phase, generation=self.generation))
            crypto._update_key = updated

        def response(self, sid, body, end=True):
            self.h3.send_headers(sid, [(b':status', b'200'),
                                      (b'content-length', str(len(body)).encode())])
            self.h3.send_data(sid, body, end_stream=end)
            ledger['responses'].append(dict(sid=sid, bytes=len(body),
                                            sha256=hashlib.sha256(body).hexdigest()))
            self.transmit()

        async def recovery(self, sid):
            await until(lambda: sid in oracle.dropped, failures, f'drop stream {sid}')
            drop = oracle.dropped[sid]
            # A late ACK for an actually received old ACK-only packet must
            # never acknowledge the outstanding request's STREAM record.
            old = oracle.dropped[TARGETS[0]]['flight'][0]
            late = await self.barrier(f'late-ack-{sid}', [[old, old]])
            self.send_wire(bytes.fromhex(late['wire']))
            oracle.actions.append(dict(action='replay-server-ack', pn=late['pn']))
            probes = []
            for i in range(3):
                token = f'{sid:04d}-{i:03d}'.encode()
                await self.barrier(f'loss-probe-{sid}-{i}', token=token)
                probes.append(oracle.response_for(token))
            assert probes[-1] >= drop['pn'] + 3, 'packet loss threshold not crossed'
            ranges = [[probes[-1], probes[-1]]]
            if case != 'ordinary':
                assert probes[-1] - probes[0] > 1
                ranges.insert(0, [probes[0], probes[0]])
            trigger = await self.barrier(f'sparse-loss-ack-{sid}', ranges)
            await until(lambda: oracle.recovered(sid) and sid in ledger['requests'],
                        failures, f'exact STREAM/FIN recovery for {sid}')
            recovered = oracle.verify_recovery(sid)
            self.send_wire(bytes.fromhex(trigger['wire']))
            oracle.actions.append(dict(action='replay-server-ack', pn=trigger['pn']))
            await self.barrier(f'fresh-duplicate-ack-{sid}', ranges)
            await self.barrier(f'retire-retransmission-{sid}', [[n, n] for n in recovered])
            ledger['recoveries'].append(dict(sid=sid, dropped=drop['pn'],
                recovered=recovered, loss_ack=trigger['pn'], probe_pns=probes))

        async def drive(self):
            self.observe_crypto()
            initial = sorted(pn for pn, p in oracle.packets.items() if p['delivered'])
            assert initial, 'missing authenticated initial request'
            await self.barrier('initial-request-ack', [[n, n] for n in initial])
            if case == 'key-update':
                self._quic.request_key_update()
            self.response(0, BODY, end=False)
            response_end = self._quic._streams[0].sender._buffer_stop
            # Each PING has its own authenticated ACK barrier, so the test
            # cannot pass merely because a large response happened to batch.
            for i in range(FLIGHT):
                await self.barrier(f'ack-only-flight-{i}')
            await until(lambda: self._quic._streams[0].sender._buffer_start >= response_end,
                        failures, 'acknowledgement of the complete 1 MiB body')
            covered = set()
            for frame in ledger['server_stream_packets']:
                if oracle.ack_for(frame['pn']) is not None:
                    covered.update(range(frame['offset'], frame['offset'] + frame['length']))
            assert len(covered) == response_end and min(covered) == 0, 'large response ACK coverage incomplete'
            ledger['large_response'] = dict(body_bytes=len(BODY), stream_bytes=response_end,
                acknowledged_stream_bytes=len(covered), ack_only_packets=len(oracle.ack_only))
            self.h3.send_data(0, b'', end_stream=True)
            self.transmit()
            await self.recovery(4)
            if case == 'key-update':
                self._quic.request_key_update()
            self.response(4, BODY[:8192])
            await self.recovery(8)
            self.response(8, BODY[:8192])
            await until(lambda: 12 in ledger['requests'], failures, 'following request')
            self.response(12, BODY[:8192])

        def quic_event_received(self, event):
            try:
                if isinstance(event, ConnectionTerminated):
                    ledger['closes'].append(dict(code=event.error_code, frame=event.frame_type,
                                                 reason=event.reason_phrase))
                    assert event.error_code in (0, 0x100) and event.frame_type is None, 'unexpected QUIC close'
                for e in self.h3.handle_event(event):
                    if isinstance(e, HeadersReceived):
                        assert e.stream_id not in ledger['headers'], 'duplicate HTTP request headers'
                        headers = dict(e.headers)
                        assert headers[b':method'] == b'POST' and headers[b':path'] == b'/recovery'
                        assert headers[b'content-length'] == str(len(UPLOAD)).encode()
                        ledger['headers'][e.stream_id] = [(k.decode(), v.decode()) for k, v in e.headers]
                        self.uploads[e.stream_id] = bytearray()
                    if isinstance(e, DataReceived):
                        self.uploads[e.stream_id].extend(e.data)
                        assert len(self.uploads[e.stream_id]) <= len(UPLOAD), 'excess request body'
                    if isinstance(e, (HeadersReceived, DataReceived)) and e.stream_ended:
                        assert bytes(self.uploads[e.stream_id]) == UPLOAD, 'wrong request body'
                        assert e.stream_id not in ledger['requests'], 'duplicate HTTP completion'
                        ledger['requests'].append(e.stream_id)
                        if e.stream_id == 0:
                            self.scripted = True
                            jobs.append(asyncio.create_task(self.drive()))
            except Exception as error:
                failures.record(error)

    server, proc, communicate = None, None, None
    result = dict(case=case, ledger=ledger)
    try:
        server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
        port = server._transport.get_extra_info('sockname')[1]
        command = [str(binary), '--http3', '-j', '-t', '1', '-c', '1', '-p', '1',
            '-n', str(REQUESTS), '-d', UPLOAD.decode(), '--timeout', '15s',
            f'https://127.0.0.1:{port}/recovery']
        result['command'] = command
        proc = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        communicate = asyncio.create_task(proc.communicate())
        async with asyncio.timeout(30):
            while not communicate.done():
                failures.check()
                for job in jobs:
                    if job.done():
                        job.result()
                await asyncio.sleep(.005)
            stdout, stderr = await communicate
            result.update(stdout=stdout.decode(), stderr=stderr.decode())
            assert proc.returncode == 0, ('client failed', proc.returncode, result['stderr'])
            assert len(jobs) == 1, 'missing recovery schedule'
            await jobs[0]
            await asyncio.sleep(.02)
            failures.check()
            for sid in TARGETS:
                oracle.verify_recovery(sid)
            assert ledger['requests'] == [0, 4, 8, 12], 'missing or extra HTTP requests'
            assert [r['sid'] for r in ledger['responses']] == [0, 4, 8, 12]
            if case == 'key-update':
                assert [u['trigger'] for u in ledger['updates']] == ['local_update'] * 2
                assert [u['new'] for u in ledger['updates']] == [1, 0]
                for sid, phase in ((4, 1), (8, 0)):
                    assert oracle.packets[oracle.dropped[sid]['pn']]['phase'] == phase
                    assert all(oracle.packets[n]['phase'] == phase for n in oracle.verify_recovery(sid))
            else:
                assert not ledger['updates']
            report = json.loads(stdout)
            validate_sample_accounting(report)
            assert report['requests'] == dict(total=REQUESTS, ok=REQUESTS, errors=0, connectErrors=0)
            assert report['statusCodes'] == {'200': REQUESTS}
            assert report['bytesReceived'] >= sum(r['bytes'] for r in ledger['responses'])
            result.update(passed=True, report=report)
    except Exception as error:
        result.update(passed=False, error=repr(error))
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        if communicate is not None:
            stdout, stderr = await communicate
            result.update(stdout=stdout.decode(), stderr=stderr.decode())
        for job in jobs:
            if not job.done():
                job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
        if server is not None:
            server.close()
        for peer in peers:
            cancel_callbacks(peer)
        await asyncio.sleep(0)
        loop.set_exception_handler(previous_handler)
        result['failures'] = failures.errors
        if failures.errors:
            result['passed'] = False
            result.setdefault('error', 'peer callback failure during cleanup')
        result['oracle'] = oracle.report()
    return result


async def main(args):
    assert aioquic.__version__ == '1.3.0', 'fixture uses pinned aioquic private APIs'
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now-datetime.timedelta(days=1))
                .not_valid_after(now+datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        path = Path(directory)
        (path/'cert').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (path/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        for case in ([args.case] if args.case else CASES):
            config = QuicConfiguration(is_client=False, alpn_protocols=['h3'], quic_logger=QuicLogger())
            config.load_cert_chain(path/'cert', path/'key')
            rows.append(await check(args.shb.resolve(), config, case))
    print(json.dumps(dict(aioquic=aioquic.__version__, rows=rows), indent=2))
    return 0 if all(row['passed'] for row in rows) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--case', choices=CASES)
    raise SystemExit(asyncio.run(main(parser.parse_args())))
