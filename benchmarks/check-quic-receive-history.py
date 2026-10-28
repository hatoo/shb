#!/usr/bin/env python3
"""Independent aioquic 1.3.0 receive-history oracle; correctness, not throughput.

Keep one real H3 request open while sending protected PATH_CHALLENGE packets.
Observe authenticated responses and ACKs, including proof of ACK-of-ACK pruning.
The bounded wire schedule controls loss, late delivery and byte-for-byte replay.
"""
import argparse
import asyncio
from collections import Counter
from dataclasses import dataclass
import datetime
import hashlib
import json
from pathlib import Path
import tempfile

import aioquic
from aioquic import tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicPacketType
from aioquic.quic.packet_builder import QuicPacketBuilder
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from report_accounting import validate_sample_accounting

CASES = ('ordinary', 'sparse', 'key-update')
BODY = bytes(range(256)) * 32
REQUESTS = 4


def contains(ranges, pn):
    return any(lo <= pn <= hi for lo, hi in ranges)


class Oracle:
    """Count frame dispatch, independently of aggregate successful requests."""

    def __init__(self):
        self.expected = Counter()
        self.responses = Counter()
        self.packets = {}
        self.acks = []
        self.response_packets = []

    def expect(self, token):
        self.expected[token.hex()] += 1

    def observe(self, pn, frames):
        # A duplicated *client* datagram is not another frame dispatch by shb.
        # Require identical decoded contents before excluding it from the ledger.
        if pn in self.packets:
            assert self.packets[pn] == frames, ('changed client packet', pn)
            return
        self.packets[pn] = frames
        for frame in frames:
            if frame['frame_type'] == 'ack':
                self.acks.append(dict(client_pn=pn, ranges=frame['acked_ranges']))
            elif frame['frame_type'] == 'path_response':
                token = frame['data']
                self.responses[token] += 1
                self.response_packets.append(dict(client_pn=pn, token=token))
                assert self.responses[token] <= self.expected[token], (
                    'unexpected PATH_RESPONSE / duplicate dispatch', token,
                    dict(self.expected), dict(self.responses))

    def ack_for(self, pn):
        return next((a for a in reversed(self.acks) if contains(a['ranges'], pn)), None)

    def pruned(self, fence, old):
        ack = self.ack_for(fence)
        assert ack is not None, ('missing fence ACK', fence)
        assert not contains(ack['ranges'], old), ('ACK history not pruned', old, ack)
        return ack

    def complete(self):
        assert self.responses == self.expected, ('missing PATH_RESPONSE',
                                                 self.responses, self.expected)


@dataclass(frozen=True)
class Packet:
    pn: int
    label: str
    generation: int
    wire: bytes
    token: bytes | None = None


class Schedule:
    """A finite schedule: only explicit first delivery authorizes a response."""

    def __init__(self, send, oracle):
        self.send = send
        self.oracle = oracle
        self.packets = {}
        self.states = {}
        self.actions = []

    def reserve(self, packet, state='ready'):
        assert state in ('ready', 'held', 'dropped')
        assert packet.pn not in self.packets, ('reused server packet number', packet.pn)
        assert len(self.packets) < 256, 'unbounded fixture schedule'
        self.packets[packet.pn] = packet
        self.states[packet.pn] = state
        self.actions.append(dict(action=state, pn=packet.pn, label=packet.label))
        return packet

    def deliver(self, packet, replay=False):
        assert self.packets[packet.pn] == packet
        state = self.states[packet.pn]
        if replay:
            assert state == 'sent', ('replay before delivery', packet.label, state)
        else:
            assert state in ('ready', 'held'), ('invalid first delivery', packet.label, state)
            self.states[packet.pn] = 'sent'
            if packet.token is not None:
                self.oracle.expect(packet.token)
        self.actions.append(dict(action='replay' if replay else 'send', pn=packet.pn,
                                 label=packet.label, generation=packet.generation))
        self.send(packet.wire)

    def report(self):
        return dict(actions=self.actions, packets=[dict(
            pn=p.pn, label=p.label, generation=p.generation, state=self.states[p.pn],
            token=None if p.token is None else p.token.hex(), wire=p.wire.hex(),
            sha256=hashlib.sha256(p.wire).hexdigest()) for p in self.packets.values()])


class Failures:
    def __init__(self):
        self.errors = []

    def record(self, error):
        self.errors.append(repr(error))

    def check(self):
        assert not self.errors, ('peer callback failure', self.errors)


def cancel_callbacks(peer):
    # QuicServer.close() starts draining and can leave protocol timers alive
    # after it closes the UDP transport. No callback may leak into the next case.
    for attribute in ('_timer', '_transmit_task'):
        handle = getattr(peer, attribute)
        if handle is not None:
            handle.cancel()
            setattr(peer, attribute, None)


async def until(predicate, failures, label):
    try:
        async with asyncio.timeout(5):
            while True:
                failures.check()
                if predicate():
                    return
                await asyncio.sleep(.001)
    except TimeoutError as error:
        raise AssertionError(f'timed out waiting for {label}') from error


async def check(binary, config, case):
    oracle, failures = Oracle(), Failures()
    ledger = dict(case=case, requests=[], updates=[], decryptions=[], pruning=[],
                  acks_sent=[], closes=[])
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
            self.cursor = 0
            self.generation = 0
            self.schedule = Schedule(self.send_wire, oracle)
            self.write_ack = self._quic._write_ack_frame

            def ack(builder, space, now):
                # Deliberately defer application ACKs until the script sends
                # them. Handshake ACKs and all other native behavior stay live.
                if self.scripted and space is self._quic._spaces[tls.Epoch.ONE_RTT]:
                    space.ack_at = None
                else:
                    self.write_ack(builder, space, now)
            self._quic._write_ack_frame = ack
            peers.append(self)
            if len(peers) != 1:
                failures.record('unexpected second connection')

        def send_wire(self, data):
            self._transport.sendto(data, self._quic._network_paths[0].addr)

        def datagram_received(self, data, addr):
            try:
                super().datagram_received(data, addr)
                trace = self._quic._quic_logger
                if trace is None:
                    return
                events = list(trace._events)
                for event in events[self.cursor:]:
                    if event['name'] != 'transport:packet_received':
                        continue
                    packet = event['data']
                    if packet['header']['packet_type'] == '1RTT':
                        # qlog records a mutable frames list before parsing;
                        # consume it only after receive_datagram has returned.
                        oracle.observe(packet['header']['packet_number'], packet['frames'])
                self.cursor = len(events)
            except Exception as error:
                failures.record(error)

        def observe_crypto(self):
            # Server crypto is initialized by the first datagram, not __init__.
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            update, decrypt = crypto._update_key, crypto.decrypt_packet

            def updated(trigger):
                old = crypto.send.key_phase
                update(trigger)
                assert crypto.send.key_phase != old
                self.generation += 1
                ledger['updates'].append(dict(trigger=trigger, old=old,
                    new=crypto.send.key_phase, generation=self.generation))

            def decrypted(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                head, _payload, pn = result
                ledger['decryptions'].append(dict(pn=pn, phase=(head[0] >> 2) & 1,
                                                  generation=self.generation))
                return result
            crypto._update_key, crypto.decrypt_packet = updated, decrypted

        def packet(self, label, token=None, state='ready', acknowledge=False):
            q = self._quic
            builder = QuicPacketBuilder(host_cid=q.host_cid, peer_cid=q._peer_cid.cid,
                version=q._version, is_client=False, max_datagram_size=1200,
                packet_number=q._packet_number, quic_logger=q._quic_logger)
            builder.start_packet(QuicPacketType.ONE_RTT, q._cryptos[tls.Epoch.ONE_RTT])
            now = loop.time()
            if acknowledge:
                self.write_ack(builder, q._spaces[tls.Epoch.ONE_RTT], now)
            if token is None:
                builder.start_frame(0x01, capacity=1)
            else:
                assert len(token) == 8
                builder.start_frame(0x1a, capacity=9).push_bytes(token)
            datagrams, packets = builder.flush()
            assert len(datagrams) == len(packets) == 1
            q._packet_number = builder.packet_number
            sent = packets[0]
            if acknowledge:
                frames = [f for f in sent.quic_logger_frames if f['frame_type'] == 'ack']
                assert len(frames) == 1
                ledger['acks_sent'].append(dict(server_pn=sent.packet_number,
                                                ranges=frames[0]['acked_ranges']))
            sent.sent_time = now
            q._loss.on_packet_sent(packet=sent, space=q._spaces[sent.epoch])
            q._network_paths[0].bytes_sent += len(datagrams[0])
            packet = Packet(sent.packet_number, label, self.generation, datagrams[0], token)
            return self.schedule.reserve(packet, state)

        async def delivered(self, packet):
            if packet.token is not None:
                # Preserve aioquic's own PATH_RESPONSE validation as well as
                # our frame ledger. Replays never reauthorize this mapping.
                self._quic._local_challenges[packet.token] = self._quic._network_paths[0]
            self.schedule.deliver(packet)
            self.transmit()
            await until(lambda: oracle.ack_for(packet.pn) is not None
                        and oracle.responses == oracle.expected, failures,
                        f'ACK and response of {packet.label}')
            oracle.complete()

        async def replay(self, packet, label):
            self.schedule.deliver(packet, replay=True)
            # A PING barrier cannot overwrite a pending PATH_RESPONSE. Its
            # authenticated ACK proves shb ran the receive loop after replay.
            fence = self.packet(label)
            await self.delivered(fence)
            oracle.complete()

        async def drive(self, sid):
            self.scripted = True
            self.observe_crypto()
            original = self.packet('original', b'original')
            await self.delivered(original)
            await self.replay(original, 'before-pruning')
            late = self.packet('late-unseen', b'late-one', state='held')
            lost = self.packet('lost-challenge', b'lost-one', state='dropped')
            last = original
            if case != 'ordinary':
                for i in range(40):
                    self.packet(f'gap-{i}', state='dropped')
                    last = self.packet(f'sparse-{i}')
                    await self.delivered(last)
                assert max(len(a['ranges']) for a in oracle.acks) == 32, 'sparse ACK bound not exercised'
            assert oracle.ack_for(late.pn) is None and oracle.ack_for(lost.pn) is None

            prior = oracle.ack_for(last.pn)
            assert prior is not None
            fence = self.packet('ack-of-ack', acknowledge=True)
            assert contains(ledger['acks_sent'][-1]['ranges'], prior['client_pn'])
            await self.delivered(fence)
            ledger['pruning'].append(dict(old=last.pn, fence=fence.pn,
                                          prior=prior, sent=ledger['acks_sent'][-1],
                                          ack=oracle.pruned(fence.pn, last.pn)))
            await self.replay(original, 'after-pruning')

            rotated = None
            if case == 'key-update':
                self._quic.request_key_update()
                rotated = self.packet('rotation-one', b'rotate-1')
                await self.delivered(rotated)
                await self.replay(original, 'previous-generation-replay')

            # A previously unseen old packet is still eligible, including
            # under the previous key generation after a rotation.
            await self.delivered(late)
            await self.delivered(self.packet('retransmission-new-pn', original.token))
            await self.delivered(self.packet('lost-frame-new-pn', lost.token))
            if rotated is not None:
                self._quic.request_key_update()
                await self.delivered(self.packet('rotation-two', b'rotate-2'))
                await self.replay(rotated, 'previous-generation-replay-two')
                await self.replay(original, 'expired-generation-replay')
                assert [u['trigger'] for u in ledger['updates']] == ['local_update'] * 2
                assert [u['new'] for u in ledger['updates']] == [1, 0]
                for generation in (1, 2):
                    assert any(d['generation'] == generation and d['phase'] == generation % 2
                               for d in ledger['decryptions']), ledger['decryptions']
            else:
                assert not ledger['updates']
            oracle.complete()
            self.scripted = False
            self.respond(sid)

        def respond(self, sid):
            self.h3.send_headers(sid, [(b':status', b'200'),
                                      (b'content-length', str(len(BODY)).encode())])
            self.h3.send_data(sid, BODY, end_stream=True)
            self.transmit()

        def quic_event_received(self, event):
            if isinstance(event, ConnectionTerminated):
                ledger['closes'].append(dict(code=event.error_code, frame=event.frame_type,
                                             reason=event.reason_phrase))
                # H3_NO_ERROR (0x100) is the client's normal application close.
                if event.error_code not in (0, 0x100) or event.frame_type is not None:
                    failures.record(('QUIC close', ledger['closes'][-1]))
            try:
                for e in self.h3.handle_event(event):
                    if isinstance(e, HeadersReceived):
                        assert e.stream_ended and dict(e.headers)[b':method'] == b'GET'
                        assert e.stream_id not in ledger['requests']
                        ledger['requests'].append(e.stream_id)
                        if len(ledger['requests']) == 1:
                            jobs.append(asyncio.create_task(self.drive(e.stream_id)))
                        else:
                            self.respond(e.stream_id)
            except Exception as error:
                failures.record(error)

    server, proc, communicate = None, None, None
    result = dict(case=case, ledger=ledger)
    try:
        server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
        port = server._transport.get_extra_info('sockname')[1]
        command = [str(binary), '--http3', '-j', '-t', '1', '-c', '1', '-p', '1',
                   '-n', str(REQUESTS), '--timeout', '15s', f'https://127.0.0.1:{port}/']
        result['command'] = command
        proc = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        communicate = asyncio.create_task(proc.communicate())
        async with asyncio.timeout(25):
            while not communicate.done():
                failures.check()
                for job in jobs:
                    if job.done():
                        job.result()
                await asyncio.sleep(.005)
            stdout, stderr = await communicate
            result.update(stdout=stdout.decode(), stderr=stderr.decode())
            assert proc.returncode == 0, result
            assert len(jobs) == 1
            await jobs[0]
            # Include callbacks queued with the final response in the verdict.
            await asyncio.sleep(.02)
            failures.check()
            oracle.complete()
            report = json.loads(stdout)
            validate_sample_accounting(report)
            assert report['requests'] == dict(total=REQUESTS, ok=REQUESTS, errors=0, connectErrors=0)
            assert report['statusCodes'] == {'200': REQUESTS}
            assert report['bytesReceived'] >= REQUESTS * len(BODY)
            assert len(ledger['requests']) == REQUESTS
            result['report'] = report
            result['passed'] = True
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
        ledger.update(expected=dict(oracle.expected), responses=dict(oracle.responses),
                      response_packets=oracle.response_packets, acks=oracle.acks,
                      schedules=[p.schedule.report() for p in peers])
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
