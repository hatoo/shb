#!/usr/bin/env python3
"""Independent encrypted QUIC timer regression, not a throughput benchmark.

Pinned aioquic supplies TLS, packet protection, ACK encoding and stream delivery.
The Rust adapter uses public production APIs and explicit logical times only.
All commands and encrypted datagrams survive a failed assertion in the output.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import time

import aioquic
from aioquic import tls
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (ConnectionIdIssued, ConnectionIdRetired,
                                ConnectionTerminated, HandshakeCompleted,
                                ProtocolNegotiated, StreamDataReceived)
from aioquic.quic.packet import (QuicPacketType, pull_quic_header, push_ack_frame,
                                pull_quic_transport_parameters,
                                push_quic_transport_parameters)
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.rangeset import RangeSet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Share the existing independent wire parser and strict offset/byte/FIN model.
spec = importlib.util.spec_from_file_location(
    'recovery_oracle', Path(__file__).with_name('check-quic-response-recovery.py'))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
decode_frames, StreamBytes = recovery.decode_frames, recovery.StreamBytes

ALPN = 'quic-timer-oracle'
ADDRESS = ('127.0.0.1', 4433)
CASES = ('ordinary', 'loss', 'sparse-reordered')
FAULTS = ('missing-ack', 'missing-fin', 'corrupt-receipt')


def receipt(data):
    return b'received:' + hashlib.sha256(data).hexdigest().encode()


def complete(actual, expected, label):
    assert actual.end == len(expected), f'{label}: missing or wrong FIN'
    assert actual.complete(), f'{label}: incomplete bytes'
    assert bytes(actual.data[i] for i in range(actual.end)) == expected, f'{label}: corrupt receipt/bytes'


class Peer(QuicConnection):
    def _serialize_transport_parameters(self):
        params = pull_quic_transport_parameters(Buffer(data=super()._serialize_transport_parameters()))
        params.max_ack_delay = 0
        buf = Buffer(capacity=4096)
        push_quic_transport_parameters(buf, params)
        self.wire_parameters = buf.data
        return buf.data


class Run:
    def __init__(self, adapter, output, case, fault):
        self.case, self.fault = case, fault
        self.output = output
        output.mkdir(parents=True, exist_ok=False)
        self.ledger = (output/'wire.jsonl').open('x')
        self.stderr = (output/'adapter.stderr').open('xb')
        self.process = subprocess.Popen([str(adapter)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0)
        self.buffer = b''
        self.commands = 0
        self.wall_deadline = time.monotonic() + 30
        self.now = 0
        self.peer = None
        self.client_connected = self.peer_connected = False
        self.responses, self.requests, self.expected = {}, {}, {}
        self.finished = set()
        self.packets = {}
        self.responded = set()
        self.target = None
        self.scripted = False
        self.last_peer_time = 0
        self.result = dict(case=case, fault=fault, passed=False)

    def log(self, **row):
        self.ledger.write(json.dumps(row) + '\n')
        self.ledger.flush()

    def command(self, op, at, **fields):
        assert self.commands < 4096 and self.now <= at <= 30_000_000
        self.commands += 1
        self.now = at
        command = dict(op=op, time_us=at, **fields)
        self.log(command=command)
        self.process.stdin.write((json.dumps(command)+'\n').encode())
        deadline = min(self.wall_deadline, time.monotonic()+5)
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'adapter response deadline'
            assert select.select([self.process.stdout], [], [], remaining)[0], 'adapter response timeout'
            chunk = os.read(self.process.stdout.fileno(), 65536)
            assert chunk, f'adapter exited: {self.process.poll()}'
            self.buffer += chunk
            assert len(self.buffer) <= 1_000_000, 'adapter output limit'
        line, self.buffer = self.buffer.split(b'\n', 1)
        response = json.loads(line)
        self.log(response=response)
        for event in response['events']:
            kind = event['type']
            if kind == 'connected':
                assert not self.client_connected
                self.client_connected = True
                continue
            stream = self.responses.setdefault(event['sid'], StreamBytes())
            offset = len(stream.data)
            assert kind in ('data', 'fin'), event
            assert event['sid'] not in self.finished, 'response event after FIN'
            if kind == 'fin':
                self.finished.add(event['sid'])
            stream.add(dict(offset=offset, data=event.get('data', ''), fin=kind == 'fin'))
        return response

    def make_peer(self, wire):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now-datetime.timedelta(days=1))
            .not_valid_after(now+datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        header = pull_quic_header(Buffer(data=wire), host_cid_length=8)
        config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN],
                                  certificate=cert, private_key=key, idle_timeout=60)
        self.peer = Peer(configuration=config,
                         original_destination_connection_id=header.destination_cid)
        self.peer._ack_delay = 0

    def observe(self, wire, at, delivered):
        assert len(wire) <= 1200
        row = dict(direction='client', time_us=at, wire=wire.hex(), delivered=delivered)
        if not wire[0] & 0x80:
            q = self.peer
            buf = Buffer(data=wire)
            pull_quic_header(buf, host_cid_length=len(q.host_cid))
            _, payload, pn, update = q._cryptos[tls.Epoch.ONE_RTT].recv.decrypt_packet(
                wire, buf.tell(), q._spaces[tls.Epoch.ONE_RTT].expected_packet_number)
            assert not update, 'unexpected key update'
            frames = decode_frames(payload)
            assert len(frames) <= 128 and len(self.packets) < 4096
            row.update(pn=pn, frames=frames)
            assert pn not in self.packets, 'unexpected repeated client packet number'
            self.packets[pn] = row
        self.log(**row)
        return row

    def peer_receive(self, wires, at):
        assert self.last_peer_time <= at
        self.last_peer_time = at
        for wire in wires:
            self.peer.receive_datagram(wire, ADDRESS, now=at/1e6)
        while (event := self.peer.next_event()) is not None:
            if isinstance(event, HandshakeCompleted):
                assert event.alpn_protocol == ALPN and not event.session_resumed and not event.early_data_accepted
                self.peer_connected = True
                params = pull_quic_transport_parameters(Buffer(data=self.peer.wire_parameters))
                assert params.max_ack_delay == 0
                self.log(handshake='complete', parameters=self.peer.wire_parameters.hex(),
                         max_ack_delay=params.max_ack_delay)
            elif isinstance(event, StreamDataReceived):
                sid = event.stream_id
                assert sid in self.expected, 'unexpected request stream'
                stream = self.requests.setdefault(sid, StreamBytes())
                stream.add(dict(offset=len(stream.data), data=event.data.hex(), fin=event.end_stream))
                if stream.complete() and sid not in self.responded:
                    complete(stream, self.expected[sid], 'request')
                    reply = receipt(self.expected[sid])
                    target = sid == self.target
                    if target and self.fault == 'corrupt-receipt':
                        reply = b'X' + reply[1:]
                    self.peer.send_stream_data(sid, reply,
                        end_stream=not (target and self.fault == 'missing-fin'))
                    self.responded.add(sid)
            elif isinstance(event, ConnectionTerminated):
                raise AssertionError(f'peer terminated: {event}')
            else:
                assert isinstance(event, (ProtocolNegotiated, ConnectionIdIssued, ConnectionIdRetired)), event
        return self.peer_send(at)

    def peer_send(self, at):
        if self.scripted:
            self.peer._spaces[tls.Epoch.ONE_RTT].ack_at = None
        wires = [wire for wire, _ in self.peer.datagrams_to_send(at/1e6)]
        for wire in wires:
            self.log(direction='peer', time_us=at, wire=wire.hex())
        return wires

    def drain(self, client_wires, at):
        # Fixed 50 ms in each direction. No timers or sleeps during the
        # successful handshake and RTT-training exchanges.
        for _ in range(16):
            if not client_wires:
                return at
            for wire in client_wires:
                self.observe(wire, at, True)
            replies = self.peer_receive(client_wires, at+50_000)
            client_wires = []
            at += 100_000
            for wire in replies:
                response = self.command('receive', at, wire=wire.hex())
                client_wires.extend(bytes.fromhex(w) for w in response['datagrams'])
        raise AssertionError('exchange turn limit')

    def request(self, at, data):
        response = self.command('request', at, data=data.hex())
        sid = response['opened']
        assert sid is not None and sid not in self.expected
        self.expected[sid] = data
        return sid, [bytes.fromhex(w) for w in response['datagrams']]

    def control(self, at, ranges=(), ping=False):
        q = self.peer
        assert self.last_peer_time <= at
        self.last_peer_time = at
        builder = QuicPacketBuilder(host_cid=q.host_cid, peer_cid=q._peer_cid.cid,
            version=q._version, is_client=False, max_datagram_size=1200,
            packet_number=q._packet_number)
        builder.start_packet(QuicPacketType.ONE_RTT, q._cryptos[tls.Epoch.ONE_RTT])
        ack = RangeSet()
        for lo, hi in ranges:
            for pn in range(lo, hi+1):
                assert pn in self.packets and self.packets[pn]['delivered'], 'ACK of undelivered packet'
            ack.add(lo, hi+1)
        if ranges:
            push_ack_frame(builder.start_frame(2, capacity=256), ack, 0)
        if ping:
            builder.start_frame(1, capacity=1)
        wires, packets = builder.flush()
        assert len(wires) == len(packets) == 1
        q._packet_number = builder.packet_number
        packets[0].sent_time = at/1e6
        q._loss.on_packet_sent(packet=packets[0], space=q._spaces[packets[0].epoch])
        q._network_paths[0].bytes_sent += len(wires[0])
        self.log(direction='peer-control', time_us=at, wire=wires[0].hex(),
                 pn=packets[0].packet_number, ranges=ranges, ping=ping)
        return wires[0]

    def execute(self):
        response = self.command('poll', 0)
        initial = [bytes.fromhex(w) for w in response['datagrams']]
        assert initial
        self.make_peer(initial[0])
        at = self.drain(initial, 0)
        assert self.client_connected and self.peer_connected, 'full TLS handshake required'
        for i in range(40):
            at = max(at, self.now) + 100_000
            sid, wires = self.request(at, f'settle-rtt-{i}'.encode())
            at = self.drain(wires, at)
            complete(self.responses[sid], receipt(self.expected[sid]), 'warmup response')
        at = max(at, self.now, self.last_peer_time) + 200_000
        if self.case == 'ordinary':
            self.target, wires = self.request(at, b'timer-target-request')
            self.drain(wires, at)
        else:
            self.scripted = True
            # Sent one path delay before the target, arriving just after its
            # send. The client ACK-only packet traverses a real 100 ms RTT.
            ping = self.control(at-50_000, ping=True)
            self.target, wires = self.request(at, b'timer-target-request')
            assert len(wires) == 1, 'target must occupy exactly one packet'
            lost = self.observe(wires[0], at, False)
            original = StreamBytes()
            for frame in lost['frames']:
                if 'sid' in frame:
                    assert frame['sid'] == self.target, 'mixed target packet'
                    original.add(frame)
            complete(original, self.expected[self.target], 'dropped request')
            reply = self.command('receive', at, wire=ping.hex())
            assert len(reply['datagrams']) == 1
            ack_wire = bytes.fromhex(reply['datagrams'][0])
            ack = self.observe(ack_wire, at, True)
            assert ack['pn'] == lost['pn']+1, 'target packet ordering changed'
            assert any(f['type'] == 2 for f in ack['frames'])
            assert all(f['type'] in (0, 2, 3) for f in ack['frames']), 'expected ACK-only packet'
            assert not self.peer_receive([ack_wire], at+50_000), 'unexpected peer output'
            previous = lost['pn']-1
            ranges = [(ack['pn'], ack['pn'])]
            stale = None
            if self.case == 'sparse-reordered':
                assert self.packets[previous]['delivered']
                ranges.insert(0, (previous, previous))
                stale = self.control(at+50_000, [(previous, previous)])
            wire = self.control(at+50_000, ranges)
            if self.fault != 'missing-ack':
                reply = self.command('receive', at+100_000, wire=wire.hex())
                assert not reply['datagrams'], 'request recovered before timer expiry'
            else:
                reply = self.command('poll', at+100_000)
            deadline = reply['deadline_us'] - at
            if stale:
                assert not self.command('receive', at+100_100, wire=stale.hex())['datagrams']
                assert not self.command('receive', at+100_200, wire=wire.hex())['datagrams']
            early = self.command('timeout', at+105_000)
            premature = [bytes.fromhex(w) for w in early['datagrams']]
            late = self.command('timeout', at+113_000)
            recovered = [bytes.fromhex(w) for w in late['datagrams']]
            self.result.update(deadline_after_send_us=deadline, lost_pn=lost['pn'],
                ack_only_pn=ack['pn'], premature_probes=early['probing'],
                premature_datagrams=len(premature), premature_bytes=sum(map(len, premature)),
                loss_datagrams=len(recovered), loss_bytes=sum(map(len, recovered)),
                recovery_datagrams=len(premature)+len(recovered),
                recovery_bytes=sum(map(len, premature+recovered)))
            # Preserve the exact same network schedule even on the historical
            # implementation: premature packets reach the peer only after loss.
            for emitted, sent_at in ((premature, at+105_000), (recovered, at+113_000)):
                for packet in emitted:
                    self.observe(packet, sent_at, True)
            self.scripted = False
            replies = self.peer_receive(premature+recovered, at+163_000)
            after = []
            for packet in replies:
                after.extend(bytes.fromhex(w) for w in self.command(
                    'receive', at+213_000, wire=packet.hex())['datagrams'])
            self.drain(after, at+213_000)
        assert set(self.requests) == set(self.expected), 'missing/extra request streams'
        assert set(self.responses) == set(self.expected), 'missing/extra response streams'
        for sid, data in self.expected.items():
            complete(self.requests.get(sid, StreamBytes()), data, 'request')
            complete(self.responses.get(sid, StreamBytes()), receipt(data), 'response')
        self.result.update(complete_streams=len(self.expected),
            request_bytes=sum(map(len, self.expected.values())),
            response_bytes=sum(len(receipt(data)) for data in self.expected.values()))
        if self.case != 'ordinary':
            assert 112_000 <= deadline <= 113_000, 'pending loss did not suppress PTO'
            assert not early['probing'] and not premature, 'premature PTO probe'
            assert recovered, 'loss did not recover request'
        self.result['passed'] = True

    def close(self):
        self.process.stdin.close()
        try:
            status = self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            status = -9
        self.result['adapter_exit'] = status
        if status:
            self.result['passed'] = False
            self.result.setdefault('error', f'adapter exit {status}')
        self.stderr.close()
        self.ledger.close()
        (self.output/'result.json').write_text(json.dumps(self.result, indent=2)+'\n')


def check(adapter, output, case, fault=None):
    run = Run(adapter, output, case, fault)
    try:
        run.execute()
    except Exception as error:
        run.result['error'] = f'{type(error).__name__}: {error}'
    finally:
        run.close()
    return run.result


def adapter_bounds(adapter, output):
    commands = {
        'line-size': b'x'*32769,
        'unterminated': b'{',
        'unknown-op': b'{"op":"unknown","time_us":0}\n',
        'missing-time': b'{"op":"poll"}\n',
        'time-horizon': b'{"op":"poll","time_us":30000001}\n',
        'backward-time': b'{"op":"poll","time_us":1}\n{"op":"poll","time_us":0}\n',
        'odd-hex': b'{"op":"receive","time_us":0,"wire":"a"}\n',
        'datagram-size': (json.dumps(dict(op='receive', time_us=0, wire='00'*1201))+'\n').encode(),
    }
    rows = []
    for name, command in commands.items():
        result = subprocess.run([str(adapter)], input=command, capture_output=True, timeout=5)
        row = dict(name=name, rejected=result.returncode != 0, exit=result.returncode,
                   input=command.decode(), stdout=result.stdout.decode(), stderr=result.stderr.decode())
        rows.append(row)
    (output/'adapter-bounds.json').write_text(json.dumps(rows, indent=2)+'\n')
    return rows


def main(args):
    assert aioquic.__version__ == '1.3.0', 'private peer APIs require pinned aioquic'
    args.output.mkdir(parents=True, exist_ok=False)
    rows = [check(args.adapter.resolve(), args.output/case, case)
            for case in ([args.case] if args.case else CASES)]
    negatives = []
    if not args.case:
        for fault in FAULTS:
            row = check(args.adapter.resolve(), args.output/fault, 'loss', fault)
            # A failed process or handshake does not validate a negative oracle.
            expected = {'missing-ack': 'pending loss did not suppress PTO',
                        'missing-fin': 'missing or wrong FIN',
                        'corrupt-receipt': 'corrupt receipt/bytes'}[fault]
            row['detected'] = not row['passed'] and row['adapter_exit'] == 0 and expected in row.get('error', '')
            negatives.append(row)
    bounds = adapter_bounds(args.adapter.resolve(), args.output)
    result = dict(aioquic=aioquic.__version__, adapter_sha256=hashlib.sha256(args.adapter.read_bytes()).hexdigest(),
                  rows=rows, negatives=negatives, bounds=[dict(name=r['name'], rejected=r['rejected']) for r in bounds])
    (args.output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return 0 if (all(r['passed'] for r in rows) and all(r['detected'] for r in negatives)
                 and all(r['rejected'] for r in bounds)) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES)
    raise SystemExit(main(parser.parse_args()))
