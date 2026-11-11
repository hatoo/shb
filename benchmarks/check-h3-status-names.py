#!/usr/bin/env python3
"""Independent aioquic / pylsqpack oracle for literal QPACK status names.

Install aioquic==1.3.0 and hpack==4.1.0 in a virtualenv. Pass --original for
an unpatched shb: only the known Huffman-name omission may fail valid cases.
All reports, wire byte ledgers, and independent decodes are retained as JSON.
These checks are correctness evidence, never throughput measurements.
"""
import argparse
import asyncio
from copy import copy
from dataclasses import asdict, dataclass
import datetime
import hashlib
import os
import json
from pathlib import Path
import tempfile

import aioquic
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
import pylsqpack

import h3_response_fragments as fragments

HUFFMAN = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
assert HUFFMAN.encode(b':status') == bytes.fromhex('b8848d36a3')


def integer(n, bits, mask):
    limit = (1 << bits) - 1
    if n < limit:
        return bytes([mask | n])
    out = bytearray([mask | limit])
    n -= limit
    while n >= 128:
        out.append(128 | (n & 127))
        n >>= 7
    out.append(n)
    return bytes(out)


def field(name, value, never=False, hn=False, hv=False):
    name = HUFFMAN.encode(name) if hn else name
    value = HUFFMAN.encode(value) if hv else value
    return (integer(len(name), 3, 0x20 | (0x10 if never else 0) | (8 if hn else 0))
            + name + integer(len(value), 7, 0x80 if hv else 0) + value)


def checked_section(body, fields):
    section = b'\0\0' + body
    instructions, decoded = pylsqpack.Decoder(0, 0).feed_header(0, section)
    assert instructions == b'' and decoded == fields, (section.hex(), decoded, fields)
    return section


@dataclass
class Case:
    name: str
    section: bytes
    status: int | None
    broken_original: bool = False
    fragmented: bool = False
    early_trailers: bool = False
    count: int = 4
    pipeline: int = 1
    wide: bool = False
    grease: bool = False


def cases():
    out = []
    for never in [False, True]:
        for hn in [False, True]:
            for hv in [False, True]:
                for status in [201, 404, 503]:
                    value = str(status).encode()
                    body = field(b':status', value, never, hn, hv)
                    section = checked_section(body, [(b':status', value)])
                    out.append(Case(f'n{int(never)}-hn{int(hn)}-hv{int(hv)}-{status}',
                                    section, status, hn))
    for never in [False, True]:
        for hv in [False, True]:
            # A large Huffman literal also exercises extended name/value lengths
            # and two-byte HTTP/3 HEADERS lengths. Keep pseudo-fields first.
            ignored = (b'x-ignored-field', b'abcdef' * 60)
            body = field(b':status', b'201', never, True, hv) + field(*ignored, hn=True, hv=True)
            section = checked_section(body, [(b':status', b'201'), ignored])
            out.append(Case(f'fragmented-n{int(never)}-hv{int(hv)}', section, 201, True,
                            fragmented=True, early_trailers=True))
    out.append(Case('multiplexed-literals', checked_section(field(b':status', b'503', True, True, True),
                   [(b':status', b'503')]), 503, True, early_trailers=True, count=128, pipeline=16))
    out.append(Case('static-control', checked_section(b'\xd9', [(b':status', b'200')]), 200,
                    early_trailers=True, count=32, pipeline=8))
    for name in [b'status', b':statu', b':statusx']:
        body = field(name, b'200', hn=True, hv=True)
        checked_section(body, [(name, b'200')])
        out.append(Case('missing-' + name.decode(), b'\0\0' + body, None, count=1))
        ordinary = name.lstrip(b':')
        section = checked_section(b'\xdb' + field(ordinary, b'200', hn=True, hv=True),
                                  [(b':status', b'404'), (ordinary, b'200')])
        out.append(Case('ignore-' + ordinary.decode(), section, 404))
    for value in [b'20', b'2x0']:
        out.append(Case('bad-value-' + value.decode(), checked_section(field(b':status', value, hn=True),
                       [(b':status', value)]), None, count=1))
    for name, section in [
        ('truncated-name', b'\0\0\x2d\xb8\x84'),
        ('truncated-value', b'\0\0\x2d\xb8\x84\x8d\x36\xa3\x0320'),
        ('bad-value-padding', b'\0\0\x2d\xb8\x84\x8d\x36\xa3\x82\x10\x02'),
    ]:
        try:
            pylsqpack.Decoder(0, 0).feed_header(0, section)
        except pylsqpack.DecompressionFailed:
            pass
        else:
            raise AssertionError(f'independent decoder accepted {name}')
        out.append(Case(name, section, None, count=1))
    for name, grease, count, pipeline in [
        ('wide-fragmented', False, 4, 1), ('wide-grease', True, 4, 1),
        ('wide-multiplexed', True, 16, 8),
    ]:
        section = checked_section(field(b':status', b'201', True, True, True), [(b':status', b'201')])
        out.append(Case(name, section, 201, True, fragmented=True, early_trailers=True,
                        count=count, pipeline=pipeline, wide=True, grease=grease))
    out.append(Case('wide-truncated-name', b'\0\0\x2d\xb8\x84', None,
                    fragmented=True, count=1, wide=True))
    return out


class TransportLedger:
    def __init__(self, transport, ledger):
        self.transport, self.ledger = transport, ledger

    def sendto(self, data, addr):
        self.transport.sendto(data, addr)
        self.ledger['server_datagram_bytes'].append(len(data))

    def __getattr__(self, name):
        return getattr(self.transport, name)


async def check(binary, config, case, original):
    loop = asyncio.get_running_loop()
    ledger = dict(requests=[], client_datagram_bytes=[], server_datagram_bytes=[], response_stream_bytes=0,
                  connections=0, tls=False, writes=[], packets=[], acks=[], premature_requests=[])
    jobs, failures, peers = [], [], []
    config = copy(config)
    old_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: failures.append(str(ctx.get('exception', ctx))))
    early = checked_section(field(b':status', b'103', True, True, True), [(b':status', b'103')])
    trailer = checked_section(field(b'status', b'103', hn=True, hv=True), [(b'status', b'103')])
    assert early == fragments.EARLY and trailer == fragments.TRAILER
    workload = asdict(case) | {'section': case.section.hex()}
    chunks = fragments.plan(workload)
    decodes = {}
    for name, section in [('final', case.section), ('early', early), ('trailer', trailer)]:
        try:
            instructions, fields = pylsqpack.Decoder(0, 0).feed_header(0, section)
            assert instructions == b''
            decodes[name] = dict(section=section.hex(), fields=[[n.hex(), v.hex()] for n, v in fields])
        except pylsqpack.DecompressionFailed:
            assert name == 'final' and case.status is None
            decodes[name] = dict(section=section.hex(), error='DecompressionFailed')
    config.quic_logger = QuicLogger()

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            ledger['connections'] += 1
            peers.append(self)
            self.h3 = H3Connection(self._quic)
            self.cursor = self.sequence = 0
            self.pending = set()
            logger = self.logger = self._quic._quic_logger
            encode_stream = logger.encode_stream_frame

            def stream_bytes(frame, stream_id):
                row = encode_stream(frame, stream_id=stream_id)
                if stream_id % 4 == 0:
                    row['data'] = frame.data.hex()
                return row
            logger.encode_stream_frame = stream_bytes
            send, receive = self._quic.datagrams_to_send, self._quic.receive_datagram

            def record_send(now):
                datagrams = send(now)
                self.record()
                return datagrams

            def record_receive(*args, **kwargs):
                result = receive(*args, **kwargs)
                # aioquic logs packet_received only after AEAD authentication.
                # The frames are complete when receive_datagram has returned.
                self.record()
                return result
            self._quic.datagrams_to_send = record_send
            self._quic.receive_datagram = record_receive

        def tick(self):
            self.sequence += 1
            return self.sequence

        def record(self):
            events = list(self.logger._events)
            for event in events[self.cursor:]:
                if event['name'] not in ('transport:packet_sent', 'transport:packet_received'):
                    continue
                packet = event['data']
                if packet['header']['packet_type'] != '1RTT':
                    continue
                pn = packet['header']['packet_number']
                if event['name'] == 'transport:packet_sent':
                    frames = [f for f in packet['frames'] if f['frame_type'] == 'stream' and f['stream_id'] % 4 == 0]
                    if frames:
                        ledger['packets'].append(dict(pn=pn, sequence=self.tick(), frames=frames))
                else:
                    ranges = [bounds for f in packet['frames'] if f['frame_type'] == 'ack' for bounds in f['acked_ranges']]
                    if ranges and not any(a['pn'] == pn for a in ledger['acks']):
                        ledger['acks'].append(dict(pn=pn, sequence=self.tick(), ranges=ranges))
            self.cursor = len(events)

        def connection_made(self, transport):
            super().connection_made(TransportLedger(transport, ledger))

        def datagram_received(self, data, addr):
            ledger['client_datagram_bytes'].append(len(data))
            super().datagram_received(data, addr)

        def quic_event_received(self, event):
            try:
                if isinstance(event, HandshakeCompleted):
                    assert event.alpn_protocol == 'h3'
                    ledger['tls'] = True
                for e in self.h3.handle_event(event):
                    if isinstance(e, HeadersReceived):
                        assert e.stream_ended
                        headers = dict(e.headers)
                        assert headers[b':method'] == b'GET' and headers[b':path'] == b'/'
                        if len(self.pending) >= case.pipeline:
                            ledger['premature_requests'].append(e.stream_id)
                        self.pending.add(e.stream_id)
                        ledger['requests'].append(e.stream_id)
                        jobs.append(asyncio.create_task(self.respond(e.stream_id)))
            except Exception as exc:
                failures.append(repr(exc))

        async def respond(self, stream_id):
            try:
                offset = 0
                for index, (name, chunk) in enumerate(chunks):
                    terminal = index == len(chunks) - 1
                    ledger['writes'].append(dict(id=stream_id, phase=name, offset=offset, data=chunk.hex(),
                                                  fin=terminal, sequence=self.tick()))
                    self._quic.send_stream_data(stream_id, chunk, end_stream=terminal)
                    ledger['response_stream_bytes'] += len(chunk)
                    self.transmit()
                    if not terminal:
                        deadline = loop.time() + 5
                        # The pinned sender advances this offset only after authenticated ACKs.
                        # Replay reconstructs proof separately from packet/ACK records.
                        while self._quic._streams[stream_id].sender._buffer_start < offset + len(chunk):
                            assert loop.time() < deadline, ('phase ACK deadline', stream_id, name)
                            await asyncio.sleep(.001)
                    offset += len(chunk)
                self.pending.remove(stream_id)
            except Exception as exc:
                failures.append(repr(exc))

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    port = server._transport.get_extra_info('sockname')[1]
    command = [str(binary), '--http3', '-j', '-t', '1', '-c', '1', '-p', str(case.pipeline),
               '-n', str(case.count), '--timeout', '10s', f'https://127.0.0.1:{port}/']
    proc, communication, report, stdout, stderr = None, None, None, b'', b''
    result = dict(case=case.name, workload=workload, original=original, command=command,
                  independent_decodes=decodes, passed=False)
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1,
                                                    env=os.environ | {'SHB_DEBUG': '1'})
        communication = asyncio.create_task(proc.communicate())
        stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), 60)
        await asyncio.wait_for(asyncio.gather(*jobs), 6)
        if proc.returncode == 0:
            report = json.loads(stdout)
    except Exception as exc:
        result['execution_failure'] = repr(exc)
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        if communication is not None:
            stdout, stderr = await communication
        for task in jobs:
            if not task.done():
                task.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
        transport = server._transport
        server.close()
        try:
            await asyncio.wait_for(asyncio.gather(*(p.wait_closed() for p in peers)), 5)
        except TimeoutError:
            failures.append('peer close deadline')
        loop.set_exception_handler(old_handler)
        result.update(report=report, stdout=stdout.decode(), stderr=stderr.decode(), peer=ledger,
                      client_exit=proc.returncode if proc else None, failures=failures,
                      cleanup=dict(client_reaped=proc is not None and proc.returncode is not None,
                                   tasks_joined=all(t.done() for t in jobs), server_closed=transport.is_closing(),
                                   connections_closed=all(p._closed.is_set() for p in peers)))
    try:
        fragments.validate_result(result)
        result['negative_controls'] = fragments.negative_controls(result)
        result['passed'] = True
    except Exception as exc:
        result['failure'] = repr(exc)
    return result


async def main(args):
    if not __debug__:
        raise RuntimeError('Run this wire oracle with Python assertions enabled')
    if aioquic.__version__ != '1.3.0' or pylsqpack.__version__ != '0.3.24':
        raise RuntimeError('This oracle requires aioquic==1.3.0 and pylsqpack==0.3.24')
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
        (path/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        config = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
        config.load_cert_chain(path/'cert', path/'key')
        rows = []
        for case in cases():
            if args.case and case.name not in args.case:
                continue
            row = await check(args.shb.resolve(), config, case, args.original)
            rows.append(row)
        evidence = dict(aioquic=aioquic.__version__, pylsqpack=pylsqpack.__version__,
                        original=args.original, rows=rows,
                        binary_sha256=hashlib.sha256(args.shb.read_bytes()).hexdigest())
        if args.output:
            with args.output.open('x') as stream:
                json.dump(evidence, stream, indent=2)
                stream.write('\n')
            print(json.dumps([dict(case=r['case'], passed=r['passed'], failure=r.get('failure'),
                                  controls=len(r.get('negative_controls', []))) for r in rows], indent=2))
        else:
            print(json.dumps(evidence, indent=2))
        if not rows or not all(row['passed'] for row in rows):
            raise RuntimeError([(r['case'], r.get('failure')) for r in rows if not r['passed']])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--original', action='store_true')
    parser.add_argument('--case', choices=[c.name for c in cases()], action='append')
    parser.add_argument('--output', type=Path, help='New JSON evidence file (never overwritten)')
    asyncio.run(main(parser.parse_args()))
