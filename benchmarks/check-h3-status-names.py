#!/usr/bin/env python3
"""Independent aioquic / pylsqpack oracle for literal QPACK status names.

Install aioquic==1.3.0 and hpack==4.1.0 in a virtualenv. Pass --original for
an unpatched shb: only the known Huffman-name omission may fail valid cases.
All reports, wire byte ledgers, and independent decodes are retained as JSON.
These checks are correctness evidence, never throughput measurements.
"""
import argparse
import asyncio
from dataclasses import dataclass
import datetime
import json
from pathlib import Path
import tempfile

import aioquic
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, encode_frame, FrameType
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
import pylsqpack

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
    ledger = dict(requests=[], client_datagram_bytes=[], server_datagram_bytes=[], response_stream_bytes=0)
    jobs = []
    failures = []
    early = checked_section(field(b':status', b'103', True, True, True), [(b':status', b'103')])
    trailer = checked_section(field(b'status', b'103', hn=True, hv=True), [(b'status', b'103')])
    response = encode_frame(FrameType.HEADERS, case.section)
    if case.early_trailers:
        response = (encode_frame(FrameType.HEADERS, early) + response
                    + encode_frame(FrameType.DATA, b'body') + encode_frame(FrameType.HEADERS, trailer))

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.h3 = H3Connection(self._quic)

        def connection_made(self, transport):
            super().connection_made(TransportLedger(transport, ledger))

        def datagram_received(self, data, addr):
            ledger['client_datagram_bytes'].append(len(data))
            super().datagram_received(data, addr)

        def quic_event_received(self, event):
            try:
                for e in self.h3.handle_event(event):
                    if isinstance(e, HeadersReceived):
                        assert e.stream_ended
                        headers = dict(e.headers)
                        assert headers[b':method'] == b'GET' and headers[b':path'] == b'/'
                        ledger['requests'].append(e.stream_id)
                        jobs.append(asyncio.create_task(self.respond(e.stream_id)))
            except Exception as exc:
                failures.append(repr(exc))

        async def respond(self, stream_id):
            # Force actual QUIC stream fragmentation, including inside the
            # name. A fresh reader is required for each multiplexed response.
            width = 3 if case.fragmented else len(response)
            for offset in range(0, len(response), width):
                chunk = response[offset:offset+width]
                self._quic.send_stream_data(stream_id, chunk, end_stream=offset+len(chunk)==len(response))
                ledger['response_stream_bytes'] += len(chunk)
                self.transmit()
                if case.fragmented:
                    await asyncio.sleep(.001)

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    port = server._transport.get_extra_info('sockname')[1]
    command = [str(binary), '--http3', '-j', '-t', '1', '-c', '1', '-p', str(case.pipeline),
               '-n', str(case.count), '--timeout', '3s', f'https://127.0.0.1:{port}/']
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), 15)
        await asyncio.gather(*jobs)
        await asyncio.sleep(.01)  # collect final client control packets
        assert not failures, failures
        assert proc.returncode == 0, stderr.decode()
        report = json.loads(stdout)
        success = case.status is not None and not (original and case.broken_original)
        expected = case.count if success else 0
        assert report['requests'] == dict(total=case.count, ok=expected, errors=case.count-expected, connectErrors=0), report
        assert report['statusCodes'] == ({str(case.status): case.count} if success else {}), report
        assert (report['latencySeconds'] is not None) == success, report
        assert len(ledger['requests']) == len(set(ledger['requests'])) == case.count, ledger
        assert ledger['response_stream_bytes'] == len(response) * case.count, ledger
        # Packet tail ACKs and close frames can remain unread at shutdown;
        # retain both byte ledgers without pretending they must be identical.
        assert 0 < report['bytesReceived'] <= sum(ledger['server_datagram_bytes'])
        assert report['bytesSent'] > 0
        return dict(case=case.name, section=case.section.hex(), expected_success=success,
                    command=command, report=report, stderr=stderr.decode(), ledger=ledger)
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        for task in jobs:
            if not task.done():
                task.cancel()
        server.close()


async def main(args):
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
            row = await check(args.shb.resolve(), config, case, args.original)
            rows.append(row)
        print(json.dumps(dict(aioquic=aioquic.__version__, pylsqpack=pylsqpack.__version__,
                              original=args.original, rows=rows), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--original', action='store_true')
    asyncio.run(main(parser.parse_args()))
