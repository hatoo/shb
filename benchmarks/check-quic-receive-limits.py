#!/usr/bin/env python3
"""Independent encrypted aioquic oracle for shb's QUIC receive limits.

Requires aioquic==1.3.0. The peer replaces its STREAM writer to deliberately
violate credit/final-size rules without allocating gigabytes. aioquic still
performs the TLS handshake, packet encryption, ACK handling and close decoding.
All injected frames and complete CLI accounting/latency reports are retained.
"""
import argparse
import asyncio
import datetime
import json
from pathlib import Path
import tempfile

import aioquic
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CASES = {
    'stream-over': (1, 3),
    'stream-empty-over': (1, 3),
    'stream-fin-over': (1, 3),
    'reset-over': (1, 3),
    'connection-stream': (2, 3),
    'connection-reset': (2, 3),
    'fin-below-high-water': (1, 6),
    'reset-below-high-water': (1, 6),
    'changed-final-size': (1, 6),
    'offset-overflow': (1, 7),
    'valid-reordered': (1, None),
    'valid-duplicate-reset': (1, None),
}


def injected(case, ids, limit, connection_limit):
    # (kind, stream id, offset/final size, payload, fin)
    sid = ids[0]
    if case == 'stream-over':
        return [('stream', sid, limit, b'x', False)]
    if case in ('stream-empty-over', 'stream-fin-over'):
        return [('stream', sid, limit + 1, b'', case == 'stream-fin-over')]
    if case == 'reset-over':
        return [('reset', sid, limit + 1, b'', False)]
    if case.startswith('connection-'):
        kind = 'stream' if case == 'connection-stream' else 'reset'
        # Each frame obeys its own stream limit, their sum exceeds MAX_DATA.
        size = connection_limit // 2 + 1
        assert size <= limit
        return [(kind, i, size, b'', False) for i in ids]
    if case in ('fin-below-high-water', 'reset-below-high-water'):
        kind = 'stream' if case == 'fin-below-high-water' else 'reset'
        return [('stream', sid, 7, b'x', False), (kind, sid, 7, b'', True)]
    if case == 'changed-final-size':
        return [('stream', sid, 8, b'', True), ('reset', sid, 9, b'', False)]
    if case == 'offset-overflow':
        return [('stream', sid, (1 << 62) - 1, b'x', False)]
    if case == 'valid-duplicate-reset':
        return [('reset', sid, 8, b'', False)] * 2
    assert case == 'valid-reordered'
    # HEADERS containing the static QPACK :status 200, reordered/overlapped.
    response = b'\x01\x03\x00\x00\xd9'
    return [('stream', sid, 3, response[3:], True),
            ('stream', sid, 3, response[3:], True),
            ('stream', sid, 0, response[:4], False)]


async def check(binary, config, case):
    count, close_code = CASES[case]
    ledger = dict(requests=[], injected=[], closes=[])
    failures = []

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.h3 = H3Connection(self._quic)
            self.ids = []
            self.sent = False
            self.original_writer = self._quic._write_stream_frame
            self._quic._write_stream_frame = self.write_stream

        def write_stream(self, builder, space, stream, max_offset):
            if stream.stream_id not in self.ids or len(self.ids) < count or self.sent:
                return self.original_writer(builder, space, stream, max_offset)
            # Consume the trigger so aioquic cannot emit it as application data.
            assert stream.sender.get_frame(64, max_offset) is not None
            frames = injected(case, self.ids, stream.max_stream_data_remote,
                              self._quic._remote_max_data)
            for kind, sid, offset, data, fin in frames:
                if kind == 'reset':
                    buf = builder.start_frame(0x04, capacity=32)
                    buf.push_uint_var(sid)
                    buf.push_uint_var(0x10c)
                    buf.push_uint_var(offset)
                else:
                    buf = builder.start_frame(0x0e | int(fin), capacity=32 + len(data))
                    buf.push_uint_var(sid)
                    buf.push_uint_var(offset)
                    buf.push_uint_var(len(data))
                    buf.push_bytes(data)
                ledger['injected'].append(dict(kind=kind, id=sid, offset=offset,
                                                data=data.hex(), fin=fin))
            self.sent = True
            return 0

        def quic_event_received(self, event):
            if isinstance(event, ConnectionTerminated):
                ledger['closes'].append(dict(code=event.error_code, frame=event.frame_type,
                                             reason=event.reason_phrase))
            try:
                for e in self.h3.handle_event(event):
                    if isinstance(e, HeadersReceived):
                        assert e.stream_ended
                        assert dict(e.headers)[b':method'] == b'GET'
                        self.ids.append(e.stream_id)
                        ledger['requests'].append(e.stream_id)
                        if len(self.ids) == count:
                            self._quic.send_stream_data(self.ids[0], b'trigger', end_stream=True)
                            self.transmit()
            except Exception as error:
                failures.append(repr(error))

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    port = server._transport.get_extra_info('sockname')[1]
    command = [str(binary), '--http3', '-j', '-t', '1', '-c', '1', '-p', str(count),
               '-n', str(count), '--timeout', '2s', f'https://127.0.0.1:{port}/']
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), 10)
        await asyncio.sleep(.05)
        assert proc.returncode == 0, stderr.decode()
        assert not failures, failures
        report = json.loads(stdout)
        success = case == 'valid-reordered'
        ok = count if success else 0
        assert report['requests'] == dict(total=count, ok=ok, errors=count-ok, connectErrors=0), report
        assert report['statusCodes'] == ({'200': count} if success else {}), report
        assert (report['latencySeconds'] is not None) == success, report
        assert len(set(ledger['requests'])) == len(ledger['requests']) == count, ledger
        assert ledger['injected'], ledger
        if close_code is not None:
            assert any(c['code'] == close_code and c['frame'] is not None
                       for c in ledger['closes']), (case, close_code, ledger)
        else:
            assert not any(c['frame'] is not None for c in ledger['closes']), ledger
        return dict(case=case, command=command, report=report, ledger=ledger, stderr=stderr.decode())
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
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
        (path/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        config = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
        config.load_cert_chain(path/'cert', path/'key')
        rows = []
        for case in ([args.case] if args.case else CASES):
            rows.append(await check(args.shb.resolve(), config, case))
        print(json.dumps(dict(aioquic=aioquic.__version__, rows=rows), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--case', choices=CASES)
    asyncio.run(main(parser.parse_args()))
