#!/usr/bin/env python3
"""Compare shb's sent bytes with an independent aioquic socket ledger.

Requires aioquic==1.3.0 and strace. Each raw teardown send is identified by its
exact payload and subtracted from the peer's received datagrams. io_uring sends
bypass the sendto syscall trace. This fixture is never a throughput measurement.
"""
import argparse
import asyncio
import datetime
import json
from pathlib import Path
import re
import tempfile

import aioquic
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


async def check(binary, certificate, key, count, parallel, repeat, directory):
    ledger = dict(datagrams=[], requests=[], response_body_bytes=0)
    failures = []
    config = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
    config.load_cert_chain(certificate, key)
    config.quic_logger = QuicLogger()

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.h3 = H3Connection(self._quic)

        def quic_event_received(self, event):
            try:
                for item in self.h3.handle_event(event):
                    if isinstance(item, HeadersReceived):
                        headers = dict(item.headers)
                        assert item.stream_ended
                        assert headers[b':method'] == b'GET'
                        assert headers[b':path'] == b'/'
                        ledger['requests'].append(item.stream_id)
                        self.h3.send_headers(item.stream_id, [(b':status', b'200')])
                        self.h3.send_data(item.stream_id, b'hello world', end_stream=True)
                        ledger['response_body_bytes'] += 11
                self.transmit()
            except Exception as exc:
                failures.append(repr(exc))

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    receive = server.datagram_received

    def record(data, address):
        # Count before endpoint demultiplexing, including the first Initial
        # and all packets arriving after the QUIC connection has closed.
        ledger['datagrams'].append(data.hex())
        receive(data, address)

    server.datagram_received = record
    port = server._transport.get_extra_info('sockname')[1]
    trace = directory / f'n{count}-p{parallel}-r{repeat}.strace'
    command = [
        'strace', '-f', '-qq', '-s', '65536', '-xx', '-e', 'trace=sendto',
        '-o', str(trace), str(binary), '--http3', '-j', '-t', '1', '-c', '1',
        '-p', str(parallel), '-n', str(count), '--timeout', '3s',
        f'https://127.0.0.1:{port}/',
    ]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        await asyncio.sleep(.03)  # Collect packets already accepted by the socket.
        assert process.returncode == 0, (process.returncode, stderr.decode())
        assert not failures, failures
        report = json.loads(stdout)
        assert report['requests'] == dict(total=count, ok=count, errors=0, connectErrors=0), report
        assert report['statusCodes'] == {'200': count} and report['latencySeconds']
        assert sorted(ledger['requests']) == list(range(0, count * 4, 4))
        assert ledger['response_body_bytes'] == count * 11
        teardown = []
        for line in trace.read_text().splitlines():
            match = re.search(
                r'sendto\(\d+, "((?:\\x[0-9a-f]{2})*)", (\d+), .*\)\s+= (\d+)$', line
            )
            assert match, line
            data = bytes.fromhex(match[1].replace('\\x', ''))
            assert int(match[3]) == len(data) == int(match[2]), line
            teardown.append(data.hex())
        assert len(teardown) == 1, teardown
        traffic = list(ledger['datagrams'])
        for packet in teardown:
            assert traffic.count(packet) == 1, 'each successful close must reach the peer once'
            traffic.remove(packet)
        sent = sum(len(packet) // 2 for packet in traffic)
        return dict(
            count=count, parallel=parallel, repeat=repeat, report=report,
            wire_benchmark_bytes=sent, deficit=sent-report['bytesSent'],
            command=command, ledger=ledger, raw_teardown=teardown,
            syscall_trace=trace.read_text(), qlog=config.quic_logger.to_dict(),
            stderr=stderr.decode(),
        )
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        server.close()


async def main(args):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now-datetime.timedelta(days=1))
            .not_valid_after(now+datetime.timedelta(days=1)).sign(key, hashes.SHA256())
        )
        (path/'cert').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (path/'key').write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        rows = []
        for count, parallel in [(1, 1), (8, 8), (64, 16), (257, 128)]:
            for repeat in range(3):
                rows.append(await check(args.shb.resolve(), path/'cert', path/'key',
                                        count, parallel, repeat, path))
        # Print evidence before asserting so a failed CI run retains the ledger.
        print(json.dumps(dict(aioquic=aioquic.__version__, rows=rows), indent=2))
        if args.original:
            assert all(row['deficit'] >= 0 for row in rows)
            assert any(row['deficit'] > 0 for row in rows), 'original deficit did not reproduce'
        else:
            assert all(row['deficit'] == 0 for row in rows), [
                (row['count'], row['parallel'], row['repeat'], row['deficit']) for row in rows
            ]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--original', action='store_true', help='require the original undercount')
    asyncio.run(main(parser.parse_args()))
