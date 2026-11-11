#!/usr/bin/env python3
"""Encrypted aioquic GOAWAY/response/reset/reconnect accounting oracle.

Requires aioquic==1.3.0. Each phase waits for an authenticated client ACK before
the next phase. Packet logs prove co-location of the mixed response/reset case.
This is a correctness check, not a throughput measurement.
"""
import argparse
import asyncio
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

import aioquic
from aioquic import tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer, encode_uint_var
from aioquic.h3.connection import H3Connection, encode_frame
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from h3_goaway import CASES, negative_controls, validate_result

spec = importlib.util.spec_from_file_location(
    'recovery', Path(__file__).with_name('check-quic-response-recovery.py'))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

UPLOAD = b'goaway-complete-retry-body-' * 1024


async def check(binary, certificate, key, case, parallel):
    loop = asyncio.get_running_loop()
    peers, jobs, failures = [], [], []
    config = QuicConfiguration(is_client=False, alpn_protocols=['h3'],
                              max_stream_data=128 if case == 'blocked-upload' else 1048576)
    config.load_cert_chain(certificate, key)
    config.quic_logger = QuicLogger()
    old_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: failures.append(str(ctx.get('exception', ctx))))

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.index = len(peers)
            self.h3 = H3Connection(self._quic)
            self.phase = 'startup'
            self.started = False
            self.acknowledged = set()
            self.cursor = 0
            self.bodies = {}
            self.ledger = dict(index=self.index, requests=[], responses=[], goaways=[],
                               packets=[], phases=[], resets=[], tls=False, closed=[],
                               client_resets=[], complete_uploads=[],
                               control_stream_id=self.h3._local_control_stream_id)
            peers.append(self)
            if case == 'blocked-upload' and self.index == 0:
                write_limits = self._quic._write_stream_limits

                def hold_request_credit(builder, space, stream):
                    if stream.stream_id % 4 != 0:
                        write_limits(builder, space, stream)
                self._quic._write_stream_limits = hold_request_credit
            send = self._quic.datagrams_to_send
            logger = self._quic._quic_logger

            def record(now):
                datagrams = send(now)
                events = list(logger._events)
                for event in events[self.cursor:]:
                    if event['name'] == 'transport:packet_sent':
                        packet = event['data']
                        if packet['header']['packet_type'] == '1RTT':
                            self.ledger['packets'].append(dict(
                                phase=self.phase, pn=packet['header']['packet_number'],
                                frames=packet['frames']))
                self.cursor = len(events)
                return datagrams
            self._quic.datagrams_to_send = record

        def datagram_received(self, data, addr):
            try:
                if not data[0] & 0x80:
                    q = self._quic
                    buf = Buffer(data=data)
                    pull_quic_header(buf, host_cid_length=len(q.host_cid))
                    _, payload, _, _ = q._cryptos[tls.Epoch.ONE_RTT].recv.decrypt_packet(
                        data, buf.tell(), q._spaces[tls.Epoch.ONE_RTT].expected_packet_number)
                    for frame in recovery.decode_frames(payload):
                        if frame['type'] == 4:
                            self.ledger['client_resets'].append(frame['values'])
                        if frame['type'] in (2, 3):
                            for lo, hi in frame['ranges']:
                                assert hi - lo < 4096
                                self.acknowledged.update(range(lo, hi + 1))
                super().datagram_received(data, addr)
            except Exception as exc:
                failures.append(repr(exc))

        def response(self, sid, status, partial=False):
            self.h3.send_headers(sid, [(b':status', str(status).encode())])
            self.h3.send_data(sid, b'part', end_stream=not partial)
            self.ledger['responses'].append(dict(id=sid, status=status, finished=not partial))

        def finish(self, sid):
            self.h3.send_data(sid, b'last', end_stream=True)
            row = next(row for row in self.ledger['responses'] if row['id'] == sid)
            assert not row['finished']
            row['finished'] = True

        def goaway(self, boundary):
            self._quic.send_stream_data(self.h3._local_control_stream_id,
                                       encode_frame(7, encode_uint_var(boundary)))
            self.ledger['goaways'].append(boundary)

        async def barrier(self, name):
            self.phase = name
            self.transmit()
            packets = [p for p in self.ledger['packets'] if p['phase'] == name]
            assert packets, ('phase did not transmit', name)
            numbers = {p['pn'] for p in packets}
            deadline = loop.time() + 5
            while not numbers <= self.acknowledged:
                assert loop.time() < deadline, ('phase ACK deadline', name, numbers,
                                                self.acknowledged, failures)
                await asyncio.sleep(.001)
            self.ledger['phases'].append(dict(
                name=name, sent=sorted(numbers),
                acknowledged=sorted(numbers & self.acknowledged)))

        async def schedule(self):
            try:
                if case == 'mixed':
                    self.goaway(16)
                    self.response(0, 200)
                    self.response(4, 201, partial=True)
                    self._quic.reset_stream(8, 0x102)
                    self.response(16, 203)
                    self._quic.reset_stream(20, 0x102)
                    self.response(24, 204, partial=True)
                    self.ledger['resets'] += [8, 20]
                    await self.barrier('mixed')
                    for i in range(3):
                        self.goaway(16)
                        await self.barrier(f'repeated-{i}')
                    await asyncio.sleep(.1)
                    self.finish(4)
                    self.response(12, 202)
                elif case == 'decreasing':
                    self.response(4, 201, partial=True)
                    for i, boundary in enumerate([24, 24, 16, 8, 8]):
                        self.goaway(boundary)
                        await self.barrier(f'boundary-{i}')
                    await asyncio.sleep(.1)
                    self.response(0, 200)
                    self.finish(4)
                elif case == 'no-suffix':
                    self.goaway(parallel * 4)
                    for sid in self.ledger['requests']:
                        self.response(sid, 200, partial=sid == 0)
                    await self.barrier('no-suffix')
                    for i in range(4):
                        self.goaway(parallel * 4)
                        await self.barrier(f'repeated-{i}')
                    await asyncio.sleep(.1)
                    self.finish(0)
                elif case == 'zero':
                    self.goaway(0)
                elif case == 'blocked-upload':
                    self.goaway(16)
                    await self.barrier('blocked-upload')
                    deadline = loop.time() + 5
                    while {row[0] for row in self.ledger['client_resets']} != {16, 20, 24, 28}:
                        assert loop.time() < deadline, ('missing cancellation', self.ledger)
                        await asyncio.sleep(.001)
                    assert all(row[1:] == [0x10c, 128] for row in self.ledger['client_resets'])
                    self.ledger['cancelled_before_response'] = sorted(
                        {row[0] for row in self.ledger['client_resets']})
                    await asyncio.sleep(.1)
                    for sid in [0, 4, 8, 12]:
                        self.response(sid, 200)
                else:
                    for sid in self.ledger['requests']:
                        self.response(sid, 200)
                self.phase = 'final'
                self.transmit()
                self.ledger['scheduled'] = True
            except Exception as exc:
                failures.append(repr(exc))

        def quic_event_received(self, event):
            try:
                if isinstance(event, HandshakeCompleted):
                    assert event.alpn_protocol == 'h3'
                    self.ledger['tls'] = True
                if isinstance(event, ConnectionTerminated):
                    self.ledger['closed'].append(event.error_code)
                for item in self.h3.handle_event(event):
                    if isinstance(item, HeadersReceived):
                        headers = dict(item.headers)
                        method = b'POST' if case == 'blocked-upload' else b'GET'
                        assert headers[b':method'] == method and headers[b':path'] == b'/'
                        assert item.stream_ended == (case != 'blocked-upload')
                        assert item.stream_id not in self.ledger['requests']
                        self.ledger['requests'].append(item.stream_id)
                        if self.index and case != 'blocked-upload':
                            self.response(item.stream_id, 205)
                        elif self.index == 0 and len(self.ledger['requests']) == parallel:
                            assert not self.started
                            self.started = True
                            jobs.append(asyncio.create_task(self.schedule()))
                    elif isinstance(item, DataReceived):
                        assert case == 'blocked-upload'
                        body = self.bodies.setdefault(item.stream_id, bytearray())
                        body.extend(item.data)
                        assert UPLOAD.startswith(body), 'changed upload bytes'
                        if item.stream_ended:
                            assert self.index > 0 and body == UPLOAD
                            self.ledger['complete_uploads'].append(item.stream_id)
                            self.response(item.stream_id, 205)
            except Exception as exc:
                failures.append(repr(exc))

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    port = server._transport.get_extra_info('sockname')[1]
    command = [str(binary), '--http3', '-j', '-t', '1', '-c', '1', '-p', str(parallel),
               '-n', str(parallel), '--timeout', '10s', f'https://127.0.0.1:{port}/']
    if case == 'blocked-upload':
        body_path = Path(certificate).with_name('upload')
        body_path.write_bytes(UPLOAD)
        command += ['-m', 'POST', '-d', '@' + str(body_path)]
    process, communication, report, stdout, stderr = None, None, None, b'', b''
    result = dict(case=case, parallel=parallel, command=command, passed=False)
    try:
        process = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        communication = asyncio.create_task(process.communicate())
        stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), 30)
        await asyncio.wait_for(asyncio.gather(*jobs), 5)
        await asyncio.sleep(.03)
        if process.returncode == 0:
            report = json.loads(stdout)
    except Exception as exc:
        result['failure'] = repr(exc)
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        if communication is not None:
            stdout, stderr = await communication
        for job in jobs:
            if not job.done():
                job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
        server.close()
        await asyncio.sleep(.01)
        loop.set_exception_handler(old_handler)
        result.update(report=report, stdout=stdout.decode(), stderr=stderr.decode(),
                      peers=[p.ledger for p in peers], failures=failures,
                      client_exit=process.returncode if process else None)
    if 'failure' not in result:
        try:
            validate_result(result)
            result['negative_controls'] = negative_controls(result)
            result['passed'] = True
        except Exception as exc:
            result['failure'] = repr(exc)
    return result


async def main(args):
    if not __debug__:
        raise RuntimeError('Run the wire oracle with Python assertions enabled')
    if aioquic.__version__ != '1.3.0':
        raise RuntimeError('This wire oracle requires aioquic==1.3.0')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now-datetime.timedelta(days=1))
                .not_valid_after(now+datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        (path/'cert').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (path/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        rows = []
        for case in args.case or CASES:
            for parallel in ([8] if case in ('mixed', 'decreasing', 'blocked-upload') else [1, 64]):
                rows.append(await check(args.shb.resolve(), path/'cert', path/'key', case, parallel))
        evidence = dict(aioquic=aioquic.__version__, rows=rows,
                        binary_sha256=hashlib.sha256(args.shb.read_bytes()).hexdigest())
        if args.output:
            with args.output.open('x') as stream:
                json.dump(evidence, stream, indent=2)
                stream.write('\n')
            print(json.dumps([dict(case=r['case'], parallel=r['parallel'],
                passed=r['passed'], controls=len(r.get('negative_controls', [])),
                failure=r.get('failure')) for r in rows], indent=2))
        else:
            print(json.dumps(evidence, indent=2))
        if not all(row['passed'] for row in rows):
            raise RuntimeError([(r['case'], r.get('failure')) for r in rows if not r['passed']])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, action='append')
    parser.add_argument('--output', type=Path, help='New JSON evidence file (never overwritten)')
    asyncio.run(main(parser.parse_args()))
