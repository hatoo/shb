#!/usr/bin/env python3
"""Independent aioquic oracle for flow-controlled HTTP/3 startup.

Checks exact control/QPACK prefixes, open critical streams, request/status/sample
counts, and recovery after loss, replay and a connection closed during startup.
With --cohort N, withholds all responses until N distinct TLS connections have
complete prefixes and one queued request each. The reconnect case uses N+1
attempts to account for the deliberately aborted startup.
Requires aioquic==1.3.0. This is a correctness test, not a throughput benchmark.
"""
import argparse
import asyncio
import datetime
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

import aioquic
from aioquic import tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived
from aioquic.quic.packet import pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from report_accounting import validate_sample_accounting
from h3_startup_cohort import (
    PREFIXES, GetCompletion, inspect_cohort, release_cohort, validate_cohort,
)

# Reuse the independent authenticated frame decoder, not shb's implementation.
spec = importlib.util.spec_from_file_location(
    'response_recovery', Path(__file__).with_name('check-quic-response-recovery.py'))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

CASES = {'ordinary': 1024, 'one-byte': 1, 'five-bytes': 5,
         'loss-replay': 1, 'reconnect': 1}
REQUESTS = 16


async def check(binary, config, case, baseline, cohort=None, barrier_timeout=5):
    peers, failures, requests = [], [], []
    failed = asyncio.get_running_loop().create_future()
    released = False
    deadline = None
    aborts = int(case == 'reconnect')

    def fail(message):
        failures.append(message)
        if not failed.done():
            failed.set_result(None)

    def maybe_release():
        nonlocal released
        ledgers = [p.ledger for p in peers]
        if released:
            inspect_cohort(ledgers, cohort, aborts)
            return
        ready = release_cohort(ledgers, cohort, aborts)
        if ready:
            released = True
            if deadline:
                deadline.cancel()
            for index in ready:
                peer = peers[index]
                request = peer.ledger['requests'][0]
                peer.h3.send_headers(request['id'],
                                     [(b':status', str(request['status']).encode())],
                                     end_stream=True)
                peer.ledger['responses'].append(dict(request))
                peer.transmit()

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.index = len(peers)
            window = 5 if case == 'reconnect' and self.index else CASES[case]
            # Keep bidirectional and connection credit ordinary, isolating the
            # three critical streams. Set this before TLS emits its parameters.
            self._quic._local_max_stream_data_uni = window
            self.h3 = H3Connection(self._quic)
            self.prefixes = {}
            self.gets = GetCompletion()
            self.ledger = dict(window=window, events=[], packets=[], requests=[], responses=[],
                               request_events=[],
                               cid=self._quic.original_destination_connection_id.hex(), tls=False,
                               aborted=False, dropped=None, replayed=False)
            self.held = None
            peers.append(self)

        def datagram_received(self, data, addr):
            try:
                replay = False
                if case == 'loss-replay' and not data[0] & 0x80:
                    q = self._quic
                    buf = Buffer(data=data)
                    pull_quic_header(buf, host_cid_length=len(q.host_cid))
                    # This peek does not advance packet numbers or receive state.
                    _, payload, pn, _ = q._cryptos[tls.Epoch.ONE_RTT].recv.decrypt_packet(
                        data, buf.tell(), q._spaces[tls.Epoch.ONE_RTT].expected_packet_number)
                    frames = recovery.decode_frames(payload)
                    spans = [f for f in frames if 8 <= f['type'] <= 15
                             and f['sid'] == 2 and f['data']]
                    for frame in spans:
                        chunk = bytes.fromhex(frame['data'])
                        offset = frame['offset']
                        assert chunk == PREFIXES[2][offset:offset + len(chunk)]
                        assert not frame['fin']
                    packet = dict(pn=pn, wire=data.hex(), frames=frames)
                    self.ledger['packets'].append(packet)
                    if self.ledger['dropped'] is None and any(f['offset'] > 0 for f in spans):
                        self.ledger['dropped'] = packet
                        self.held = (data, addr, spans)
                        return
                    if self.held:
                        replay = any(a['offset'] == b['offset'] and a['data'] == b['data']
                                     for a in spans for b in self.held[2])
                        if replay:
                            assert pn != self.ledger['dropped']['pn'], 'expected a retransmission'
                super().datagram_received(data, addr)
                if replay:
                    old, route, _ = self.held
                    self.held = None
                    # Original packet now arrives after its retransmission,
                    # then arrives again. The application must see each byte once.
                    super().datagram_received(old, route)
                    super().datagram_received(old, route)
                    self.ledger['replayed'] = True
            except Exception as exc:
                fail(repr(exc))

        def quic_event_received(self, event):
            try:
                if isinstance(event, HandshakeCompleted):
                    assert event.alpn_protocol == 'h3'
                    self.ledger['tls'] = True
                if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 2:
                    sid = event.stream_id
                    assert sid in PREFIXES, f'extra uni stream {sid}'
                    assert not event.end_stream, 'critical stream closed'
                    prefix = self.prefixes.get(sid, b'') + event.data
                    assert prefix == PREFIXES[sid][:len(prefix)], 'duplicated or changed prefix'
                    self.prefixes[sid] = prefix
                    self.ledger['events'].append(dict(id=sid, data=event.data.hex(), fin=False))
                    if case == 'reconnect' and self.index == 0 and not self.ledger['aborted']:
                        assert len(self.prefixes.get(2, b'')) < len(PREFIXES[2])
                        assert not self.ledger['requests']
                        self.ledger['aborted'] = True
                        self.close(error_code=0x100, reason_phrase='close during startup')
                        return
                for event in self.h3.handle_event(event):
                    if isinstance(event, HeadersReceived):
                        assert self.prefixes == PREFIXES, 'request before complete startup'
                        headers = dict(event.headers)
                        assert headers[b':method'] == b'GET' and headers[b':path'] == b'/'
                    elif not isinstance(event, DataReceived):
                        continue
                    is_headers = isinstance(event, HeadersReceived)
                    self.ledger['request_events'].append(dict(id=event.stream_id,
                        headers=is_headers, ended=event.stream_ended,
                        data='' if is_headers else event.data.hex()))
                    if self.gets.receive(event.stream_id, is_headers, event.stream_ended,
                                         b'' if is_headers else event.data):
                        key = (self.index, event.stream_id)
                        assert key not in requests, 'duplicate request'
                        requests.append(key)
                        status = 200 if len(requests) % 2 else 503
                        self.ledger['requests'].append(dict(id=event.stream_id, status=status))
                        if cohort:
                            maybe_release()
                        else:
                            self.h3.send_headers(event.stream_id,
                                                 [(b':status', str(status).encode())], end_stream=True)
                            self.ledger['responses'].append(dict(self.ledger['requests'][-1]))
            except Exception as exc:
                fail(repr(exc))

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    port = server._transport.get_extra_info('sockname')[1]
    total = cohort + aborts if cohort else REQUESTS
    command = [str(binary), '--http3', '-j', '-n', str(total), '-p', '1' if cohort else '4',
               '-c', str(cohort or 1), '-t', '1', '--connect-timeout', '10s',
               '--timeout', '10s' if cohort else '3s', f'https://127.0.0.1:{port}/']
    proc = None
    communication = None
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        if cohort and not released:
            def expire():
                ready = [i for i, p in enumerate(peers) if len(p.ledger['requests']) == 1
                         and not p.ledger['aborted']]
                fail(f'cohort barrier timed out: need {cohort}, ready {ready}, '
                     f'observed connections {len(peers)}')
            deadline = asyncio.get_running_loop().call_later(barrier_timeout, expire)
        communication = asyncio.create_task(proc.communicate())
        done, _ = await asyncio.wait([communication, failed], timeout=20,
                                     return_when=asyncio.FIRST_COMPLETED)
        assert not failures, failures
        assert communication in done, 'client did not finish within 20 seconds'
        stdout, stderr = communication.result()
        await asyncio.sleep(.01)
        assert proc.returncode == 0, stderr.decode()
        assert not failures, failures
        report = json.loads(stdout)
        validate_sample_accounting(report)
        assert not any(p.gets.pending for p in peers), 'incomplete GET at teardown'
        if cohort:
            assert released, 'cohort barrier did not release'
            validate_cohort([p.ledger for p in peers], cohort, aborts, report)
            if case == 'loss-replay':
                assert all(p.ledger['dropped'] and p.ledger['replayed'] for p in peers)
            return dict(case=case, cohort=cohort, command=command, report=report,
                        stderr=stderr.decode(), peers=[p.ledger for p in peers])
        broken = baseline and case != 'ordinary'
        errors = REQUESTS if broken else int(case == 'reconnect')
        ok = REQUESTS - errors
        assert report['requests'] == dict(total=REQUESTS, ok=ok, errors=errors,
                                          connectErrors=errors), report
        assert len(requests) == ok, requests
        expected_status = {'200': (ok + 1) // 2, '503': ok // 2} if ok else {}
        assert report['statusCodes'] == expected_status, report
        assert len(peers) == (REQUESTS if broken else 1 + int(case == 'reconnect'))
        if not broken:
            for peer in peers:
                if not peer.ledger['aborted']:
                    assert peer.prefixes == PREFIXES
            if case == 'loss-replay':
                assert peers[0].ledger['dropped'] is not None
                assert peers[0].ledger['replayed'], 'original packet was not replayed after recovery'
            if case == 'reconnect':
                assert peers[0].ledger['aborted']
        return dict(case=case, command=command, baseline=baseline, report=report,
                    stderr=stderr.decode(), peers=[p.ledger for p in peers])
    except Exception:
        print(json.dumps(dict(case=case, command=command, failures=failures,
                              peers=[p.ledger for p in peers])), file=sys.stderr)
        raise
    finally:
        if deadline:
            deadline.cancel()
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        if communication:
            await communication
        server.close()


async def main(args):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        (path / 'cert').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (path / 'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        config = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
        config.load_cert_chain(path / 'cert', path / 'key')
        rows = [await check(args.shb.resolve(), config, case, args.baseline,
                            args.cohort, args.barrier_timeout)
                for case in (args.case or CASES)]
        print(json.dumps(dict(aioquic=aioquic.__version__, rows=rows), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--baseline', action='store_true', help='expect the known short-write failure')
    parser.add_argument('--case', action='append', choices=CASES)
    parser.add_argument('--cohort', type=int, help='require one request per distinct connection')
    parser.add_argument('--barrier-timeout', type=float, default=5,
                        help='seconds to wait for all cohort members (default: 5)')
    args = parser.parse_args()
    if args.cohort is not None and (args.cohort < 1 or args.baseline):
        parser.error('--cohort requires a positive size and cannot use --baseline')
    if not 0 < args.barrier_timeout < 10:
        parser.error('--barrier-timeout must be between 0 and 10 seconds')
    asyncio.run(main(args))
