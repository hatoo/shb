#!/usr/bin/env python3
"""Independent aioquic critical-stream closure and exact-accounting oracle.

Adapted from hatoo/xdp-http c433's h3_critical_server.py (MIT). QUIC/TLS,
request decoding, ordinary responses and close decoding belong to aioquic.
The harmless cases replace the unused encoder prefix rather than opening a
fourth stream: shb advertises exactly three peer unidirectional streams.
Requires aioquic==1.3.0 and pylsqpack==0.3.24. No throughput claims.
Closure waits for acknowledgement of the type prefix: resetting an unsent
prefix would instead test the explicitly permitted absent-type case.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path

import aioquic
import pylsqpack
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection, StreamType
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

from report_accounting import validate_sample_accounting

KINDS = ('control', 'encoder', 'decoder', 'unknown', 'empty', 'partial')
CRITICAL = KINDS[:3]
REASON = 'critical stream closed'


def audit(row):
    """Replay raw client/peer evidence; a timeout cannot pass as a rejection."""
    if row['client_exit'] != 0 or row['failures']:
        raise ValueError('client or independent peer failed')
    if row['cleanup'] != dict(client_reaped=True, communication_joined=True,
                              server_closed=True, peers_closed=True):
        raise ValueError('incomplete cleanup')
    report = json.loads(row['stdout'])
    validate_sample_accounting(report)
    workers = row['workers']
    critical = row['kind'] in CRITICAL
    count = workers * 4
    ok = 0 if critical else count
    if report['requests'] != dict(total=count, ok=ok, errors=count-ok, connectErrors=0):
        raise ValueError('incorrect request budget')
    if report['statusCodes'] != ({'200': ok} if ok else {}):
        raise ValueError('incorrect response statuses')
    if report['protocol'] != 'HTTP/3' or report['connections'] != workers or report['threads'] != workers:
        raise ValueError('incorrect client configuration')
    if len(row['peers']) != workers:
        raise ValueError('unexpected reconnect or missing connection')
    expected_code = (0x10c if row['baseline'] else 0x104) if critical else 0x100
    for peer in row['peers']:
        if not peer['handshake'] or peer['requests'] != [0, 4, 8, 12] or not peer['fired']:
            raise ValueError('missing handshake/requests/terminal action')
        prefix_size = 0 if row['kind'] == 'empty' else 1
        if not (type(peer['prefix_acked']) is int and type(peer['prefix_sent']) is int
                and prefix_size <= peer['prefix_acked'] <= peer['prefix_sent']):
            raise ValueError('type prefix was not acknowledged before closure')
        if len(peer['closes']) != 1:
            raise ValueError('missing or duplicate peer-decrypted close')
        close = peer['closes'][0]
        if close['code'] != expected_code or close['frame'] is not None:
            raise ValueError('wrong application close; request timeout is not critical closure')
        if critical and not row['baseline'] and close['reason'] != REASON:
            raise ValueError('wrong critical close reason')
        if peer['responses'] != ([] if critical else [0, 4, 8, 12]):
            raise ValueError('unexpected response ledger')
    if critical and not row['baseline'] and '[drive] peer closed a critical HTTP/3 stream' not in row['stderr']:
        raise ValueError('missing critical closure diagnosis')
    return dict(requests=count, completed=ok, errors=count-ok,
                samples=report['latencySamples'], close_code=expected_code)


async def trial(binary, config, kind, ending, workers, baseline):
    peers, failures = [], []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _, context: failures.append(str(context)))

    class Http(H3Connection):
        def _create_uni_stream(self, stream_type, push_id=None):
            if kind not in CRITICAL and stream_type == StreamType.QPACK_ENCODER:
                stream_id = self._quic.get_next_available_stream_id(is_unidirectional=True)
                self._quic.send_stream_data(stream_id, {'unknown': b'\x21', 'empty': b'', 'partial': b'\x40'}[kind])
                return stream_id
            return super()._create_uni_stream(stream_type, push_id)

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = Http(self._quic)
            self.ledger = dict(handshake=False, requests=[], responses=[], closes=[], fired=False)
            peers.append(self)

        def datagram_received(self, data, addr):
            super().datagram_received(data, addr)
            # ACK processing need not emit a QUIC application event.
            self.maybe_close_stream()

        def maybe_close_stream(self):
            if self.ledger['fired'] or len(self.ledger['requests']) != 4:
                return
            stream_id = getattr(self.http, '_local_' + (kind if kind in CRITICAL else 'encoder') + '_stream_id')
            sender = self._quic._streams[stream_id].sender
            # Read-only pinned-aioquic observation: _buffer_start advances
            # only when contiguous sent bytes are acknowledged. Never mutate
            # its delivery/recovery state to arrange the intended violation.
            prefix_size = 0 if kind == 'empty' else 1
            if sender._buffer_start < prefix_size:
                return
            self.ledger.update(prefix_sent=sender.highest_offset, prefix_acked=sender._buffer_start)
            if kind not in CRITICAL:
                for sid in self.ledger['requests']:
                    self.http.send_headers(sid, [(b':status', b'200'), (b'content-length', b'13')])
                    self.http.send_data(sid, b'x' * 13, end_stream=True)
                    self.ledger['responses'].append(sid)
            if ending == 'fin':
                self._quic.send_stream_data(stream_id, b'', end_stream=True)
            else:
                self._quic.reset_stream(stream_id, 0x100)
            self.ledger.update(fired=True, stream_id=stream_id)
            self.transmit()

        def quic_event_received(self, event):
            if isinstance(event, ConnectionTerminated):
                self.ledger['closes'].append(dict(code=event.error_code, frame=event.frame_type,
                                                  reason=event.reason_phrase))
                return
            if isinstance(event, HandshakeCompleted):
                self.ledger['handshake'] = event.alpn_protocol == 'h3'
            # No more instructions may be written to the intentionally closed
            # stream. All four requests were independently decoded before it.
            if self.ledger['fired']:
                return
            try:
                for received in self.http.handle_event(event):
                    if not isinstance(received, HeadersReceived):
                        continue
                    if not received.stream_ended or dict(received.headers).get(b':method') != b'GET':
                        raise ValueError('unexpected request')
                    self.ledger['requests'].append(received.stream_id)
                    self.maybe_close_stream()
            except Exception as error:
                failures.append(repr(error))

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    port = server._transport.get_extra_info('sockname')[1]
    command = [str(binary), '--http3', '-j', '-t', str(workers), '-c', str(workers),
               '-p', '4', '-n', str(4*workers), '--timeout', '2s', '--batch-linger', '1',
               f'https://127.0.0.1:{port}/']
    row = dict(kind=kind, ending=ending, workers=workers, baseline=baseline, command=command)
    proc, communication = None, None
    stdout, stderr = b'', b''
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1,
                                                   env=os.environ | {'SHB_DEBUG': '1'})
        communication = asyncio.create_task(proc.communicate())
        stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), 15)
        # Snapshot actual remote closes before server.close() creates any local
        # termination. No synthetic shutdown can satisfy the wire oracle.
        deadline = loop.time() + 3
        while peers and not all(peer.ledger['closes'] for peer in peers) and loop.time() < deadline:
            await asyncio.sleep(.01)
    except Exception as error:
        failures.append(repr(error))
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        if communication is not None:
            stdout, stderr = await communication
        row['peers'] = json.loads(json.dumps([peer.ledger for peer in peers]))
        transport = server._transport
        server.close()
        try:
            await asyncio.wait_for(asyncio.gather(*(peer.wait_closed() for peer in peers)), 5)
        except TimeoutError:
            failures.append('peer shutdown timeout')
        loop.set_exception_handler(previous_handler)
        row.update(client_exit=proc.returncode if proc else None, stdout=stdout.decode(), stderr=stderr.decode(),
                   failures=failures, cleanup=dict(client_reaped=proc is not None and proc.returncode is not None,
                       communication_joined=communication is not None and communication.done(),
                       server_closed=transport.is_closing(), peers_closed=all(peer._closed.is_set() for peer in peers)))
    try:
        row['counts'] = audit(row)
        row['passed'] = True
    except Exception as error:
        row.update(passed=False, failure=repr(error))
    return row


async def main(args):
    if aioquic.__version__ != '1.3.0' or pylsqpack.__version__ != '0.3.24':
        raise RuntimeError('requires aioquic==1.3.0 and pylsqpack==0.3.24')
    binary = args.shb.resolve()
    identity = hashlib.sha256(binary.read_bytes()).hexdigest()
    config = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
    certs = Path(__file__).resolve().parents[1] / 'docker/conf'
    config.load_cert_chain(certs/'cert.pem', certs/'key.pem')
    rows = []
    # Exclusive creation protects earlier evidence even if a later case fails.
    with args.output.open('x') as output:
        for workers in args.workers:
            for kind in args.kind or KINDS:
                for ending in ('fin', 'reset'):
                    row = await trial(binary, config, kind, ending, workers, args.baseline)
                    rows.append(row)
                    print(f'{workers}w {kind}/{ending}: {"PASS" if row["passed"] else row["failure"]}', flush=True)
        unchanged = hashlib.sha256(binary.read_bytes()).hexdigest() == identity
        sources = [Path(__file__), Path(__file__).with_name('report_accounting.py'),
                   certs / 'cert.pem', certs / 'key.pem']
        evidence = dict(binary=str(binary), sha256=identity, binary_unchanged=unchanged,
                        aioquic=aioquic.__version__, pylsqpack=pylsqpack.__version__,
                        sources={str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in sources}, rows=rows)
        json.dump(evidence, output, indent=2)
        output.write('\n')
    return 0 if unchanged and all(row['passed'] for row in rows) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true', help='require the known timeout failure, not the repair')
    parser.add_argument('--workers', type=int, choices=(1, 2), nargs='+', default=[1, 2])
    parser.add_argument('--kind', choices=KINDS, action='append')
    raise SystemExit(asyncio.run(main(parser.parse_args())))
