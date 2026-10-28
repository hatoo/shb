#!/usr/bin/env python3
"""Independent aioquic response-byte/FIN oracle plus native shb receipt checks."""
import argparse
import asyncio
import json
import ssl
from pathlib import Path

from aioquic.asyncio import connect
from aioquic import tls
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset

from h3_response_flight import Peer, run_shb, validate_peer, validate_fin_frames


def patterned_body(size):
    return bytes((i * 31 + i // 251) % 256 for i in range(size))


class Probe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.expected = b''
        self.streams = {}
        self.failure = None

    def quic_event_received(self, event):
        try:
            response_event = isinstance(event, StreamDataReceived) and event.stream_id in self.streams
            if isinstance(event, StreamReset) and event.stream_id in self.streams:
                raise ValueError(f'response reset: {event}')
            if response_event:
                self.streams[event.stream_id]['wire'].extend(event.data)
            if isinstance(event, ConnectionTerminated):
                if any(not state['future'].done() for state in self.streams.values()):
                    raise ValueError(f'connection closed before response completion: {event}')
                if event.error_code not in (0, 0x100):
                    raise ValueError(f'unexpected close: {event}')
            for http in self.http.handle_event(event):
                if not isinstance(http, (HeadersReceived, DataReceived)):
                    continue
                state = self.streams[http.stream_id]
                if state['ended']:
                    raise ValueError('data after FIN')
                if isinstance(http, HeadersReceived):
                    if state['headers']:
                        raise ValueError('duplicate headers/trailers')
                    headers = http.headers
                    if (headers.count((b':status', b'200')) != 1 or
                            [v for k, v in headers if k == b'content-length'] != [str(len(self.expected)).encode()]):
                        raise ValueError(f'wrong response headers: {headers}')
                    state['headers'] = True
                else:
                    offset = state['bytes']
                    if not state['headers'] or http.data != self.expected[offset:offset + len(http.data)]:
                        raise ValueError(f'wrong response bytes at offset {offset}')
                    state['bytes'] += len(http.data)
            # aioquic emits no H3 event for a final ignored GREASE frame.
            # Observe authenticated QUIC FIN directly, after H3 consumed its bytes.
            if response_event and event.end_stream:
                state = self.streams[event.stream_id]
                validate_fin_frames(state['wire'])
                if not state['headers'] or state['bytes'] != len(self.expected):
                    raise ValueError(f'truncated response: {state["bytes"]}')
                state['ended'] = True
                state['wire'].clear()
                state['future'].set_result(state['bytes'])
        except Exception as error:
            self.failure = error
            for state in self.streams.values():
                if not state['future'].done():
                    state['future'].set_exception(error)

    async def request(self, *, method=b'GET', body=b''):
        if self.failure:
            raise self.failure
        stream = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self.streams[stream] = dict(headers=False, bytes=0, ended=False, future=future, wire=bytearray())
        headers = [(b':method', method), (b':scheme', b'https'),
                   (b':authority', b'localhost'), (b':path', b'/response')]
        if body:
            headers.append((b'content-length', str(len(body)).encode()))
        self.http.send_headers(stream, headers, end_stream=not body)
        if body:
            self.http.send_data(stream, body, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(future, 10)


async def probe_case(binary, directory, size, *, fault='none', bad_request=False):
    count = 1 if fault != 'none' or bad_request else 5
    config = QuicConfiguration(is_client=True, alpn_protocols=['h3'], verify_mode=ssl.CERT_NONE,
                               max_data=32 * 1048576, max_stream_data=16 * 1048576)
    async with Peer(binary, directory, count, size, fault=fault, deadline=12) as peer:
        host, port = peer.address.split(':')
        async with connect(host, int(port), configuration=config, create_protocol=Probe) as client:
            client.expected = patterned_body(size)
            if bad_request:
                await client.request(method=b'POST', body=b'unexpected')
            else:
                # A following request on the same connection, then multiplexing.
                for _ in range(min(count, 3)):
                    await client.request()
                if count > 3:
                    await asyncio.gather(client.request(), client.request())
            ledger, code = await peer.finish()
            validate_peer(ledger, code, count, size, 1)
            if client.failure:
                raise client.failure
            return dict(size=size, responses=count, body_bytes=count * size, peer=ledger)


async def missing_receipt_case(binary, directory):
    """Complete HTTP bytes/FIN without transport ACKs must not count as receipt."""
    config = QuicConfiguration(is_client=True, alpn_protocols=['h3'], verify_mode=ssl.CERT_NONE)
    async with Peer(binary, directory, 1, 1024, deadline=3) as peer:
        host, port = peer.address.split(':')
        async with connect(host, int(port), configuration=config, create_protocol=Probe) as client:
            client.expected = patterned_body(1024)
            original_ack = client._quic._write_ack_frame
            suppressed = 0

            def withhold_application_ack(builder, space, now):
                nonlocal suppressed
                if space is client._quic._spaces[tls.Epoch.ONE_RTT]:
                    space.ack_at = None
                    suppressed += 1
                else:
                    original_ack(builder=builder, space=space, now=now)

            # Only this negative test touches aioquic's pinned transport internals.
            client._quic._write_ack_frame = withhold_application_ack
            received = await client.request()
            ledger, code = await peer.finish()
            if received != 1024 or suppressed == 0 or ledger['finished'] != 1:
                raise AssertionError('receipt negative did not deliver the full response')
            if ledger['acknowledged'] != 0 or code == 0 or not ledger['errors']:
                raise AssertionError('unacknowledged response passed the receipt oracle')
            return dict(negative='missing-receipt', received=received,
                        suppressed_acks=suppressed, peer=ledger, peer_exit=code)


async def incomplete_run_cases(binary, directory):
    rows = []
    async with Peer(binary, directory / 'empty', 1, 1024) as peer:
        ledger, code = await peer.finish()
        if code == 0 or not ledger['errors'] or ledger['accepted'] != 0:
            raise AssertionError('empty run passed')
        rows.append(dict(negative='empty-run', peer=ledger, peer_exit=code))
    async with Peer(binary, directory / 'early-exit', 1, 1024) as peer:
        peer.process.kill()
        await peer.process.wait()
        try:
            await peer.finish()
        except ValueError as error:
            rows.append(dict(negative='early-exit', rejected=str(error)))
        else:
            raise AssertionError('early peer exit passed')
    return rows


async def main(args):
    rows = []
    for size in (1024, 1048576, 8 * 1048576):
        rows.append(await probe_case(args.peer, args.output / f'probe-{size}', size))
    # Deliberate wire failures test the body/FIN oracle, not a claimed speedup.
    for fault in ('truncate', 'corrupt', 'missing-fin', 'late-error'):
        try:
            await probe_case(args.peer, args.output / f'negative-{fault}', 1024, fault=fault)
        except (ValueError, asyncio.TimeoutError) as error:
            expected = {'truncate': 'truncated response:', 'corrupt': 'wrong response bytes at offset 0',
                        'late-error': 'injected late receipt failure'}
            if fault == 'missing-fin':
                if not isinstance(error, asyncio.TimeoutError):
                    raise
            elif expected[fault] not in str(error):
                raise
            rows.append(dict(negative=fault, rejected=str(error) or 'deadline'))
        else:
            raise AssertionError(f'{fault} was accepted')
    try:
        await probe_case(args.peer, args.output / 'negative-request', 1024, bad_request=True)
    except (ValueError, asyncio.TimeoutError) as error:
        diagnostic = (args.output / 'negative-request' / 'peer.stderr').read_text()
        if 'expected GET' not in diagnostic:
            raise AssertionError(f'request was not rejected by method validation: {diagnostic}') from error
        rows.append(dict(negative='request', rejected=str(error) or 'deadline'))
    else:
        raise AssertionError('invalid request was accepted')
    rows.append(await missing_receipt_case(args.peer, args.output / 'negative-receipt'))
    rows.extend(await incomplete_run_cases(args.peer, args.output / 'negative-lifecycle'))
    for connections, parallel in ((1, 1), (2, 4)):
        for size in (1048576, 8 * 1048576):
            result = await run_shb(args.peer, args.shb, args.output / f'shb-{connections}-{parallel}-{size}',
                                   requests=16, size=size, connections=connections, parallel=parallel)
            rows.append(dict(shb=True, size=size, connections=connections, parallel=parallel, **result))
    (args.output / 'summary.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(json.dumps(rows, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', required=True, type=Path)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=False)
    asyncio.run(main(arguments))
