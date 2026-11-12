#!/usr/bin/env python3
"""Live response reordering correctness/exposure, never a throughput claim."""
import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger

from h3_response_flight import Peer, kill_group, validate_client, validate_peer
from native_reordering import require, socket_evidence, udp_snapshot, validate_exposure, validate_schedule, validate_udp, validate_wire

spec = importlib.util.spec_from_file_location('flight', Path(__file__).with_name('check-h3-response-flight.py'))
flight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flight)


class Probe(flight.Probe):
    def __init__(self, *args, drop_once=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.drop_once = drop_once
        self.dropped = []
        self.received_datagrams = 0

    def datagram_received(self, data, addr):
        self.received_datagrams += 1
        # Lose one actual response-sized 1-RTT UDP datagram before QUIC sees
        # it. All later copies reach the independent reader normally.
        if self.drop_once and self.streams and not self.dropped and data[0] & 0x80 == 0 and 1000 < len(data) <= 1200:
            self.dropped.append(dict(length=len(data), sha256=hashlib.sha256(data).hexdigest()))
            return
        super().datagram_received(data, addr)


class LoggedPeer(Peer):
    async def __aexit__(self, *args):
        await super().__aexit__(*args)
        (self.directory / 'cleanup.json').write_text(json.dumps(dict(
            pid=None if self.process is None else self.process.pid,
            returncode=None if self.process is None else self.process.returncode,
        )) + '\n')


async def run(args):
    task = asyncio.current_task()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    mode = 'missing-prefix' if args.fault == 'missing-prefix' else args.mode
    fault = args.fault if args.fault in ('corrupt', 'missing-fin') else 'none'
    prefix = ('env', f'SHB_NATIVE_REORDER={mode}:{args.size}:{args.chunk}')
    qlog = QuicLogger()
    summary = dict(mode=args.mode, fault=args.fault, requests=args.requests,
                   body_bytes=args.size, chunk=args.chunk, reader='shb' if args.shb else 'aioquic',
                   peer_sha256=hashlib.sha256(args.peer.read_bytes()).hexdigest())
    with (output / 'configuration.json').open('x') as f:
        json.dump(summary, f, indent=2)
    summary['udp_start'] = udp_snapshot()
    try:
        async with LoggedPeer(args.peer, output / 'case', args.requests, args.size,
                        deadline=12, prefix=prefix, fault=fault) as peer:
            host, port = peer.address.split(':')
            summary['socket_start'] = socket_evidence(peer.process.pid, int(port))
            if args.shb:
                require(args.fault == 'none', 'native shb fault checks require an instrumented byte oracle')
                command = [str(args.shb), '--http3', '-t', '1', '-c', '1', '-p', '1',
                           '-n', str(args.requests), '--timeout', '5s', '-j', f'https://{peer.address}/response']
                (output / 'client-command.json').write_text(json.dumps(command) + '\n')
                with (output / 'client.stdout').open('xb') as stdout, (output / 'client.stderr').open('xb') as stderr:
                    process = await asyncio.create_subprocess_exec(*command, stdout=stdout, stderr=stderr, start_new_session=True)
                    try:
                        await asyncio.wait_for(process.wait(), 40)
                    finally:
                        if process.returncode is None:
                            await kill_group(process)
                report = json.loads((output / 'client.stdout').read_bytes())
                (output / 'client-exit.json').write_text(json.dumps(process.returncode) + '\n')
                validate_client(report, process.returncode, args.requests, 1, 1)
                if args.exposure:
                    summary['exposure'] = validate_exposure((output / 'client.stderr').read_text(),
                                                           args.requests, args.size, args.chunk, args.mode)
                summary.update(report=report, client_sha256=hashlib.sha256(args.shb.read_bytes()).hexdigest())
                summary['socket_end'] = socket_evidence(peer.process.pid, int(port))
                ledger, code = await peer.finish()
                validate_peer(ledger, code, args.requests, args.size, 1)
            else:
                config = QuicConfiguration(is_client=True, alpn_protocols=['h3'], verify_mode=ssl.CERT_NONE,
                                           max_data=32 * 1048576, max_stream_data=16 * 1048576,
                                           quic_logger=qlog)
                async with connect(host, int(port), configuration=config,
                                   create_protocol=lambda *a, **k: Probe(*a, drop_once=args.fault == 'drop-once', **k)) as client:
                    udp = client._transport.get_extra_info('socket')
                    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1048576)
                    summary['reader_receive_buffer'] = udp.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                    summary['reader_socket_start'] = socket_evidence(os.getpid(), udp.getsockname()[1])
                    client.expected = flight.patterned_body(args.size)
                    if args.fault in ('missing-prefix', 'missing-fin', 'corrupt'):
                        require(args.requests == 1, 'negative cases require one request')
                        try:
                            await asyncio.wait_for(client.request(), 2.0)
                        except (asyncio.TimeoutError, ValueError) as error:
                            state = next(iter(client.streams.values()))
                            if args.fault == 'missing-prefix':
                                require(isinstance(error, asyncio.TimeoutError) and state['bytes'] == 0 and not state['ended'],
                                        'missing-prefix negative did not reach the intended blocked state')
                            elif args.fault == 'missing-fin':
                                require(isinstance(error, asyncio.TimeoutError) and state['bytes'] == args.size and not state['ended'],
                                        'missing-FIN negative did not deliver all bytes without completion')
                            else:
                                require('wrong response bytes' in str(error), 'corruption did not reach the byte oracle')
                            summary['rejected'] = dict(reason=str(error) or 'deadline', body_bytes=state['bytes'], ended=state['ended'])
                        else:
                            raise AssertionError('negative control was accepted')
                        summary['socket_end'] = socket_evidence(peer.process.pid, int(port))
                        summary['reader_socket_end'] = socket_evidence(os.getpid(), udp.getsockname()[1])
                    else:
                        for _ in range(args.requests):
                            await client.request()
                        require(not client.failure, 'independent reader failed')
                        summary.update(body_bytes_verified=args.requests * args.size,
                                       independent_completed=sum(s['ended'] for s in client.streams.values()),
                                       dropped=client.dropped, received_datagrams=client.received_datagrams)
                        summary['socket_end'] = socket_evidence(peer.process.pid, int(port))
                        summary['reader_socket_end'] = socket_evidence(os.getpid(), udp.getsockname()[1])
                        ledger, code = await peer.finish()
                        validate_peer(ledger, code, args.requests, args.size, 1)
                        stderr = (peer.directory / 'peer.stderr').read_text()
                        schedule = validate_schedule(stderr, args.requests, args.size, args.chunk, args.mode)
                        summary['wire'] = validate_wire(qlog.to_dict(), client.streams,
                                                        schedule['armed'][0]['start'], args.size, args.chunk, args.mode)
                        if args.fault == 'drop-once':
                            require(len(client.dropped) == 1 and schedule['transport']['lost_packets'] > 0,
                                    'loss control did not exercise packet recovery')
                if 'rejected' in summary:
                    # Close the incomplete connection and collect an explicit
                    # failing receipt ledger. No expected failure is concealed
                    # by killing the peer before its own accounting runs.
                    ledger, code = await peer.finish()
                    if args.fault != 'corrupt':
                        require(code != 0 and ledger['errors'], 'fault peer unexpectedly passed its receipt oracle')
            summary.update(peer=ledger, peer_exit=code)
            if 'rejected' not in summary:
                summary['schedule'] = validate_schedule((peer.directory / 'peer.stderr').read_text(),
                                                        args.requests, args.size, args.chunk, args.mode)
            summary['passed'] = True
        summary['udp_end'] = udp_snapshot()
        summary['udp_delta'] = validate_udp(summary['udp_start'], summary['udp_end'])
    except BaseException as error:
        summary.update(passed=False, error=repr(error))
        raise
    finally:
        if 'udp_end' not in summary:
            summary['udp_end'] = udp_snapshot()
            try:
                summary['udp_delta'] = validate_udp(summary['udp_start'], summary['udp_end'])
            except ValueError as error:
                summary['udp_error'] = str(error)
        (output / 'qlog.json').write_text(json.dumps(qlog.to_dict()) + '\n')
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--shb', type=Path)
    parser.add_argument('--exposure', action='store_true', help='require queue depth and exact DATA checks from an untimed observer')
    parser.add_argument('--mode', choices=('ordered', 'reverse', 'mixed', 'duplicates'), default='reverse')
    parser.add_argument('--fault', choices=('none', 'missing-prefix', 'missing-fin', 'corrupt', 'drop-once'), default='none')
    parser.add_argument('--requests', type=int, default=3)
    parser.add_argument('--size', type=int, default=513 * 1024)
    parser.add_argument('--chunk', type=int, default=1024)
    parser.add_argument('--namespace', choices=('user', 'sudo'), default='user',
                        help='create an isolated loopback namespace (sudo must be noninteractive)')
    arguments = parser.parse_args()
    require(not arguments.exposure or arguments.shb, '--exposure requires --shb')
    require(1 <= arguments.requests <= 512 and 64 <= arguments.chunk <= 1024,
            'invalid request/fragment bound')
    require(2 * arguments.chunk <= arguments.size <= 16 * 1048576, 'invalid body size')
    if 'NATIVE_REORDER_PARENT_NETNS' not in os.environ:
        # The PID namespace also contains subprocesses that use their own
        # process groups. Killing its init tears down every owned peer/client.
        launcher = ['unshare', '-Urnpf', '--mount-proc', '--kill-child=KILL'] if arguments.namespace == 'user' else ['sudo', '-n', 'unshare', '--net', '--pid', '--fork', '--mount-proc', '--kill-child=KILL']
        command = [*launcher, 'sh', '-c', 'ip link set lo up && exec "$@"', 'native-reorder',
                   'env', 'NATIVE_REORDER_PARENT_NETNS=' + os.readlink('/proc/self/ns/net'),
                   sys.executable, *sys.argv]
        raise SystemExit(subprocess.run(command).returncode)
    asyncio.run(run(arguments))
