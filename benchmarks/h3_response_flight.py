"""Strict native response-peer lifecycle and report checks; no packet I/O here."""
import asyncio
import json
import os
from pathlib import Path
import signal

from report_accounting import validate_sample_accounting


def validate_fin_frames(wire):
    """FIN must follow complete H3 frames, including an ignored final GREASE frame."""
    offset = 0

    def varint():
        nonlocal offset
        if offset == len(wire):
            raise ValueError('FIN within frame header')
        length = 1 << (wire[offset] >> 6)
        if length > len(wire) - offset:
            raise ValueError('FIN within varint')
        value = int.from_bytes(wire[offset:offset + length], 'big') & ((1 << (8 * length - 2)) - 1)
        offset += length
        return value

    while offset < len(wire):
        varint()  # Frame type; semantics and body bytes are checked by aioquic.
        size = varint()
        if size > len(wire) - offset:
            raise ValueError('FIN within frame payload')
        offset += size


def validate_peer(ledger, returncode, requests, size, connections=None):
    if returncode != 0:
        raise ValueError(f'peer exit {returncode}: {ledger}')
    expected = dict(accepted=requests, validated=requests, finished=requests,
                    acknowledged=requests, acknowledgedBodyBytes=requests * size,
                    expectedRequests=requests, bodyBytes=size)
    for key, value in expected.items():
        if type(ledger.get(key)) is not int or ledger[key] != value:
            raise ValueError(f'peer {key}: expected {value}, got {ledger.get(key)}')
    if ledger.get('errors') != [] or ledger.get('fault') != 'None':
        raise ValueError(f'peer errors or injected fault: {ledger}')
    actual_connections = ledger.get('connections')
    if type(actual_connections) is not int or actual_connections <= 0:
        raise ValueError('missing connection count')
    if connections is not None and actual_connections != connections:
        raise ValueError(f'unexpected connections: {actual_connections}')


def validate_client(report, returncode, requests, connections, parallel, threads=1):
    if returncode != 0:
        raise ValueError(f'client exit {returncode}')
    validate_sample_accounting(report)
    if type(report['requests'].get('connectErrors')) is not int:
        raise ValueError('invalid connection-error count')
    if report['requests'] != dict(total=requests, ok=requests, errors=0, connectErrors=0):
        raise ValueError(f'client request accounting: {report["requests"]}')
    if report['statusCodes'] != {'200': requests}:
        raise ValueError('unexpected response status')
    if report['protocol'] != 'HTTP/3' or report['connections'] != connections or report['threads'] != threads:
        raise ValueError('wrong client configuration')
    # parallel is recorded in the command, since shb does not report it.
    if parallel < 1:
        raise ValueError('invalid parallelism')


class Peer:
    def __init__(self, binary, directory, requests, size, *, workers=2,
                 deadline=30, fault='none', prefix=()):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.requests, self.size, self.deadline = requests, size, deadline
        self.command = [*prefix, str(binary), '--requests', str(requests),
                        '--body-bytes', str(size), '--workers', str(workers),
                        '--deadline-seconds', str(deadline), '--fault', fault]
        self.process = None

    async def __aenter__(self):
        self.stderr = (self.directory / 'peer.stderr').open('xb')
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.command, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=self.stderr, start_new_session=True)
            self.ready_line = await asyncio.wait_for(self.process.stdout.readline(), 10)
            (self.directory / 'peer.ready').write_bytes(self.ready_line)
            ready = json.loads(self.ready_line)
            if (ready['expectedRequests'], ready['bodyBytes']) != (self.requests, self.size):
                raise ValueError('peer ready configuration mismatch')
            self.address = ready['ready']
            if not self.address.startswith('127.0.0.1:'):
                raise ValueError('expected loopback peer')
            (self.directory / 'peer-command.json').write_text(json.dumps(self.command) + '\n')
            return self
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def finish(self):
        if self.process.returncode is not None:
            raise ValueError(f'peer exited before finish: {self.process.returncode}')
        output, _ = await asyncio.wait_for(self.process.communicate(b'finish\n'), self.deadline + 5)
        (self.directory / 'peer.stdout').write_bytes(output)
        # Exactly one complete final record. Extra/missing records fail parsing.
        self.ledger = json.loads(output)
        (self.directory / 'peer-exit.json').write_text(json.dumps(self.process.returncode) + '\n')
        return self.ledger, self.process.returncode

    async def __aexit__(self, *_):
        if self.process is not None and self.process.returncode is None:
            await kill_group(self.process)
            remaining = await self.process.stdout.read()
            (self.directory / 'peer-unfinished.stdout').write_bytes(remaining)
        self.stderr.close()


async def kill_group(process):
    # time/taskset wrappers must not leave a live load generator or UDP peer.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await process.wait()


async def run_shb(peer_binary, shb, directory, *, requests, size, connections=1,
                  parallel=1, workers=2, threads=1, deadline=60, peer_prefix=(), client_prefix=()):
    async with Peer(peer_binary, directory, requests, size, workers=workers,
                    deadline=deadline, prefix=peer_prefix) as peer:
        command = [*client_prefix, str(shb), '--http3', '-t', str(threads), '-c', str(connections),
                   '-p', str(parallel), '-n', str(requests), '--timeout', '10s', '-j',
                   f'https://{peer.address}/response']
        (peer.directory / 'client-command.json').write_text(json.dumps(command) + '\n')
        with (peer.directory / 'client.stdout').open('xb') as stdout, (peer.directory / 'client.stderr').open('xb') as stderr:
            process = await asyncio.create_subprocess_exec(*command, stdout=stdout, stderr=stderr,
                                                           start_new_session=True)
            try:
                await asyncio.wait_for(process.wait(), deadline)
            finally:
                if process.returncode is None:
                    await kill_group(process)
        report = json.loads((peer.directory / 'client.stdout').read_bytes())
        ledger, code = await peer.finish()
        validate_client(report, process.returncode, requests, connections, parallel, threads)
        validate_peer(ledger, code, requests, size, connections)
        return dict(report=report, peer=ledger, command=command)
