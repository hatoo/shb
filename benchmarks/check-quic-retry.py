#!/usr/bin/env python3
"""Fixed encrypted Retry schedules; correctness evidence, never a timing benchmark."""

import argparse
import asyncio
import datetime
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import aioquic
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.packet import QuicPacketType, encode_quic_retry, pull_ack_frame, pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from quic_retry import CASES, PARALLEL, REQUESTS, negative_controls, require, validate_result


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, ledger, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.ledger = ledger

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.ledger['handshakes'] += 1
        for http in self.h3.handle_event(event):
            if isinstance(http, HeadersReceived):
                require(http.stream_ended and http.stream_id not in self.ledger['streams'],
                        'request-fin', http)
                headers = dict(http.headers)
                require(headers.get(b':method') == b'GET' and headers.get(b':path') == b'/',
                        'request-fields', http.headers)
                self.ledger['streams'].append(http.stream_id)
                self.h3.send_headers(http.stream_id, [(b':status', b'200'), (b'content-length', b'2')])
                self.h3.send_data(http.stream_id, b'OK', end_stream=True)
                self.ledger['responses'].append(http.stream_id)
        self.transmit()


class Wire:
    def __init__(self, transport, server):
        self.transport, self.server = transport, server

    def __getattr__(self, name):
        return getattr(self.transport, name)

    def sendto(self, data, addr):
        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
        if header.packet_type == QuicPacketType.RETRY:
            self.server.token = header.token
            self.server.retry_cid = header.source_cid
            if self.server.case == 'forged-second':
                # A different token distinguishes accepting the forgery even if
                # the legitimate Retry arrives before the client's reply.
                forged = encode_quic_retry(
                    version=header.version, source_cid=header.source_cid,
                    destination_cid=header.destination_cid,
                    original_destination_cid=self.server.original_cid,
                    retry_token=bytes(byte ^ 0xff for byte in header.token))
                forged = forged[:-1] + bytes([forged[-1] ^ 1])
                self.server.send_retry(forged, addr, 'forged', False)
                self.server.callbacks.append(asyncio.get_running_loop().call_later(
                    .02, self.server.send_retry, data, addr, 'authentic', True))
                return
            self.server.send_retry(data, addr, 'authentic', True)
            return
        self.transport.sendto(data, addr)


class Server(QuicServer):
    def __init__(self, config, case, ledger, peers):
        def factory(*args, **kwargs):
            peer = Peer(*args, ledger=ledger, **kwargs)
            peers.append(peer)
            ledger['peers'] += 1
            return peer

        super().__init__(configuration=config, create_protocol=factory, retry=case != 'no-retry')
        self.case, self.ledger = case, ledger
        self.token = self.retry_cid = self.original_cid = self.held = None
        self.callbacks = []
        self.sequence = 0

    def tick(self):
        self.sequence += 1
        return self.sequence

    def connection_made(self, transport):
        super().connection_made(Wire(transport, self))

    def send_retry(self, data, addr, kind, valid):
        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
        self.ledger['retries'].append(dict(
            kind=kind, seq=self.tick(), scid=header.source_cid.hex(),
            token_length=len(header.token), token_sha256=sha(header.token), integrity_valid=valid))
        self._transport.transport.sendto(data, addr)

    def deliver_initial(self, data, addr, index):
        self.ledger['deliveries'].append(dict(initial=index, seq=self.tick()))
        super().datagram_received(data, addr)

    def datagram_received(self, data, addr):
        buf = Buffer(data=data)
        header = pull_quic_header(buf, host_cid_length=8)
        if header.packet_type != QuicPacketType.INITIAL:
            super().datagram_received(data, addr)
            return
        if self.original_cid is None:
            self.original_cid = header.destination_cid
        keys = CryptoPair()
        keys.setup_initial(self.retry_cid if header.token else self.original_cid,
                           is_client=False, version=header.version)
        _, plain, pn = keys.decrypt_packet(data[:header.packet_length], buf.tell(), 0)
        payload, crypto = Buffer(data=plain), []
        while not payload.eof():
            kind = payload.pull_uint_var()
            if kind in (0, 1):  # PADDING / PING
                continue
            if kind == 2:
                pull_ack_frame(payload)
                continue
            require(kind == 6, 'initial-frame', kind)
            offset = payload.pull_uint_var()
            chunk = payload.pull_bytes(payload.pull_uint_var())
            crypto.append(dict(offset=offset, length=len(chunk), sha256=sha(chunk)))
        index = len(self.ledger['initials'])
        row = dict(seq=self.tick(), pn=pn, token_length=len(header.token),
                   token_sha256=sha(header.token), dcid=header.destination_cid.hex(),
                   wire_bytes=len(data), crypto=crypto, action='deliver')
        self.ledger['initials'].append(row)
        if header.token:
            require(header.token == self.token, 'wire-token', 'Initial changed the authentic token')
            if index == 1 and self.case in ('drop', 'reorder'):
                row['action'] = self.case
                if self.case == 'reorder':
                    self.held = (data, addr, index)
                return
            if index == 1 and self.case == 'forged-second':
                second = encode_quic_retry(
                    version=header.version, source_cid=b'secondid', destination_cid=header.source_cid,
                    original_destination_cid=self.original_cid,
                    retry_token=b'do not replace the accepted token')
                self.send_retry(second, addr, 'second', True)
        self.deliver_initial(data, addr, index)
        if self.held is not None:
            held, self.held = self.held, None
            self.deliver_initial(*held)


async def run(binary, config, case):
    ledger = dict(handshakes=0, peers=0, streams=[], responses=[], retries=[], initials=[], deliveries=[])
    peers, failures = [], []
    loop = asyncio.get_running_loop()
    old_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _, ctx: failures.append(str(ctx.get('exception', ctx))))
    proc = transport = server = None
    row = dict(case=case, binary_sha256=sha(binary.read_bytes()), ledger=ledger,
               client_exit=None, report=None, failures=failures, cleanup={})
    try:
        transport, server = await loop.create_datagram_endpoint(
            lambda: Server(config, case, ledger, peers), local_addr=('127.0.0.1', 0))
        port = transport.get_extra_info('sockname')[1]
        command = [str(binary), '--http3', '-t', '1', '-c', '1', '-p', str(PARALLEL),
                   '-n', str(REQUESTS), '--timeout', '5s', '--connect-timeout', '5s',
                   '-j', f'https://127.0.0.1:{port}/']
        row['command'] = command
        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        # Shield communicate so a timeout can still drain and retain both pipes.
        reader = asyncio.create_task(proc.communicate())
        try:
            stdout, stderr = await asyncio.wait_for(asyncio.shield(reader), 20)
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = await asyncio.wait_for(reader, 5)
            failures.append('client deadline exceeded')
        row.update(client_exit=proc.returncode, stdout=stdout.decode(errors='replace'),
                   stderr=stderr.decode(errors='replace'))
        row['report'] = json.loads(stdout)
    except Exception as exc:
        failures.append(f'{type(exc).__name__}: {exc}')
    finally:
        try:
            if proc is not None and proc.returncode is None:
                proc.kill()
                await asyncio.wait_for(proc.wait(), 5)
            if server is not None:
                for handle in server.callbacks:
                    handle.cancel()
                server.close()
            if peers:
                await asyncio.wait_for(asyncio.gather(*(p.wait_closed() for p in peers)), 5)
        except Exception as exc:
            failures.append(f'cleanup {type(exc).__name__}: {exc}')
        finally:
            # aioquic 1.3.0 owns these timer handles, not background Tasks.
            # Cancel them even when a failed handshake cannot close gracefully.
            for peer in peers:
                for attr in ('_timer', '_transmit_task'):
                    handle = getattr(peer, attr)
                    if handle is not None:
                        handle.cancel()
            if transport is not None:
                transport.close()
            await asyncio.sleep(0)
            row['cleanup'] = dict(
                client_reaped=proc is not None and proc.returncode is not None,
                transport_closed=transport is not None and transport.is_closing(),
                peers_closed=all(p._closed.is_set() for p in peers),
                callbacks_cancelled=server is not None and all(h.cancelled() for h in server.callbacks))
            loop.set_exception_handler(old_handler)
    try:
        validate_result(row)
        row['controls'] = negative_controls(row)
        row['passed'] = True
    except Exception as exc:
        row.update(passed=False, validation_error=str(exc))
    return row


def configuration(path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (path / 'cert').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (path / 'key').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    config = QuicConfiguration(is_client=False, alpn_protocols=['h3'])
    config.load_cert_chain(path / 'cert', path / 'key')
    return config


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shb', required=True, type=Path)
    parser.add_argument('--output', type=Path, help='new JSON evidence file (default: stdout)')
    parser.add_argument('--case', choices=CASES, action='append', help='run only selected schedules')
    args = parser.parse_args()
    require(aioquic.__version__ == '1.3.0', 'peer-version', aioquic.__version__)
    binary = args.shb.resolve(strict=True)
    # Reserve before launching sockets/processes; never overwrite earlier evidence.
    output = args.output.open('x') if args.output else None
    result = dict(aioquic=aioquic.__version__, rows=[], passed=False)
    try:
        with tempfile.TemporaryDirectory(prefix='shb-retry-') as directory:
            config = configuration(Path(directory))
            for case in args.case or CASES:
                row = await run(binary, config, case)
                result['rows'].append(row)
                print(f'{case}: {"PASS" if row["passed"] else row["validation_error"]}', file=sys.stderr)
                if not row['passed']:
                    break
        result['passed'] = all(row['passed'] for row in result['rows'])
    finally:
        json.dump(result, output or sys.stdout, indent=2)
        print(file=output or sys.stdout)
        if output:
            output.close()
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
