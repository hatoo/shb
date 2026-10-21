#!/usr/bin/env python3
"""Independent QPACK request oracle: pylsqpack 0.3.24 / aioquic 1.3.0.

Checks every static name against the decoder's own table, plain values, ordered
duplicates, zero dynamic capacity, and exact live headers/body/FIN accounting.
The live cases are correctness checks, not throughput measurements.
"""
import argparse
import asyncio
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import aioquic
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pylsqpack


def static_names():
    # Ask the independent decoder for all 99 RFC 9204 Appendix A entries.
    # Do not duplicate the implementation's name/index mapping in this oracle.
    names = []
    for index in range(99):
        field = bytes([0xc0 | index]) if index < 63 else bytes([0xff, index - 63])
        control, headers = pylsqpack.Decoder(0, 0).feed_header(0, b'\0\0' + field)
        assert control == b'' and len(headers) == 1
        name = headers[0][0].decode()
        if name not in names:
            names.append(name)
    return names


def run_probe(probe):
    names = static_names()
    requests = []
    for name in names + ['x-custom', 'accept-extra']:
        for value in ['', 'v', 'identity', 'héllo日本語', 'a' * 126, 'a' * 127,
                      'a' * 128, 'a' * 40000]:
            requests.append(dict(method='POST', scheme='https', authority='example.com:443',
                                 path='/api/items?q=1234', body_len=1234,
                                 headers=[(name, value), ('x-repeat', '1'), (name, 'other')]))
    requests += [dict(method=m, scheme=s, authority='h', path=p, body_len=0, headers=hs)
                 for m, s, p, hs in [
                     ('GET', 'https', '/', []), ('CUSTOM', 'custom', '/~', [('x', '~|^{}')]),
                     ('GET', 'https', '/' + 'abc0123' * 5000, []),
                     ('GET', 'https', '/', [(n, 'v') for n in names]),
                     ('GET', 'https', '/', [('accept', 'application/json'), ('cookie', 'a=b')])]]
    result = subprocess.run([str(probe)], input=''.join(json.dumps(r) + '\n' for r in requests),
                            text=True, capture_output=True, timeout=60, check=True)
    outputs = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(outputs) == len(requests)
    sizes = []
    for request, output in zip(requests, outputs):
        encoded = bytes(output['encoded'])
        assert encoded[:2] == b'\0\0', request
        want = [(b':method', request['method'].encode()), (b':scheme', request['scheme'].encode()),
                (b':authority', request['authority'].encode()), (b':path', request['path'].encode())]
        want += [(k.encode(), v.encode()) for k, v in request['headers']]
        if request['body_len']:
            want.append((b'content-length', str(request['body_len']).encode()))
        decoder = pylsqpack.Decoder(0, 0)
        for stream in [0, 8, 4]:  # Reuse and reorder with no encoder stream instructions.
            control, actual = decoder.feed_header(stream, encoded)
            assert control == b'' and actual == want, (request, actual)
        sizes.append(dict(names=[n for n, _ in request['headers']],
                          value_lengths=[len(v.encode()) for _, v in request['headers']],
                          encoded_bytes=len(encoded)))
    return dict(static_names=len(names), request_cases=len(requests), sizes=sizes)


class ZeroTableH3(H3Connection):
    def _get_local_settings(self):
        settings = super()._get_local_settings()
        settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0
        settings[Setting.QPACK_BLOCKED_STREAMS] = 0
        return settings


async def live_case(shb, certificate, key, name, headers, body='', path='/', method='GET'):
    count = 32
    state = dict(requests=0, completed=0, body_bytes=0, response_body_bytes=0,
                 received_datagrams=0, received_bytes=0)
    failures = []
    peers = []
    config = QuicConfiguration(is_client=False, alpn_protocols=['h3'],
                               max_data=32768, max_stream_data=8192)
    config.load_cert_chain(certificate, key)
    port = None

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.h3 = ZeroTableH3(self._quic)
            self.h3._decoder = pylsqpack.Decoder(0, 0)
            self.bodies = {}
            self.streams = set()
            peers.append(self)

        def quic_event_received(self, event):
            try:
                for item in self.h3.handle_event(event):
                    if isinstance(item, HeadersReceived):
                        assert item.stream_id not in self.streams, 'duplicate request or trailers'
                        self.streams.add(item.stream_id)
                        want = [(b':method', method.encode()), (b':scheme', b'https'),
                                (b':authority', f'127.0.0.1:{port}'.encode()), (b':path', path.encode())]
                        want += [(k.lower().encode(), v.encode()) for k, v in headers]
                        if body:
                            if not any(k.lower() == 'content-type' for k, _ in headers):
                                want.append((b'content-type', b'application/x-www-form-urlencoded'))
                            want.append((b'content-length', str(len(body.encode())).encode()))
                        elif method == 'POST':
                            want.append((b'content-length', b'0'))
                        assert item.headers == want, (name, item.headers, want)
                        self.bodies[item.stream_id] = bytearray()
                        state['requests'] += 1
                    elif isinstance(item, DataReceived):
                        self.bodies[item.stream_id].extend(item.data)
                    else:
                        continue
                    if item.stream_ended:
                        actual = bytes(self.bodies.pop(item.stream_id))
                        assert actual == body.encode(), name
                        state['body_bytes'] += len(actual)
                        state['completed'] += 1
                        self.h3.send_headers(item.stream_id, [(b':status', b'200'), (b'content-length', b'11')])
                        self.h3.send_data(item.stream_id, b'hello world', end_stream=True)
                        state['response_body_bytes'] += 11
                self.transmit()
            except Exception as exc:
                failures.append(repr(exc))

    server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Peer)
    port = server._transport.get_extra_info('sockname')[1]
    receive = server.datagram_received

    def record(data, address):
        state['received_datagrams'] += 1
        state['received_bytes'] += len(data)
        receive(data, address)

    server.datagram_received = record
    command = [str(shb), '--http3', '-j', '-t', '1', '-c', '1', '-p', '8',
               '-n', str(count), '--timeout', '5s', '-m', method]
    for k, v in headers:
        command += ['-H', k + ': ' + v]
    if body:
        command += ['-d', body]
    command += [f'https://127.0.0.1:{port}{path}']
    process = None
    try:
        process = await asyncio.create_subprocess_exec(*command, stdout=-1, stderr=-1)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
        await asyncio.sleep(.03)
        assert process.returncode == 0, (name, stderr.decode())
        assert not failures, (name, failures)
        report = json.loads(stdout)
        assert report['requests'] == dict(total=count, ok=count, errors=0, connectErrors=0), report
        assert report['statusCodes'] == {'200': count} and report['latencySeconds'], report
        assert state['requests'] == state['completed'] == count, state
        assert state['body_bytes'] == count * len(body.encode()), state
        assert state['response_body_bytes'] == count * 11
        assert len(peers) == 1 and not peers[0].bodies
        assert peers[0].streams == set(range(0, count * 4, 4))
        assert peers[0].h3._decoder_bytes_sent == 0
        assert peers[0].h3._encoder_bytes_received == 0
        return dict(name=name, ledger=state, report=report, stderr=stderr.decode())
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        server.close()


async def main(args):
    result = dict(probe=run_probe(args.probe.resolve()),
                  versions=dict(pylsqpack=pylsqpack.__version__, aioquic=aioquic.__version__))
    legal = [n for n in static_names() if not n.startswith(':') and n != 'content-length']
    cases = [
        ('ordinary', []), ('all-legal-names', [(n, 'value') for n in legal]),
        ('nonempty-static-value', [('Accept-Encoding', 'identity'), ('age', '123')]),
        ('duplicates', [('accept', 'one'), ('x-custom', 'v'), ('accept', 'two'),
                        ('cookie', 'a=b'), ('cookie', 'c=d')]),
        ('empty', [('accept', ''), ('x-custom', '')]),
        ('utf8', [('user-agent', 'héllo日本語'), ('x-custom', 'héllo日本語')]),
        ('fragmented-known', [('user-agent', 'a' * 40000)]),
        ('fragmented-unknown', [('x-custom', 'a' * 40000)]),
        ('fragmented-path', [('accept', 'v')], '', '/' + 'abc0123' * 5000),
        ('post-body', [('content-type', 'application/json'), ('user-agent', 'test')],
         'abc0123' * 10000, '/upload', 'POST'),
        ('post-empty', [('accept', 'v')], '', '/', 'POST'),
        ('post-auto-content-type', [('accept', 'v')], 'body', '/', 'POST'),
    ]
    cases += [(f'prefix-{n}', [('user-agent', 'a' * n)]) for n in (126, 127, 128, 255, 256)]
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
                                                 serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
        result['live'] = [await live_case(args.shb.resolve(), path/'cert', path/'key', *case)
                          for case in cases]
    result['sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.probe, args.shb)}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--shb', type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
