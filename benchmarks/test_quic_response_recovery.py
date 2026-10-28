"""Reject incomplete recovery, forged ACK evidence and lost callback failures."""
import asyncio
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from aioquic.buffer import Buffer
from aioquic.quic.packet import push_ack_frame
from aioquic.quic.rangeset import RangeSet

spec = importlib.util.spec_from_file_location(
    'response_recovery', Path(__file__).with_name('check-quic-response-recovery.py'))
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)


def stream(sid=4, offset=0, data=b'original', fin=True):
    return dict(type=15, sid=sid, offset=offset, data=data.hex(), fin=fin)


def ack(*ranges):
    return dict(type=2, ranges=list(ranges), delay=0)


def prepared():
    oracle = fixture.Oracle()
    oracle.observe(0, b'initial', 0, [stream(sid=0)])
    oracle.authorize_ack([[0, 0]])
    oracle.acks_sent.append(dict(ranges=[[0, 0]]))
    for pn in range(1, fixture.FLIGHT + 1):
        oracle.observe(pn, bytes([pn]), 0, [ack([100, 100])])
    return oracle


class FrameTests(unittest.TestCase):
    def test_exact_stream_bytes_offsets_and_fin(self):
        for kind in range(8, 16):
            with self.subTest(kind=kind):
                buf = Buffer(capacity=100)
                buf.push_uint_var(kind)
                buf.push_uint_var(4)
                if kind & 4:
                    buf.push_uint_var(7)
                if kind & 2:
                    buf.push_uint_var(3)
                buf.push_bytes(b'\x00\xffx')
                frames = fixture.decode_frames(buf.data)
                self.assertEqual(frames, [dict(type=kind, sid=4,
                    offset=7 if kind & 4 else 0, fin=bool(kind & 1), data='00ff78')])

    def test_sparse_ack_and_ecn_preserve_inclusive_boundaries(self):
        for kind in (2, 3):
            buf = Buffer(capacity=100)
            buf.push_uint_var(kind)
            push_ack_frame(buf, RangeSet([range(1, 4), range(7, 8), range(10, 13)]), 9)
            if kind == 3:
                for n in (2, 3, 4):
                    buf.push_uint_var(n)
            buf.push_uint8(1)
            result = fixture.decode_frames(buf.data)
            self.assertEqual(result[0]['ranges'], [[1, 3], [7, 7], [10, 12]])
            self.assertEqual(result[0]['delay'], 9)
            self.assertEqual(result[1], dict(type=1))
            if kind == 3:
                self.assertEqual(result[0]['ecn'], [2, 3, 4])

    def test_truncated_unknown_and_empty_payloads_fail(self):
        for payload in (b'', b'\x0f\x04', b'\x0b\x04\x05x', b'\x3f'):
            with self.subTest(payload=payload), self.assertRaises(Exception):
                fixture.decode_frames(payload)

    def test_padding_does_not_hide_an_eliciting_frame(self):
        self.assertEqual(fixture.decode_frames(b'\x00\x00\x01\x00'),
                         [dict(type=0), dict(type=1), dict(type=0)])


class StreamTests(unittest.TestCase):
    def test_reordered_fragments_identical_overlap_and_fin(self):
        model = fixture.StreamBytes()
        model.add(stream(offset=4, data=b'inal'))
        self.assertFalse(model.complete())
        model.add(stream(data=b'orig', fin=False))
        model.add(stream(offset=2, data=b'iginal'))
        self.assertTrue(model.complete())
        self.assertEqual(model.report()['data'], b'original'.hex())

    def test_missing_fin_and_missing_byte_are_incomplete(self):
        for frames in ([stream(fin=False)], [stream(offset=1)]):
            model = fixture.StreamBytes()
            for frame in frames:
                model.add(frame)
            self.assertFalse(model.complete())

    def test_conflicting_retransmission_fails(self):
        model = fixture.StreamBytes()
        model.add(stream())
        with self.assertRaisesRegex(AssertionError, 'changed STREAM byte'):
            model.add(stream(data=b'originaX'))

    def test_changed_final_size_data_after_fin_and_fin_before_data_fail(self):
        for original, changed, error in (
            (stream(), stream(data=b'origina'), 'changed FIN'),
            (stream(), stream(offset=8, data=b'x', fin=False), 'beyond FIN'),
            (stream(fin=False), stream(data=b'origina'), 'FIN before'),
        ):
            with self.subTest(error=error):
                model = fixture.StreamBytes()
                model.add(original)
                with self.assertRaisesRegex(AssertionError, error):
                    model.add(changed)

    def test_zero_length_fin_and_request_memory_bound(self):
        model = fixture.StreamBytes()
        model.add(stream(data=b''))
        self.assertTrue(model.complete())
        for offset in (-1, 65537):
            with self.assertRaisesRegex(AssertionError, 'unbounded'):
                fixture.StreamBytes().add(stream(offset=offset))


class OracleTests(unittest.TestCase):
    def test_drop_cannot_count_as_recovery_or_be_acknowledged(self):
        oracle = prepared()
        self.assertFalse(oracle.observe(40, b'lost', 0, [stream()]))
        self.assertFalse(oracle.recovered(4))
        with self.assertRaisesRegex(AssertionError, 'missing retransmitted'):
            oracle.verify_recovery(4)
        with self.assertRaisesRegex(AssertionError, 'undelivered'):
            oracle.authorize_ack([[40, 40]])

    def test_repeated_dropped_datagram_is_still_dropped(self):
        oracle = prepared()
        for _ in range(2):
            self.assertFalse(oracle.observe(40, b'lost', 0, [stream()]))
        self.assertFalse(oracle.recovered(4))
        self.assertEqual(len(oracle.dropped), 1)

    def test_exact_fresh_packet_recovery_and_duplicate_delivery(self):
        oracle = prepared()
        oracle.observe(40, b'lost', 0, [stream()])
        for _ in range(2):
            self.assertTrue(oracle.observe(41, b'retransmit', 0, [stream()]))
        self.assertEqual(oracle.verify_recovery(4), [41])
        oracle.authorize_ack([[41, 41]])
        with self.assertRaisesRegex(AssertionError, 'changed client packet'):
            oracle.observe(41, b'different ciphertext', 0, [stream()])

    def test_recovery_allows_different_packetization(self):
        oracle = prepared()
        oracle.observe(40, b'lost', 0, [stream()])
        oracle.observe(41, b'first', 0, [stream(data=b'orig', fin=False)])
        oracle.observe(42, b'last', 0, [stream(offset=4, data=b'inal')])
        self.assertEqual(oracle.verify_recovery(4), [41, 42])

    def test_wrong_recovered_bytes_fail_even_when_request_length_matches(self):
        oracle = prepared()
        oracle.observe(40, b'lost', 0, [stream()])
        oracle.observe(41, b'changed', 0, [stream(data=b'originaX')])
        with self.assertRaisesRegex(AssertionError, 'differs from dropped'):
            oracle.verify_recovery(4)

    def test_missing_recovery_fin_is_not_success(self):
        oracle = prepared()
        oracle.observe(40, b'lost', 0, [stream()])
        oracle.observe(41, b'no-fin', 0, [stream(fin=False)])
        with self.assertRaisesRegex(AssertionError, 'missing retransmitted'):
            oracle.verify_recovery(4)

    def test_flight_must_be_ack_only_and_unacknowledged(self):
        for mode in ('eliciting', 'acked'):
            with self.subTest(mode=mode):
                oracle = prepared()
                if mode == 'eliciting':
                    oracle.ack_only.clear()
                    for pn in range(100, 100 + fixture.FLIGHT):
                        oracle.observe(pn, str(pn).encode(), 0, [ack([10, 10]), dict(type=1)])
                else:
                    oracle.acks_sent.append(dict(ranges=[[0, fixture.FLIGHT - 1]]))
                with self.assertRaisesRegex(AssertionError, 'missing unacknowledged'):
                    oracle.observe(200, b'lost', 0, [stream()])

    def test_partial_target_packet_is_not_the_requested_experiment(self):
        oracle = prepared()
        with self.assertRaisesRegex(AssertionError, 'whole request and FIN'):
            oracle.observe(40, b'partial', 0, [stream(fin=False)])

    def test_unknown_packet_or_range_hole_cannot_be_acknowledged(self):
        oracle = prepared()
        oracle.observe(40, b'lost', 0, [stream()])
        oracle.observe(41, b'retransmit', 0, [stream()])
        for ranges in ([[40, 41]], [[42, 42]], [[3, 2]], []):
            with self.subTest(ranges=ranges), self.assertRaises(AssertionError):
                oracle.authorize_ack(ranges)

    def test_ack_and_path_response_barriers_require_delivered_packets(self):
        oracle = prepared()
        token = b'barrier!'
        frames = [stream(), ack([500, 500]), dict(type=0x1b, token=token.hex())]
        oracle.observe(40, b'lost', 0, frames)
        self.assertIsNone(oracle.ack_for(500))
        self.assertIsNone(oracle.response_for(token))
        oracle.observe(41, b'got', 0, frames)
        self.assertEqual(oracle.ack_for(500), 41)
        self.assertEqual(oracle.response_for(token), 41)


class FailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_callback_error_beats_successful_predicate(self):
        failures = fixture.Failures()
        failures.record(ValueError('bad frame'))
        with self.assertRaisesRegex(AssertionError, 'bad frame'):
            await fixture.until(lambda: True, failures, 'already ready')

    async def test_queued_callback_error_and_deadline_propagate(self):
        failures = fixture.Failures()
        asyncio.get_running_loop().call_soon(failures.record, RuntimeError('late callback'))
        with self.assertRaisesRegex(AssertionError, 'late callback'):
            await fixture.until(lambda: False, failures, 'never')
        with self.assertRaisesRegex(AssertionError, 'timed out waiting for missing FIN'):
            await fixture.until(lambda: False, fixture.Failures(), 'missing FIN', timeout=.005)

    async def test_timer_and_pending_transmit_are_cancelled(self):
        called = []
        loop = asyncio.get_running_loop()
        peer = SimpleNamespace(_timer=loop.call_later(0, called.append, 'timer'),
                               _transmit_task=loop.call_soon(called.append, 'transmit'))
        handles = [peer._timer, peer._transmit_task]
        fixture.cancel_callbacks(peer)
        fixture.cancel_callbacks(peer)
        await asyncio.sleep(0)
        self.assertEqual(called, [])
        self.assertTrue(all(handle.cancelled() for handle in handles))

    def server(self, close):
        return SimpleNamespace(_transport=SimpleNamespace(
            get_extra_info=lambda _key: ('127.0.0.1', 12345)), close=close)

    async def test_launch_failure_preserves_artifact_closes_server_restores_handler(self):
        closed = []
        handler = asyncio.get_running_loop().get_exception_handler()
        with patch.object(fixture, 'serve', AsyncMock(return_value=self.server(lambda: closed.append(True)))), \
             patch.object(fixture.asyncio, 'create_subprocess_exec', AsyncMock(side_effect=OSError('missing binary'))):
            result = await fixture.check(Path('/missing/shb'), None, 'ordinary')
        self.assertFalse(result['passed'])
        self.assertIn('missing binary', result['error'])
        self.assertIn('oracle', result)
        self.assertEqual(closed, [True])
        self.assertIs(asyncio.get_running_loop().get_exception_handler(), handler)

    async def test_timeout_kills_process_drains_pipes_and_closes_server(self):
        stopped, closed = asyncio.Event(), []
        proc = SimpleNamespace(returncode=None)

        def kill():
            proc.returncode = -9
            stopped.set()

        async def communicate():
            await stopped.wait()
            return b'partial output', b'partial error'

        proc.kill, proc.communicate, proc.wait = kill, communicate, AsyncMock(return_value=-9)
        timeout = asyncio.timeout
        with patch.object(fixture, 'serve', AsyncMock(return_value=self.server(lambda: closed.append(True)))), \
             patch.object(fixture.asyncio, 'create_subprocess_exec', AsyncMock(return_value=proc)), \
             patch.object(fixture.asyncio, 'timeout', lambda _seconds: timeout(.01)):
            result = await fixture.check(Path('/fake/shb'), None, 'ordinary')
        self.assertFalse(result['passed'])
        self.assertEqual(proc.returncode, -9)
        self.assertEqual(result['stdout'], 'partial output')
        self.assertEqual(result['stderr'], 'partial error')
        self.assertEqual(closed, [True])
        proc.wait.assert_awaited_once()

    async def test_cleanup_callback_failure_is_in_final_verdict(self):
        def close():
            asyncio.get_running_loop().call_exception_handler({'message': 'cleanup failure'})

        with patch.object(fixture, 'serve', AsyncMock(return_value=self.server(close))), \
             patch.object(fixture.asyncio, 'create_subprocess_exec', AsyncMock(side_effect=OSError('launch failure'))):
            result = await fixture.check(Path('/missing/shb'), None, 'ordinary')
        self.assertFalse(result['passed'])
        self.assertTrue(any('cleanup failure' in error for error in result['failures']))


if __name__ == '__main__':
    unittest.main()
