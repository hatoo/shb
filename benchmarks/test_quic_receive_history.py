"""The wire oracle must reject missing, duplicated and unauthorized work."""
import asyncio
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location(
    'receive_history', Path(__file__).with_name('check-quic-receive-history.py'))
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)


def response(token=b'original'):
    return dict(frame_type='path_response', data=token.hex())


def ack(*ranges):
    return dict(frame_type='ack', acked_ranges=list(ranges))


class OracleTests(unittest.TestCase):
    def test_duplicate_dispatch_in_fresh_client_packet_fails(self):
        oracle = fixture.Oracle()
        oracle.expect(b'original')
        oracle.observe(10, [response()])
        with self.assertRaisesRegex(AssertionError, 'duplicate dispatch'):
            oracle.observe(11, [response()])

    def test_duplicate_client_datagram_is_not_duplicate_dispatch(self):
        oracle = fixture.Oracle()
        oracle.expect(b'original')
        oracle.observe(10, [response()])
        oracle.observe(10, [response()])
        oracle.complete()
        self.assertEqual(len(oracle.response_packets), 1)
        with self.assertRaisesRegex(AssertionError, 'changed client packet'):
            oracle.observe(10, [response(b'changed!')])

    def test_same_frame_retransmitted_in_new_server_packet_is_eligible(self):
        oracle = fixture.Oracle()
        for pn in (10, 11):
            oracle.expect(b'original')
            oracle.observe(pn, [response()])
            oracle.complete()
        self.assertEqual(oracle.responses[b'original'.hex()], 2)

    def test_unexpected_token_and_unsolicited_response_fail(self):
        for token in (b'original', b'unknown!'):
            oracle = fixture.Oracle()
            with self.assertRaisesRegex(AssertionError, 'unexpected PATH_RESPONSE'):
                oracle.observe(10, [response(token)])

    def test_missing_response_fails_even_with_valid_ack(self):
        oracle = fixture.Oracle()
        oracle.expect(b'original')
        oracle.observe(10, [ack([1, 1])])
        with self.assertRaisesRegex(AssertionError, 'missing PATH_RESPONSE'):
            oracle.complete()

    def test_ack_boundaries_and_holes_are_exact(self):
        ranges = [[1, 3], [7, 7], [10, 12]]
        self.assertEqual([n for n in range(14) if fixture.contains(ranges, n)],
                         [1, 2, 3, 7, 10, 11, 12])

    def test_pruning_requires_an_ack_of_the_fence_and_absent_old_number(self):
        oracle = fixture.Oracle()
        oracle.observe(10, [ack([2, 2])])
        with self.assertRaisesRegex(AssertionError, 'missing fence ACK'):
            oracle.pruned(4, 2)
        oracle.observe(11, [ack([2, 4])])
        with self.assertRaisesRegex(AssertionError, 'not pruned'):
            oracle.pruned(4, 2)
        oracle.observe(12, [ack([4, 4])])
        self.assertEqual(oracle.pruned(4, 2)['client_pn'], 12)


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.oracle = fixture.Oracle()
        self.schedule = fixture.Schedule(self.sent.append, self.oracle)

    def packet(self, pn=1, state='ready', token=b'original'):
        return self.schedule.reserve(fixture.Packet(
            pn, f'packet-{pn}', 0, b'protected-' + bytes([pn]), token), state)

    def test_replay_preserves_exact_bytes_without_authorizing_response(self):
        packet = self.packet()
        self.schedule.deliver(packet)
        self.oracle.observe(10, [response()])
        self.schedule.deliver(packet, replay=True)
        self.assertEqual(self.sent, [packet.wire, packet.wire])
        self.assertEqual(self.oracle.expected[b'original'.hex()], 1)
        with self.assertRaisesRegex(AssertionError, 'duplicate dispatch'):
            self.oracle.observe(11, [response()])

    def test_delay_reorders_packet_without_changing_its_identity(self):
        late = self.packet(1, 'held', b'late-one')
        fresh = self.packet(2)
        self.schedule.deliver(fresh)
        self.assertNotIn(b'late-one'.hex(), self.oracle.expected)
        self.schedule.deliver(late)
        self.assertEqual(self.sent, [fresh.wire, late.wire])
        self.assertEqual(self.oracle.expected[b'late-one'.hex()], 1)

    def test_drop_is_permanent_and_new_packet_can_retransmit_frame(self):
        lost = self.packet(1, 'dropped')
        for replay in (False, True):
            with self.assertRaises(AssertionError):
                self.schedule.deliver(lost, replay=replay)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.oracle.expected, {})
        self.schedule.deliver(self.packet(2))
        self.oracle.observe(10, [response()])
        self.oracle.complete()

    def test_replay_before_first_delivery_and_second_first_delivery_fail(self):
        for state in ('ready', 'held'):
            with self.subTest(state=state):
                self.setUp()
                packet = self.packet(state=state)
                with self.assertRaisesRegex(AssertionError, 'replay before delivery'):
                    self.schedule.deliver(packet, replay=True)
                self.schedule.deliver(packet)
                with self.assertRaisesRegex(AssertionError, 'invalid first delivery'):
                    self.schedule.deliver(packet)

    def test_reusing_packet_number_or_substituting_wire_fails(self):
        self.packet()
        with self.assertRaisesRegex(AssertionError, 'reused server packet number'):
            self.packet()
        with self.assertRaises(AssertionError):
            self.schedule.deliver(fixture.Packet(1, 'packet-1', 0, b'forged', b'original'))

    def test_schedule_is_bounded(self):
        for pn in range(256):
            self.packet(pn, 'dropped', None)
        with self.assertRaisesRegex(AssertionError, 'unbounded fixture'):
            self.schedule.reserve(fixture.Packet(256, 'overflow', 0, b'packet'))


class CallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_protocol_callbacks_are_cancelled_before_next_case(self):
        called = []
        loop = asyncio.get_running_loop()
        timer = loop.call_later(0, called.append, 'timer')
        transmit = loop.call_soon(called.append, 'transmit')
        peer = SimpleNamespace(_timer=timer, _transmit_task=transmit)
        fixture.cancel_callbacks(peer)
        fixture.cancel_callbacks(peer)
        await asyncio.sleep(.001)
        self.assertEqual(called, [])
        self.assertTrue(timer.cancelled())
        self.assertTrue(transmit.cancelled())
        self.assertIsNone(peer._timer)
        self.assertIsNone(peer._transmit_task)

    async def test_failure_cannot_be_hidden_by_a_successful_predicate(self):
        failures = fixture.Failures()
        failures.record(RuntimeError('callback failed'))
        with self.assertRaisesRegex(AssertionError, 'callback failed'):
            await fixture.until(lambda: True, failures, 'already ready')

    async def test_queued_callback_failure_propagates_during_wait(self):
        failures = fixture.Failures()
        asyncio.get_running_loop().call_soon(failures.record, ValueError('bad frame'))
        with self.assertRaisesRegex(AssertionError, 'bad frame'):
            await fixture.until(lambda: False, failures, 'never ready')


if __name__ == '__main__':
    unittest.main()
