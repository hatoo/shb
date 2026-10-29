"""Guard the event oracle, controlled schedules and negative-fixture verdicts."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'reassembly_oracle', Path(__file__).with_name('check-quic-receive-reassembly.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def data(value, sid=4):
    return dict(type='data', sid=sid, data=value.hex())


def fin(sid=4):
    return dict(type='fin', sid=sid)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.delivery = oracle.Delivery(4, b'abcdef')

    def rejects(self, message, events, **kwargs):
        with self.assertRaisesRegex(oracle.DeliveryError, message):
            self.delivery.observe(events, **kwargs)

    def test_complete_across_events_and_commands(self):
        self.delivery.observe([data(b'ab')])
        self.delivery.observe([data(b'cd'), data(b'ef'), fin()], fin_sent=True)
        self.delivery.observe([], fin_sent=True)
        self.delivery.complete()

    def test_no_events_while_prefix_is_held(self):
        self.delivery.observe([], blocked=True, fin_sent=True)
        self.rejects('before missing prefix', [data(b'abc')], blocked=True)

    def test_fin_cannot_fill_gap(self):
        self.rejects('before missing prefix', [fin()], blocked=True, fin_sent=True)

    def test_wrong_stream(self):
        self.rejects('unexpected response stream', [data(b'ab', sid=0)])

    def test_unexpected_event(self):
        self.rejects('unexpected response event', [dict(type='reset', sid=4)])

    def test_repeated_connected(self):
        self.rejects('unexpected response stream', [dict(type='connected')])

    def test_corrupt_same_length_bytes(self):
        self.rejects('wrong response bytes', [data(b'abcdeX')])

    def test_out_of_order_bytes(self):
        self.rejects('wrong response bytes', [data(b'def')])

    def test_duplicate_application_bytes(self):
        self.delivery.observe([data(b'abc')])
        self.rejects('wrong response bytes', [data(b'abc')])

    def test_extra_bytes(self):
        self.rejects('extra response bytes', [data(b'abcdefg')])

    def test_empty_data_event(self):
        self.rejects('empty data event', [data(b'')])

    def test_fin_before_peer_sent_it(self):
        self.delivery.observe([data(b'abcdef')])
        self.rejects('FIN before peer sent it', [fin()])

    def test_fin_before_body(self):
        self.rejects('FIN before complete body', [data(b'abc'), fin()], fin_sent=True)

    def test_event_after_fin(self):
        for event in (fin(), data(b'abc')):
            with self.subTest(event=event):
                self.delivery = oracle.Delivery(4, b'abcdef')
                self.delivery.observe([data(b'abcdef'), fin()], fin_sent=True)
                self.rejects('event after FIN', [event], fin_sent=True)

    def test_missing_fin(self):
        self.delivery.observe([data(b'abcdef')])
        with self.assertRaisesRegex(oracle.DeliveryError, 'missing FIN'):
            self.delivery.complete()

    def test_missing_bytes(self):
        self.delivery.observe([data(b'abc')])
        with self.assertRaisesRegex(oracle.DeliveryError, 'incomplete body'):
            self.delivery.complete()


class ScheduleTests(unittest.TestCase):
    def test_bounded_complete_suffix_and_absent_prefix(self):
        for case in oracle.CASES:
            for seed in (17, 91):
                with self.subTest(case=case, seed=seed):
                    body, prefix, spans = oracle.schedule(case, seed)
                    self.assertEqual((body, prefix, spans), oracle.schedule(case, seed))
                    covered = set()
                    for lo, hi in spans:
                        self.assertLessEqual(prefix, lo)
                        self.assertLess(lo, hi)
                        self.assertLessEqual(hi, len(body))
                        self.assertLessEqual(hi - lo, 1024)
                        covered.update(range(lo, hi))
                    self.assertEqual(covered, set(range(prefix, len(body))))
                    self.assertLessEqual(len(spans), 513)

    def test_duplicates_use_identical_offsets(self):
        for copies in (1, 8, 64, 512):
            body, prefix, spans = oracle.schedule('duplicates', 17, copies)
            self.assertEqual(spans, [(prefix, len(body))] * copies)

    def test_bridge_fills_actual_holes(self):
        body, prefix, spans = oracle.schedule('bridge', 17)
        self.assertEqual(prefix, 1)
        self.assertTrue(all(hi == lo + 1 and lo % 2 for lo, hi in spans[:-1]))
        self.assertEqual(spans[-1], (prefix, len(body)))

    def test_random_seeds_change_schedule_not_body(self):
        for case in ('random', 'overlap'):
            first, second = (oracle.schedule(case, seed) for seed in (17, 91))
            self.assertEqual(first[:2], second[:2])
            self.assertNotEqual(first[2], second[2])

    def test_ordered_and_reversed(self):
        for case, reverse in (('ordered', False), ('reverse', True)):
            _, _, spans = oracle.schedule(case, 17)
            self.assertEqual(spans, sorted(spans, reverse=reverse))


class NegativeVerdictTests(unittest.TestCase):
    def row(self, fault):
        return dict(passed=False, adapter_exit=0, handshake_complete=True,
                    request_complete=True, error_type='DeliveryError',
                    error='DeliveryError: ' + oracle.FAULTS[fault], schedule_complete=True)

    def test_intended_faults_detected(self):
        for fault in oracle.FAULTS:
            self.assertTrue(oracle.negative_detected(self.row(fault), fault))

    def test_unrelated_failures_are_not_detection(self):
        for fault in oracle.FAULTS:
            for key, value in (('adapter_exit', 1), ('handshake_complete', False),
                               ('request_complete', False), ('error', 'unrelated'),
                               ('error_type', 'AssertionError'), ('passed', True)):
                with self.subTest(fault=fault, key=key):
                    row = self.row(fault)
                    row[key] = value
                    self.assertFalse(oracle.negative_detected(row, fault))

    def test_missing_data_and_fin_require_completed_input_schedule(self):
        for fault in ('missing-prefix', 'missing-fin'):
            row = self.row(fault)
            del row['schedule_complete']
            self.assertFalse(oracle.negative_detected(row, fault))


if __name__ == '__main__':
    unittest.main()
