"""Fault controls for independently decoded ACK fences and socket reports."""
import copy
import unittest

from native_reordering import covers, validate_exposure, validate_udp, validate_wire


def packet(direction, pn, frames):
    return dict(name='transport:packet_' + direction,
                data=dict(header=dict(packet_type='1RTT', packet_number=pn), frames=frames))


def stream(start, size, fin=False):
    return dict(frame_type='stream', stream_id=0, offset=start, length=size, fin=fin)


def transcript():
    # Body bytes [20, 52); [20, 28) is withheld. Tail/FIN arrives first.
    return dict(traces=[dict(events=[
        packet('received', 10, [stream(44, 8, True)]),
        packet('received', 11, [stream(36, 8)]),
        packet('received', 12, [stream(28, 8)]),
        packet('sent', 7, [dict(frame_type='ack', acked_ranges=[[10, 12]])]),
        packet('received', 13, [stream(20, 8)]),
    ])])


class WireTests(unittest.TestCase):
    def check(self, qlog):
        return validate_wire(qlog, {0}, 20, 32, 8, 'reverse')

    def test_tail_fin_and_every_suffix_packet_precede_prefix(self):
        self.assertEqual(self.check(transcript()), {0: dict(distinct_suffix_frames=3, ack_fenced=True, fin_before_prefix=True)})

    def test_no_ack_or_sparse_ack_hole_cannot_fence(self):
        for ranges in ([], [[10, 10], [12, 12]], [[9, 11]]):
            with self.subTest(ranges=ranges):
                q = transcript()
                q['traces'][0]['events'][3]['data']['frames'][0]['acked_ranges'] = ranges
                with self.assertRaisesRegex(ValueError, 'before independent suffix ACK fence'):
                    self.check(q)

    def test_acked_endpoints_do_not_cover_missing_interior_byte(self):
        q = transcript()
        q['traces'][0]['events'][1]['data']['frames'][0]['length'] = 7
        with self.assertRaisesRegex(ValueError, 'before independent suffix ACK fence'):
            self.check(q)

    def test_ack_after_prefix_is_too_late(self):
        q = transcript()
        q['traces'][0]['events'][3:5] = reversed(q['traces'][0]['events'][3:5])
        with self.assertRaisesRegex(ValueError, 'before independent suffix ACK fence'):
            self.check(q)

    def test_ack_in_another_packet_number_space_does_not_count(self):
        q = transcript()
        q['traces'][0]['events'][3]['data']['header']['packet_type'] = 'handshake'
        with self.assertRaisesRegex(ValueError, 'before independent suffix ACK fence'):
            self.check(q)

    def test_missing_fin_and_missing_prefix_are_distinct_failures(self):
        q = transcript()
        q['traces'][0]['events'][0]['data']['frames'][0]['fin'] = False
        with self.assertRaisesRegex(ValueError, 'missing wire FIN'):
            self.check(q)
        q = transcript()
        q['traces'][0]['events'].pop()
        with self.assertRaisesRegex(ValueError, 'missing prefix release'):
            self.check(q)

    def test_replayed_packet_is_not_another_distinct_fragment(self):
        q = transcript()
        q['traces'][0]['events'].insert(1, copy.deepcopy(q['traces'][0]['events'][0]))
        self.assertEqual(self.check(q)[0]['distinct_suffix_frames'], 3)

    def test_fin_in_the_prefix_frame_is_not_fin_before_gap(self):
        q = transcript()
        q['traces'][0]['events'][0]['data']['frames'][0]['fin'] = False
        q['traces'][0]['events'][-1]['data']['frames'][0]['fin'] = True
        with self.assertRaisesRegex(ValueError, 'FIN-before-gap'):
            self.check(q)

    def test_credit_union_is_order_independent_and_keeps_holes(self):
        self.assertTrue(covers([(4, 7), (2, 4), (6, 8)], 2, 8))
        self.assertFalse(covers([(2, 4), (5, 8)], 2, 8))
        self.assertFalse(covers([(0, 1)], 2, 8))


class NamespaceTests(unittest.TestCase):
    def test_zero_error_counts_require_real_private_namespace(self):
        keys = ('InErrors', 'RcvbufErrors', 'SndbufErrors', 'InCsumErrors', 'InDatagrams', 'OutDatagrams')
        before = dict(namespace='net:[2]', host_namespace='net:[1]', counters=dict.fromkeys(keys, 0))
        after = copy.deepcopy(before)
        after['counters'].update(InDatagrams=10, OutDatagrams=10)
        self.assertEqual(validate_udp(before, after)['InDatagrams'], 10)
        for key in keys[:4]:
            with self.subTest(key=key):
                broken = copy.deepcopy(after)
                broken['counters'][key] = 1
                with self.assertRaises(ValueError):
                    validate_udp(before, broken)
        with self.assertRaisesRegex(ValueError, 'private network namespace'):
            validate_udp(dict(before, host_namespace='net:[2]'), after)


class ExposureTests(unittest.TestCase):
    def test_exact_body_credit_drain_and_queue_depth_are_required(self):
        import json
        row = dict(final_size=525329, read_offset=525329, credited_bytes=525329,
                   ready=0, pending=0, peak_pending=512)
        def report(stream, body=525312):
            return 'NATIVE_BODY ' + json.dumps({'bytes': body}) + '\nNATIVE_EXPOSURE ' + json.dumps(stream)
        validate_exposure(report(row), 1, 525312, 1024, 'reverse')
        for key, value in [('final_size', None), ('read_offset', 17), ('credited_bytes', 2 * 525329),
                           ('ready', 1), ('pending', 1), ('peak_pending', 511)]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    validate_exposure(report(dict(row, **{key: value})), 1, 525312, 1024, 'reverse')
        with self.assertRaises(ValueError):
            validate_exposure(report(row, 525311), 1, 525312, 1024, 'reverse')
        with self.assertRaises(ValueError):
            validate_exposure(report(row) + '\n' + report(row), 1, 525312, 1024, 'reverse')


if __name__ == '__main__':
    unittest.main()
