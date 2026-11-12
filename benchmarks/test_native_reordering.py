"""Fault controls for independently decoded ACK fences and socket reports."""
import copy
import unittest

from native_reordering import covers, suite_cases, suite_coverage, validate_exposure, validate_udp, validate_wire


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


class SmallMatrixTests(unittest.TestCase):
    def results(self):
        results = []
        for case in suite_cases('small'):
            summary = dict(case, passed=True)
            count, size = case['requests'], case['body_bytes']
            if case['fault'] != 'none':
                summary['rejected'] = dict(reason='wrong response bytes at offset 0' if case['fault'] == 'corrupt' else 'deadline',
                                           body_bytes=size if case['fault'] == 'missing-fin' else 0, ended=False)
            else:
                summary['schedule'] = dict(fences=[] if case['mode'] == 'ordered' else [{}] * count,
                                           transport=dict(lost_packets=0))
                if case['reader'] == 'aioquic':
                    summary.update(independent_completed=count, body_bytes_verified=count * size,
                                   wire={str(i * 4): {} for i in range(count)})
                else:
                    summary['reader'] = 'shb'
                    summary['report'] = dict(requests=dict(total=count, ok=count, errors=0, connectErrors=0),
                                             latencySamples=count, statusCodes={'200': count}, latencySeconds={},
                                             protocol='HTTP/3', connections=1, threads=1)
                if case['reader'] == 'exposure':
                    # Deliberately differs from logical chunks: packet splitting
                    # and an ignored final frame can increase the native queue.
                    peak = 0 if case['mode'] == 'ordered' else size // case['chunk'] + 2
                    summary['exposure'] = dict(bodies=[dict(bytes=size) for _ in range(count)],
                                               streams=[dict(peak_pending=peak, final_size=size + 17,
                                                             credited_bytes=size + 17, read_offset=size + 17,
                                                             ready=0, pending=0) for _ in range(count)])
            results.append(dict(case=case['case'], summary=summary))
        return results

    def test_small_plan_covers_each_geometry_schedule_reader_and_fault(self):
        cases = suite_cases('small')
        self.assertEqual(len(cases), 30)
        self.assertEqual(len({c['case'] for c in cases}), 30)
        positive = {(c['body_bytes'], c['chunk'], c['mode'], c['reader'], c['requests'])
                    for c in cases if c['fault'] == 'none'}
        self.assertEqual(positive, {(size, chunk, mode, reader, 3)
                         for size, chunk in ((128, 64), (4096, 256), (16384, 256))
                         for mode in ('ordered', 'reverse', 'mixed')
                         for reader in ('aioquic', 'shb', 'exposure')})
        self.assertEqual({(c['fault'], c['body_bytes'], c['chunk'], c['reader'], c['requests'])
                          for c in cases if c['fault'] != 'none'},
                         {(fault, 128, 64, 'aioquic', 1)
                          for fault in ('missing-prefix', 'missing-fin', 'corrupt')})

    def test_large_plan_retains_duplicate_and_loss_controls(self):
        cases = suite_cases('large')
        self.assertEqual(len(cases), 16)
        self.assertTrue(all(c['body_bytes'] == 525312 and c['chunk'] == 1024 for c in cases))
        self.assertEqual(sum(c['mode'] == 'duplicates' for c in cases), 3)
        self.assertEqual(sum(c['fault'] == 'drop-once' for c in cases), 1)

    def test_record_observed_queues_separately_from_configured_chunks(self):
        result = suite_coverage('small', self.results())
        self.assertFalse(result['timing_eligible'])
        row = next(c for c in result['cases'] if c['case'] == '128-64-exposure-reverse-none')
        self.assertEqual(row['configured_suffix_chunks'], 1)
        self.assertEqual(row['observed_peak_pending'], [4, 4, 4])
        self.assertEqual(row['observed_final_bytes'], row['observed_credited_bytes'])
        self.assertEqual(row['observed_final_bytes'], row['observed_consumed_bytes'])

    def test_missing_duplicate_or_wrong_size_cannot_cover_matrix(self):
        good = self.results()
        with self.assertRaisesRegex(ValueError, 'incomplete matrix'):
            suite_coverage('small', good[:-1])
        broken = copy.deepcopy(good)
        broken[1] = broken[0]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            suite_coverage('small', broken)
        broken = copy.deepcopy(good)
        broken[0]['summary']['body_bytes'] = 525312
        with self.assertRaisesRegex(ValueError, 'body_bytes mismatch'):
            suite_coverage('small', broken)

    def test_failure_missing_wire_or_missing_observer_cannot_pass(self):
        for index, key, value, reason in ((0, 'passed', False, 'did not pass'),
                                          (0, 'wire', {}, 'missing independent wire stream'),
                                          (2, 'exposure', {'streams': [], 'bodies': [{'bytes': 128}] * 3}, 'retired stream')):
            with self.subTest(key=key):
                broken = self.results()
                broken[index]['summary'][key] = value
                with self.assertRaisesRegex(ValueError, reason):
                    suite_coverage('small', broken)

    def test_sample_loss_and_unexpected_transport_loss_fail(self):
        broken = self.results()
        broken[1]['summary']['report']['latencySamples'] = 2
        with self.assertRaisesRegex(ValueError, 'sample counts'):
            suite_coverage('small', broken)
        broken = self.results()
        broken[0]['summary']['schedule']['transport']['lost_packets'] = 1
        with self.assertRaisesRegex(ValueError, 'packet loss'):
            suite_coverage('small', broken)

    def test_negative_exit_alone_cannot_replace_specific_rejection(self):
        broken = self.results()
        del broken[-1]['summary']['rejected']
        with self.assertRaisesRegex(ValueError, 'specifically rejected'):
            suite_coverage('small', broken)

    def test_fault_substitution_and_observer_credit_drift_fail(self):
        broken = self.results()
        broken[-1]['summary']['rejected'] = broken[-3]['summary']['rejected']
        with self.assertRaisesRegex(ValueError, 'corruption missed'):
            suite_coverage('small', broken)
        broken = self.results()
        broken[-2]['summary']['rejected']['body_bytes'] = 0
        with self.assertRaisesRegex(ValueError, 'wrong blocked state'):
            suite_coverage('small', broken)
        broken = self.results()
        broken[2]['summary']['exposure']['streams'][0]['credited_bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'credit mismatch'):
            suite_coverage('small', broken)


if __name__ == '__main__':
    unittest.main()
