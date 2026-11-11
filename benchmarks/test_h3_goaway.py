"""Fault controls replay real peer/report evidence without aioquic or sockets."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import h3_goaway as oracle
import h3_control_fragments as fragments


class GoawayOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((Path(__file__).parent / 'fixtures/h3-goaway.json').read_text())['rows']

    def row(self, case):
        return deepcopy(next(r for r in self.rows if r['case'] == case))

    def rejected(self, row, code, validator=oracle.validate_result):
        with self.assertRaises(oracle.GoawayFailure) as raised:
            validator(row)
        self.assertEqual(raised.exception.code, code)

    def test_all_nine_positive_wire_ledgers_are_unchanged(self):
        self.assertEqual([(r['case'], r['parallel']) for r in self.rows], [
            ('mixed', 8), ('decreasing', 8), ('no-suffix', 1), ('no-suffix', 64),
            ('zero', 1), ('zero', 64), ('ordinary', 1), ('ordinary', 64), ('blocked-upload', 8)])
        before = deepcopy(self.rows)
        for row in self.rows:
            with self.subTest(case=row['case'], parallel=row['parallel']):
                oracle.validate_result(row)
        self.assertEqual(self.rows, before)

    def test_semantic_controls_reject_exact_fault_without_changing_evidence(self):
        before = deepcopy(self.rows)
        controls = []
        for row in self.rows:
            with self.subTest(case=row['case'], parallel=row['parallel']):
                controls.extend(oracle.negative_controls(row))
        self.assertEqual(len(controls), 62)
        self.assertTrue({'upload-cancellation', 'cancellation-order', 'retry-count',
                         'request-budget', 'missing-samples', 'sample-count', 'retry-body',
                         'ack-barrier', 'held-latency', 'mixed-packet'} <=
                        {c['rejected_by'] for c in controls})
        self.assertEqual(self.rows, before)

    def test_crash_handshake_and_peer_errors_cannot_pass_negative_controls(self):
        for fault, code in [('exit', 'client-exit'), ('tls', 'handshake'), ('peer', 'peer-failure')]:
            with self.subTest(fault=fault):
                row = self.row('blocked-upload')
                if fault == 'exit':
                    row['client_exit'] = -9
                elif fault == 'tls':
                    row['peers'][0]['tls'] = False
                else:
                    row['failures'].append('phase ACK deadline')
                self.rejected(row, code, oracle.negative_controls)

    def test_unrelated_failure_does_not_count_as_detection(self):
        with patch.object(oracle, 'validate_result', side_effect=[
                None, oracle.GoawayFailure('handshake', 'failed TLS')]):
            self.rejected(self.row('mixed'), 'wrong-control-failure', oracle.negative_controls)

    def test_disabled_validator_does_not_pass_controls(self):
        with patch.object(oracle, 'validate_result', return_value=None):
            self.rejected(self.row('mixed'), 'undetected-control', oracle.negative_controls)

    def test_wrong_cancellation_code_or_final_size(self):
        for field, value in [(1, 0), (2, 129)]:
            with self.subTest(field=field):
                row = self.row('blocked-upload')
                row['peers'][0]['client_resets'][0][field] = value
                self.rejected(row, 'cancellation-fields')

    def test_duplicate_request_with_same_attempt_count(self):
        row = self.row('mixed')
        row['peers'][1]['requests'][1] = 0
        self.rejected(row, 'request-ids')

    def test_missing_schedule_boundary_or_phase(self):
        for field, code in [('scheduled', 'incomplete-schedule'), ('goaways', 'goaway-boundaries'),
                            ('phases', 'phase-sequence')]:
            with self.subTest(field=field):
                row = self.row('decreasing')
                row['peers'][0][field] = False if field == 'scheduled' else []
                self.rejected(row, code)

    def test_unknown_ack_packet_and_empty_barrier(self):
        for numbers in [[999999], []]:
            row = self.row('mixed')
            row['peers'][0]['phases'][0].update(sent=numbers, acknowledged=numbers)
            self.rejected(row, 'ack-barrier')

    def test_nonfinite_or_short_held_latency(self):
        for maximum in [float('nan'), float('inf'), -.1, .001]:
            with self.subTest(maximum=maximum):
                row = self.row('decreasing')
                row['report']['latencySeconds']['max'] = maximum
                self.rejected(row, 'held-latency')


class FragmentedControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((Path(__file__).parent / 'fixtures/h3-control-fragments.json').read_text())['rows']

    def rejected(self, row, code):
        with self.assertRaises(oracle.GoawayFailure) as raised:
            oracle.validate_result(row)
        self.assertEqual(raised.exception.code, code)

    def test_seven_new_wire_ledgers_and_precise_controls(self):
        self.assertEqual([(r['case'], r['parallel']) for r in self.rows], [
            ('fragmented', 8), ('malformed-goaway', 1), ('malformed-goaway', 64),
            ('oversized-goaway', 1), ('oversized-goaway', 64),
            ('trailing-goaway', 1), ('trailing-goaway', 64)])
        before, controls = deepcopy(self.rows), []
        for row in self.rows:
            with self.subTest(case=row['case'], parallel=row['parallel']):
                oracle.validate_result(row)
                controls.extend(oracle.negative_controls(row))
        self.assertEqual(len(controls), 121)
        self.assertTrue({'control-bytes', 'control-offset', 'wire-bytes', 'wire-coverage',
                         'authenticated-ack', 'fragment-order', 'fragment-mixed-packet',
                         'parser-error', 'cleanup'} <= {c['rejected_by'] for c in controls})
        self.assertEqual(self.rows, before)

    def test_malformed_control_cannot_count_a_colocated_success(self):
        for original in self.rows[1:]:
            for field, code in [('success', 'request-budget'), ('sample', 'sample-count'),
                                ('status', 'status-count')]:
                with self.subTest(case=original['case'], parallel=original['parallel'], field=field):
                    row = deepcopy(original)
                    if field == 'success':
                        row['report']['requests']['ok'] = 1
                        row['report']['requests']['errors'] -= 1
                    elif field == 'sample':
                        row['report']['latencySamples'] = 1
                    else:
                        row['report']['statusCodes'] = {'299': 1}
                    self.rejected(row, code)

    def test_malformed_response_must_share_the_terminal_packet(self):
        for original in self.rows[1:]:
            row = deepcopy(original)
            for packet in row['peers'][0]['packets']:
                if packet['phase'] == 'invalid-final':
                    packet['frames'] = [f for f in packet['frames'] if f['stream_id'] != 0]
            self.rejected(row, 'invalid-mixed-packet')

    def test_specific_parser_error_is_required_not_any_drive_error(self):
        for original in self.rows[1:]:
            row = deepcopy(original)
            row['stderr'] = '[drive] an unrelated parser failure\n'
            self.rejected(row, 'parser-error')

    def test_cross_phase_frame_cannot_fake_a_receive_boundary(self):
        row = deepcopy(self.rows[0])
        peer = row['peers'][0]
        frame = next(f for p in peer['packets'] if p['phase'] == 'grease-type-prefix'
                     for f in p['frames'] if f['stream_id'] == peer['control_stream_id'])
        frame['data'] += peer['control_writes'][1]['data']
        frame['length'] = len(bytes.fromhex(frame['data']))
        self.rejected(row, 'wire-offset')

    def test_duplicate_packet_or_sequence_is_not_independent_evidence(self):
        for field, code in [('pn', 'packet-number'), ('sequence', 'event-sequence')]:
            row = deepcopy(self.rows[0])
            packets = row['peers'][0]['packets']
            # A spare ACK-only packet does not alter the phase packet set.
            packets.append(dict(packets[0], pn=999999, sequence=999999, frames=[]))
            packets[-1][field] = packets[0][field]
            self.rejected(row, code)

    def test_workload_contains_nonminimal_fields_and_false_goaways(self):
        plan = dict(fragments.chunks('fragmented'))
        self.assertEqual(plan['wide-type-prefix'] + plan['wide-type-tail'], b'\xc0' + b'\0' * 6 + b'\x07')
        self.assertEqual(plan['wide-length-prefix'] + plan['wide-length-tail'], b'\x80\0\0\x08')
        self.assertEqual(plan['wide-id-prefix'] + plan['wide-id-tail'], b'\xc0' + b'\0' * 6 + b'\x10')
        body = b''.join(data for name, data in plan.items() if name.startswith('grease-body-'))
        self.assertEqual(len(body), 4096)
        self.assertGreater(body.count(b'\x07\x01\0'), 400)


if __name__ == '__main__':
    unittest.main()
