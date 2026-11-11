"""Replay real encrypted response traces and precise faults without aioquic."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import h3_response_fragments as oracle


class ResponseFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((Path(__file__).parent / 'fixtures/h3-response-fragments.json').read_text())['rows']

    def row(self, name='wide-grease'):
        return deepcopy(next(r for r in self.rows if r['case'] == name))

    def rejected(self, row, code, validator=oracle.validate_result):
        with self.assertRaises(oracle.ResponseFailure) as raised:
            validator(row)
        self.assertEqual(raised.exception.code, code)

    def test_real_wire_records_and_precise_controls(self):
        self.assertEqual([r['case'] for r in self.rows],
                         ['fragmented-n0-hv0', 'wide-grease', 'wide-multiplexed', 'wide-truncated-name'])
        before, controls = deepcopy(self.rows), []
        for row in self.rows:
            with self.subTest(case=row['case']):
                oracle.validate_result(row)
                controls.extend(oracle.negative_controls(row))
        self.assertTrue({'sample-count', 'status-count', 'wire-bytes', 'wire-offset', 'wire-fin',
                         'authenticated-ack', 'fragment-order', 'parser-error'} <=
                        {r['rejected_by'] for r in controls})
        self.assertEqual(self.rows, before)

    def test_unrelated_failure_cannot_satisfy_control(self):
        with patch.object(oracle, 'validate_result', side_effect=[
                None, oracle.ResponseFailure('handshake', 'TLS failed')]):
            self.rejected(self.row(), 'wrong-control-failure', oracle.negative_controls)

    def test_disabled_validator_cannot_satisfy_control(self):
        with patch.object(oracle, 'validate_result', return_value=None):
            self.rejected(self.row(), 'undetected-control', oracle.negative_controls)

    def test_execution_failures_cannot_pass_controls(self):
        for fault, code in [('exit', 'client-exit'), ('tls', 'handshake'), ('peer', 'peer-failure')]:
            with self.subTest(fault=fault):
                row = self.row()
                if fault == 'exit':
                    row['client_exit'] = -9
                elif fault == 'tls':
                    row['peer']['tls'] = False
                else:
                    row['failures'].append('ACK deadline')
                self.rejected(row, code, oracle.negative_controls)

    def test_split_fields_and_ignored_header_lookalikes(self):
        chunks = dict(oracle.plan(self.row()['workload']))
        self.assertEqual(chunks['final-type-prefix'] + chunks['final-type-tail'], b'\x80\0\0\x01')
        self.assertEqual(len(chunks['final-length-prefix']), 7)
        self.assertIn(b'\x01\x03\0\0\xd9', chunks['grease-payload-0'])
        self.assertIn(b'\x01\x03\0\0\xd9', b''.join(v for k, v in chunks.items() if k.startswith('body-payload')))
        self.assertEqual(chunks['fin'], b'')

    def test_corrupted_ignored_body_is_detected(self):
        row = self.row()
        peer = row['peer']
        write = next(w for w in peer['writes'] if w['phase'] == 'body-payload-0')
        frame = next(f for p in peer['packets'] for f in p['frames']
                     if f['stream_id'] == write['id'] and f['offset'] == write['offset'])
        frame['data'] = 'ff' * frame['length']
        self.rejected(row, 'wire-bytes')

    def test_cross_phase_stream_frame_cannot_prove_fragmentation(self):
        row = self.row()
        first, second = row['peer']['writes'][:2]
        frame = next(f for p in row['peer']['packets'] for f in p['frames'] if f['length'])
        frame['data'] = first['data'] + second['data']
        frame['length'] = len(bytes.fromhex(frame['data']))
        self.rejected(row, 'wire-offset')

    def test_early_empty_fin_is_rejected_even_with_a_final_fin(self):
        row = self.row()
        row['peer']['packets'][0]['frames'].append(dict(frame_type='stream', stream_id=0,
                                                       offset=1, length=0, data='', fin=True))
        self.rejected(row, 'wire-fin')

    def test_duplicate_events_or_packets_do_not_prove_delivery(self):
        for field, code in [('pn', 'packet-number'), ('sequence', 'event-sequence')]:
            with self.subTest(field=field):
                row = self.row()
                row['peer']['packets'][1][field] = row['peer']['packets'][0][field]
                self.rejected(row, code)

    def test_acknowledged_original_allows_unacknowledged_retransmission(self):
        row = self.row()
        # The identical retransmission may go unacknowledged. An ACK of the
        # original already proved delivery, so replay must not demand both.
        packet = deepcopy(row['peer']['packets'][0])
        packet.update(pn=999999, sequence=999999)
        row['peer']['packets'].append(packet)
        oracle.validate_result(row)

    def test_rejected_terminal_payload_needs_no_ack(self):
        row = self.row('wide-truncated-name')
        terminal = row['peer']['packets'][-1]
        row['peer']['acks'] = [a for a in row['peer']['acks'] if a['sequence'] < terminal['sequence']]
        oracle.validate_result(row)
        row['stderr'] = '[broken] 1 requests in flight discarded\n'
        self.rejected(row, 'parser-error')

    def test_wrong_stream_and_premature_completion_are_rejected(self):
        row = self.row()
        row['peer']['packets'][0]['frames'][0]['stream_id'] = 999
        self.rejected(row, 'response-stream')
        row = self.row()
        row['peer']['premature_requests'] = [4]
        self.rejected(row, 'premature-completion')

    def test_multiplexed_streams_really_overlap(self):
        row = self.row('wide-multiplexed')
        peer = row['peer']
        first_fin = min(w['sequence'] for w in peer['writes'] if w['fin'])
        started = {w['id'] for w in peer['writes'] if w['sequence'] < first_fin}
        self.assertEqual(started, set(range(0, 32, 4)))


if __name__ == '__main__':
    unittest.main()
