"""Replay real encrypted Retry evidence and verify the fault controls themselves."""

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import quic_retry as oracle


class RetryOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((Path(__file__).parent / 'fixtures/quic-retry.json').read_text())['rows']

    def row(self, case='retry'):
        return deepcopy(next(row for row in self.rows if row['case'] == case))

    def rejected(self, row, code, validator=oracle.validate_result):
        with self.assertRaises(oracle.RetryFailure) as raised:
            validator(row)
        self.assertEqual(raised.exception.code, code)

    def test_all_five_wire_schedules_and_101_precise_controls(self):
        self.assertEqual([row['case'] for row in self.rows], list(oracle.CASES))
        before, controls = deepcopy(self.rows), []
        for row in self.rows:
            with self.subTest(case=row['case']):
                oracle.validate_result(row)
                controls.extend(oracle.negative_controls(row))
        self.assertEqual(len(controls), 101)
        self.assertEqual(self.rows, before)

    def test_crash_handshake_and_callback_failure_cannot_pass_controls(self):
        for fault, code in [('exit', 'client-exit'), ('tls', 'handshake'), ('peer', 'peer-failure')]:
            with self.subTest(fault=fault):
                row = self.row()
                if fault == 'exit':
                    row['client_exit'] = -9
                elif fault == 'tls':
                    row['ledger']['handshakes'] = 0
                else:
                    row['failures'].append('failed decryption')
                self.rejected(row, code, oracle.negative_controls)

    def test_unrelated_failure_is_not_detection(self):
        with patch.object(oracle, 'validate_result', side_effect=[
                None, oracle.RetryFailure('handshake', 'failed TLS')]):
            self.rejected(self.row(), 'wrong-control-failure', oracle.negative_controls)

    def test_disabled_validator_is_not_detection(self):
        with patch.object(oracle, 'validate_result', return_value=None):
            self.rejected(self.row(), 'undetected-control', oracle.negative_controls)

    def test_every_initial_repeats_the_authentic_token(self):
        for case in oracle.CASES[1:]:
            original = self.row(case)
            for index in range(1, len(original['ledger']['initials'])):
                with self.subTest(case=case, index=index):
                    row = deepcopy(original)
                    row['ledger']['initials'][index]['token_sha256'] = '0' * 64
                    self.rejected(row, 'token-identity')

    def test_correct_http_report_cannot_hide_absent_retransmission(self):
        row = self.row('drop')
        row['ledger']['initials'] = row['ledger']['initials'][:2]
        self.rejected(row, 'missing-retransmission')

    def test_retransmission_must_preserve_each_crypto_byte_and_offset(self):
        for field, value, code in [('offset', 1, 'crypto-layout'),
                                   ('length', 1, 'retransmit-crypto'),
                                   ('sha256', 'f' * 64, 'retransmit-crypto')]:
            with self.subTest(field=field):
                row = self.row('drop')
                row['ledger']['initials'][2]['crypto'][0][field] = value
                self.rejected(row, code)

    def test_reordering_requires_delivery_of_replacement_before_original(self):
        row = self.row('reorder')
        row['ledger']['deliveries'][1]['initial'] = 1
        row['ledger']['deliveries'][2]['initial'] = 2
        self.rejected(row, 'delivery-order')

    def test_drop_cannot_be_replaced_by_a_delay(self):
        row = self.row('drop')
        row['ledger']['deliveries'].append(dict(initial=1, seq=999))
        self.rejected(row, 'delivery-order')

    def test_retry_cid_can_change_after_server_answers(self):
        row = self.row()
        self.assertNotEqual(row['ledger']['initials'][-1]['dcid'],
                            row['ledger']['retries'][0]['scid'])
        oracle.validate_result(row)
        row['ledger']['initials'][1]['dcid'] = '00'
        self.rejected(row, 'retry-cid')

    def test_forgery_has_distinct_token_and_precedes_authentic_retry(self):
        row = self.row('forged-second')
        row['ledger']['retries'][0]['token_sha256'] = row['ledger']['retries'][1]['token_sha256']
        self.rejected(row, 'retry-forgeries')
        row = self.row('forged-second')
        row['ledger']['retries'][0]['seq'] = row['ledger']['retries'][1]['seq'] + 1
        self.rejected(row, 'forgery-order')

    def test_missing_second_retry_is_not_a_successful_forgery_schedule(self):
        row = self.row('forged-second')
        row['ledger']['retries'].pop()
        self.rejected(row, 'retry-schedule')

    def test_repeated_connection_cannot_hide_behind_exact_request_counts(self):
        row = self.row()
        row['ledger']['peers'] += 1
        self.rejected(row, 'handshake')

    def test_sample_count_requires_an_integer(self):
        for value in [True, 32.0, '32', None]:
            row = self.row()
            row['report']['latencySamples'] = value
            self.rejected(row, 'sample-count')


if __name__ == '__main__':
    unittest.main()
