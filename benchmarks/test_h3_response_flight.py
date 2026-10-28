import copy
import unittest

from h3_response_flight import validate_client, validate_peer, validate_fin_frames


class FrameEndTests(unittest.TestCase):
    def test_ignored_frame_can_carry_fin(self):
        validate_fin_frames(b'\x01\x01h\x00\x03abc\x21\x00')

    def test_partial_varint_header_or_payload_at_fin_fails(self):
        for wire in (b'\x01', b'\x40', b'\x01\x40', b'\x00\x04abc', b'\x21\x01'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                validate_fin_frames(wire)


class ReceiptLedgerTests(unittest.TestCase):
    def setUp(self):
        self.good = dict(connections=1, accepted=5, validated=5, finished=5,
                         acknowledged=5, acknowledgedBodyBytes=5120, expectedRequests=5,
                         bodyBytes=1024, fault='None', errors=[])

    def test_complete_receipts(self):
        validate_peer(self.good, 0, 5, 1024, 1)

    def test_successful_writes_do_not_prove_receipt(self):
        self.good.update(acknowledged=4, acknowledgedBodyBytes=4096)
        with self.assertRaises(ValueError):
            validate_peer(self.good, 0, 5, 1024, 1)

    def test_missing_truncated_excess_or_noninteger_accounting(self):
        for field in ('accepted', 'validated', 'finished', 'acknowledged',
                      'acknowledgedBodyBytes', 'expectedRequests', 'bodyBytes', 'connections'):
            for value in (None, 0, -1, True, 1.0, self.good[field] + 1):
                with self.subTest(field=field, value=value):
                    broken = dict(self.good, **{field: value})
                    with self.assertRaises(ValueError):
                        validate_peer(broken, 0, 5, 1024, 1)

    def test_late_failure_after_complete_counts(self):
        for field, value in (('errors', ['late failure']), ('errors', None),
                             ('fault', 'Truncate'), ('fault', None)):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    validate_peer(dict(self.good, **{field: value}), 0, 5, 1024, 1)

    def test_failed_or_early_exit_cannot_pass_full_ledger(self):
        for code in (-9, 1, None):
            with self.assertRaises(ValueError):
                validate_peer(self.good, code, 5, 1024, 1)


class ClientAccountingTests(unittest.TestCase):
    def setUp(self):
        self.report = dict(requests=dict(total=5, ok=5, errors=0, connectErrors=0),
                           latencySamples=5, statusCodes={'200': 5}, latencySeconds={},
                           protocol='HTTP/3', connections=1, threads=1)

    def test_exact_counts(self):
        validate_client(self.report, 0, 5, 1, 1)

    def test_missing_sample_error_status_or_request(self):
        mutations = [dict(latencySamples=4), dict(statusCodes={'503': 5}),
                     dict(requests=dict(total=5, ok=5, errors=0, connectErrors=1)),
                     dict(requests=dict(total=4, ok=4, errors=0, connectErrors=0)),
                     dict(connections=2), dict(protocol='HTTP/2')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    validate_client(dict(copy.deepcopy(self.report), **mutation), 0, 5, 1, 1)


if __name__ == '__main__':
    unittest.main()
