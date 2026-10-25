"""The live upload validators must reject missing or invented latency samples."""
import copy
import unittest

from report_accounting import validate_sample_accounting


class ReportAccountingTests(unittest.TestCase):
    def report(self):
        return dict(requests=dict(ok=3, errors=2, connectErrors=1, total=5),
                    statusCodes={'200': 2, '503': 1}, latencySamples=3,
                    latencySeconds={'min': .001, 'mean': .002, 'max': .003,
                                    'percentiles': {'p99': .003}})

    def test_mixed_results_preserve_report(self):
        report = self.report()
        before = copy.deepcopy(report)
        validate_sample_accounting(report)
        self.assertEqual(report, before)

    def test_missing_short_extra_total_and_invalid_counts_fail(self):
        for value in [None, 0, 2, 4, 5, -1, 3.0, True, '3']:
            with self.subTest(value=value):
                report = self.report()
                report['latencySamples'] = value
                with self.assertRaises(ValueError):
                    validate_sample_accounting(report)
        report = self.report()
        del report['latencySamples']
        with self.assertRaises(KeyError):
            validate_sample_accounting(report)

    def test_zero_successes_and_zero_budget(self):
        for errors in [0, 5]:
            report = dict(requests=dict(ok=0, errors=errors, total=errors),
                          statusCodes={}, latencySamples=0, latencySeconds=None)
            validate_sample_accounting(report)
            report['latencySamples'] = errors or 1
            with self.assertRaises(ValueError):
                validate_sample_accounting(report)

    def test_other_ledger_mismatches_fail(self):
        for field, value in [('requests', dict(ok=3, errors=2, total=6)),
                             ('statusCodes', {'200': 2}), ('latencySeconds', None)]:
            with self.subTest(field=field):
                report = self.report()
                report[field] = value
                with self.assertRaises(ValueError):
                    validate_sample_accounting(report)


if __name__ == '__main__':
    unittest.main()
