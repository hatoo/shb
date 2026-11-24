"""Contract tests for the independent wire/accounting oracle."""
import copy
import json
import unittest

from h3_critical_close import audit, CRITICAL, REASON


def row(kind='control', workers=1, baseline=False):
    critical = kind in CRITICAL
    total = workers * 4
    ok = 0 if critical else total
    report = dict(requests=dict(total=total, ok=ok, errors=total-ok, connectErrors=0),
                  statusCodes={'200': ok} if ok else {}, latencySamples=ok,
                  latencySeconds={} if ok else None, protocol='HTTP/3',
                  connections=workers, threads=workers)
    code = (0x10c if baseline else 0x104) if critical else 0x100
    peer = dict(handshake=True, requests=[0, 4, 8, 12], fired=True,
                prefix_sent=0 if kind == 'empty' else 1,
                prefix_acked=0 if kind == 'empty' else 1,
                closes=[dict(code=code, frame=None, reason=REASON)],
                responses=[] if critical else [0, 4, 8, 12])
    return dict(kind=kind, workers=workers, baseline=baseline, client_exit=0,
                failures=[], cleanup=dict(client_reaped=True, communication_joined=True,
                                         server_closed=True, peers_closed=True),
                stdout=json.dumps(report), stderr='[drive] peer closed a critical HTTP/3 stream',
                peers=[copy.deepcopy(peer) for _ in range(workers)])


class CriticalOracleTests(unittest.TestCase):
    def test_positive_negative_and_baseline_budgets(self):
        for kind in ('control', 'encoder', 'decoder', 'unknown', 'empty', 'partial'):
            for workers in (1, 2):
                for baseline in (False, True):
                    with self.subTest(kind=kind, workers=workers, baseline=baseline):
                        counts = audit(row(kind, workers, baseline))
                        self.assertEqual(counts['requests'], 4 * workers)
                        self.assertEqual(counts['samples'], counts['completed'])

    def test_timeout_or_transport_close_cannot_satisfy_critical_closure(self):
        for code, frame, reason in ((0x10c, None, ''), (0x100, None, REASON),
                                     (0x104, 0, REASON), (0x104, None, 'other')):
            evidence = row()
            evidence['peers'][0]['closes'] = [dict(code=code, frame=frame, reason=reason)]
            with self.assertRaises(ValueError):
                audit(evidence)

    def test_unsent_unacknowledged_or_impossible_prefix_delivery_fails(self):
        for sent, acked in ((0, 0), (1, 0), (0, 1), (1, 2), (1, True)):
            evidence = row()
            evidence['peers'][0].update(prefix_sent=sent, prefix_acked=acked)
            with self.subTest(sent=sent, acked=acked), self.assertRaises(ValueError):
                audit(evidence)

    def test_missing_duplicate_or_extra_peer_evidence_fails(self):
        for key in ('handshake', 'fired', 'requests', 'closes', 'responses'):
            evidence = row()
            evidence['peers'][0][key] = False if key in ('handshake', 'fired') else ([] if key == 'closes' else [123])
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit(evidence)
        for count in (0, 2):
            evidence = row()
            evidence['peers'] *= count
            with self.assertRaises(ValueError):
                audit(evidence)
        evidence = row()
        evidence['peers'][0]['closes'] *= 2
        with self.assertRaises(ValueError):
            audit(evidence)

    def test_missing_extra_and_invalid_samples_fail(self):
        for value in (None, 0, 3, 5, True, '4'):
            evidence = row('unknown')
            report = json.loads(evidence['stdout'])
            report['latencySamples'] = value
            evidence['stdout'] = json.dumps(report)
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit(evidence)

    def test_even_self_consistent_wrong_counts_or_configuration_fail(self):
        for field, value in (('requests', dict(total=5, ok=0, errors=5, connectErrors=0)),
                             ('threads', 2), ('connections', 2), ('protocol', 'HTTP/2')):
            evidence = row()
            report = json.loads(evidence['stdout'])
            report[field] = value
            evidence['stdout'] = json.dumps(report)
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit(evidence)

    def test_process_peer_and_cleanup_failures_cannot_pass(self):
        for key, value in (('client_exit', 1), ('failures', ['peer exception']),
                           ('stderr', ''), ('cleanup', {})):
            evidence = row()
            evidence[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit(evidence)
        for key in row()['cleanup']:
            evidence = row()
            evidence['cleanup'][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit(evidence)


if __name__ == '__main__':
    unittest.main()
