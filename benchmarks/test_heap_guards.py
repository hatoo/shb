"""Guard acceptance must reject corrupt accounting and inconclusive controls."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import heap_guards as g


class GuardTests(unittest.TestCase):
    def report(self):
        return dict(requests=dict(ok=10000, total=10000, errors=0, connectErrors=0),
                    statusCodes={'200': 10000}, latencySamples=10000,
                    requestsPerSec=5000, durationSeconds=2,
                    latencySeconds=dict(percentiles={'p99': .001, 'p99.9': .002}))

    def metrics(self, report):
        return g.metrics(report, dict(user_s=.8, system_s=.2), dict(user_s=.5, system_s=.1))

    def test_exact_samples_and_cpu_per_request(self):
        values = self.metrics(self.report())
        self.assertEqual(values['samples'], 10000)
        self.assertEqual(values['cpu_ns'], 100000)
        self.assertEqual(values['peer_cpu_ns'], 60000)

    def test_missing_or_corrupt_accounting_rejected(self):
        for fault in ('samples', 'errors', 'connect', 'status', 'total', 'rate', 'nan', 'missing_tail'):
            with self.subTest(fault=fault):
                r = self.report()
                if fault == 'samples':
                    r['latencySamples'] -= 1
                elif fault == 'errors':
                    r['requests']['errors'] = 1
                elif fault == 'connect':
                    r['requests']['connectErrors'] = 1
                elif fault == 'status':
                    r['statusCodes'] = {'103': 10000}
                elif fault == 'total':
                    r['requests']['total'] += 1
                elif fault == 'rate':
                    r['requestsPerSec'] += 1
                elif fault == 'nan':
                    r['latencySeconds']['percentiles']['p99.9'] = float('nan')
                else:
                    del r['latencySeconds']['percentiles']['p99.9']
                with self.assertRaises((ValueError, KeyError)):
                    self.metrics(r)

    def test_smt_sibling_is_not_a_separate_core(self):
        rows = [dict(cpu=0, socket=0, core=3), dict(cpu=1, socket=0, core=3),
                dict(cpu=2, socket=0, core=4), dict(cpu=3, socket=0, core=4)]
        self.assertEqual(g.placement(rows), dict(server_cpu=0, client_cpu=2))
        with self.assertRaises(ValueError):
            g.placement(rows[:2])
        with self.assertRaises(ValueError):
            g.placement(rows[1:])

    def test_affinity_audits_all_threads(self):
        g.affinity(dict(threads={'1': dict(affinity=[0]), '2': dict(affinity=[0])}), 0)
        for threads in ({}, {'1': dict(affinity=[0]), '2': dict(affinity=[1])}):
            with self.assertRaises(ValueError):
                g.affinity(dict(threads=threads), 0)

    def test_h1_command_does_not_enable_multiplexing(self):
        config = dict(protocol='h1', client_cpu=2, client='/frozen/shb', seconds=5)
        command = g.ordinary_client(config, Path('/new'), 18083)
        self.assertNotIn('-p', command)
        self.assertNotIn('--http2', command)
        self.assertNotIn('--http3', command)
        for protocol in ('h2', 'h3'):
            command = g.ordinary_client(config | {'protocol': protocol}, Path('/new'), 18443)
            self.assertEqual(command[command.index('-p') + 1], '32')
            self.assertIn('--http2' if protocol == 'h2' else '--http3', command)

    def test_one_noisy_pair_cannot_hide_behind_the_median(self):
        good = dict(rps=0, cpu_ns=0, peer_cpu_ns=0, p99=0, p999=0)
        self.assertTrue(g.suitable([good] * 3))
        for key, value in (('rps', 3.01), ('cpu_ns', -3.01), ('p99', 10.01), ('p999', -10.01)):
            self.assertFalse(g.suitable([good, good | {key: value}, good]))

    def test_guard_failure_is_separate_from_control_noise(self):
        gain = dict(rps=5, cpu_ns=-5, peer_cpu_ns=0, p99=-11, p999=-12)
        self.assertTrue(g.guard_passes([gain] * 3))
        self.assertFalse(g.suitable([gain] * 3))
        for key, value in (('rps', -3.01), ('cpu_ns', 3.01), ('p99', 10.01), ('p999', 10.01)):
            self.assertFalse(g.guard_passes([gain, gain | {key: value}, gain]))

    def test_private_namespace_and_all_udp_errors_required(self):
        before = dict(namespace='child', host_namespace='host',
                      counters={k: 0 for k in (*g.ERRORS, 'InDatagrams', 'OutDatagrams')})
        after = copy.deepcopy(before)
        after['counters'].update(InDatagrams=10, OutDatagrams=10)
        self.assertEqual(g.udp_audit(before, after, True)['InDatagrams'], 10)
        for key in g.ERRORS:
            bad = copy.deepcopy(after)
            bad['counters'][key] = 1
            with self.assertRaises(ValueError):
                g.udp_audit(before, bad, True)
        with self.assertRaises(ValueError):
            g.udp_audit(before | {'host_namespace': 'child'}, after, True)

    def test_evidence_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'record.json'
            g.save(path, dict(original=True))
            with self.assertRaises(FileExistsError):
                g.save(path, dict(original=False))
            self.assertEqual(json.loads(path.read_text()), dict(original=True))

    def test_changed_binary_stops_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'client'
            binary.write_text('old')
            config = dict(inputs={str(binary): g.digest(binary)})
            binary.write_text('new')
            with patch.object(g.subprocess, 'Popen') as popen:
                with self.assertRaisesRegex(ValueError, 'frozen input'):
                    g.launch(config, root / 'trial.json')
                popen.assert_not_called()

    def test_failed_process_keeps_exit_and_cannot_be_a_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = dict(inputs={}, kind='ordinary')
            with patch.object(g.subprocess, 'Popen') as popen:
                popen.return_value.wait.return_value = 17
                popen.return_value.poll.return_value = 17
                with self.assertRaisesRegex(ValueError, 'trial failed'):
                    g.launch(config, root / 'trial.json')
            self.assertEqual(json.loads((root / 'trial.exit.json').read_text()), 17)


if __name__ == '__main__':
    unittest.main()
