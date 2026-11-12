"""Reject missing CPU evidence and check Linux per-thread timing against a clock."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from native_reordering import require

spec = importlib.util.spec_from_file_location('measure_native', Path(__file__).with_name('measure-native-reordering.py'))
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)
measure.require = require


class MeasurementTests(unittest.TestCase):
    def test_missing_or_nonfinite_cpu_is_not_valid_evidence(self):
        valid = dict(exit=0, elapsed_s=0.5, user_s=0.1, system_s=0.01)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'resource.json'
            for change in ({'exit': 1}, {'user_s': float('nan')}, {'system_s': -1},
                           {'elapsed_s': float('inf')}, {'elapsed_s': 0},
                           {'user_s': 0, 'system_s': 0}):
                with self.subTest(change=change):
                    path.write_text(json.dumps(valid | change))
                    with self.assertRaises(ValueError):
                        measure.resources(path)

    def test_thread_runtime_matches_independent_process_cpu_clock(self):
        before = measure.thread_snapshot(os.getpid())
        start = time.process_time_ns()
        while time.process_time_ns() - start < 60_000_000:
            sum(i * i for i in range(1000))
        cpu_ns = time.process_time_ns() - start
        after = measure.thread_snapshot(os.getpid())
        tid = str(os.getpid())
        a, b = before['threads'][tid], after['threads'][tid]
        self.assertEqual(a['start_ticks'], b['start_ticks'])
        self.assertEqual(a['affinity'], sorted(os.sched_getaffinity(0)))
        delta_ns = b['schedstat_ns'][0] - a['schedstat_ns'][0]
        self.assertLess(abs(delta_ns - cpu_ns), 15_000_000)
        ticks = (b['user_ticks'] + b['system_ticks']) - (a['user_ticks'] + a['system_ticks'])
        self.assertLess(abs(ticks / after['clock_ticks'] - cpu_ns / 1e9), 0.03)


if __name__ == '__main__':
    unittest.main()
