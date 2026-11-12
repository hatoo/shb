"""Exercise the real measurement supervisor across normal/failing processes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class SupervisorTests(unittest.TestCase):
    def run_child(self, source):
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / 'usage.json'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('measure-process.py')),
                                     str(result_path), sys.executable, '-c', source],
                                    input='input-sentinel\n', capture_output=True, text=True, timeout=10)
            usage = json.loads(result_path.read_text())
            self.assertEqual(int(result_path.with_suffix('.pid').read_text()), usage['pid'])
            self.assertGreater(usage['elapsed_s'], 0)
            self.assertGreater(usage['user_s'] + usage['system_s'], 0)
            self.assertGreater(usage['max_rss_kib'], 0)
            return result, usage

    def test_preserves_input_output_and_collects_child_cpu(self):
        result, usage = self.run_child('import sys; print(sys.stdin.readline().strip()); '
                                       'print("stderr-sentinel", file=sys.stderr); '
                                       'sum(i*i for i in range(1000000))')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(usage['exit'], 0)
        self.assertEqual(result.stdout, 'input-sentinel\n')
        self.assertEqual(result.stderr, 'stderr-sentinel\n')

    def test_preserves_failure(self):
        result, usage = self.run_child('import sys; sys.exit(7)')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(usage['exit'], 7)

    def test_records_signal_as_signal(self):
        result, usage = self.run_child('import os,signal; os.kill(os.getpid(), signal.SIGTERM)')
        self.assertEqual(result.returncode, 143)
        self.assertEqual(usage['exit'], -15)

    def test_refuses_to_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'usage.json'
            output.write_text('retained\n')
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('measure-process.py')),
                                     str(output), sys.executable, '-c', 'print("must not run")'],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertEqual(output.read_text(), 'retained\n')


if __name__ == '__main__':
    unittest.main()
