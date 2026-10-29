"""Guard exact byte/FIN validation separately from the live encrypted runs."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'timer_oracle', Path(__file__).with_name('check-quic-timer.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class CompletenessTests(unittest.TestCase):
    def stream(self, data=b'abc', fin=True, offset=0):
        stream = oracle.StreamBytes()
        stream.add(dict(offset=offset, data=data.hex(), fin=fin))
        return stream

    def test_exact_complete(self):
        oracle.complete(self.stream(), b'abc', 'test')

    def test_missing_fin(self):
        with self.assertRaisesRegex(AssertionError, 'FIN'):
            oracle.complete(self.stream(fin=False), b'abc', 'test')

    def test_missing_bytes(self):
        with self.assertRaisesRegex(AssertionError, 'incomplete bytes'):
            oracle.complete(self.stream(data=b'bc', offset=1), b'abc', 'test')

    def test_same_length_corruption(self):
        with self.assertRaisesRegex(AssertionError, 'corrupt receipt/bytes'):
            oracle.complete(self.stream(data=b'abX'), b'abc', 'test')

    def test_extra_bytes(self):
        with self.assertRaisesRegex(AssertionError, 'FIN'):
            oracle.complete(self.stream(data=b'abcd'), b'abc', 'test')

    def test_reordered_retransmissions(self):
        stream = self.stream(data=b'bc', offset=1)
        for _ in range(2):
            stream.add(dict(offset=0, data=b'ab'.hex(), fin=False))
        oracle.complete(stream, b'abc', 'test')

    def test_changed_retransmission(self):
        stream = self.stream()
        with self.assertRaisesRegex(AssertionError, 'changed STREAM byte'):
            stream.add(dict(offset=0, data=b'X'.hex(), fin=False))

    def test_receipt_depends_on_all_bytes(self):
        self.assertNotEqual(oracle.receipt(b'abX'), oracle.receipt(b'abc'))
        self.assertNotEqual(oracle.receipt(b'abc'), oracle.receipt(b'abcd'))


if __name__ == '__main__':
    unittest.main()
