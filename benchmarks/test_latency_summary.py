"""Compile the real summary fixture; check it with independent Python oracles.

Run with unittest discovery. RUSTUP_TOOLCHAIN=1.91.0 also exercises the MSRV.
No third-party modules, network services, or timing acceptance gates are used.
"""

import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAX = (1 << 64) - 1
BOUNDARIES = [0, 1, (1 << 32) - 1, 1 << 32, (1 << 32) + 1,
              (1 << 53) - 1, 1 << 53, (1 << 53) + 1, MAX - 1, MAX]
PATTERNS = ["random", "duplicates", "sorted", "reverse", "equal", "skewed", "runs",
            "wide", "wide-duplicates", "wide-sorted", "wide-reverse", "wide-equal",
            "boundaries"]


def generate(pattern, length, seed):
    values = []
    state = seed
    for i in range(length):
        state ^= (state << 13) & MAX
        state ^= state >> 7
        state ^= (state << 17) & MAX
        values.append({
            "random": state % 1_000_000_000,
            "duplicates": state % 32 * 1000,
            "sorted": i,
            "reverse": length - i,
            "equal": 123_456,
            "skewed": state % (1_000_000_000 if state % 1000 == 0 else 1000),
            "runs": i % max(length // 16, 1),
            "wide": state,
            "wide-duplicates": MAX - state % 32,
            "wide-sorted": MAX - (length - 1 - i),
            "wide-reverse": MAX - i,
            "wide-equal": MAX,
            "boundaries": BOUNDARIES[i % len(BOUNDARIES)],
        }[pattern])
    return values


def expected_bits(values):
    if not values:
        return []
    ordered = sorted(values)
    length = len(ordered)
    # Sum with Python's unbounded integer, then preserve the specified f64
    # conversion/division order. Ranks are defined here, not read from Rust.
    seconds = [float(ordered[0]) / 1e9, float(sum(ordered)) / float(length) / 1e9,
               float(ordered[-1]) / 1e9]
    for percentile in [10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0, 99.9, 99.99]:
        rank = min(int(percentile / 100.0 * float(length)), length - 1)
        seconds.append(float(ordered[rank]) / 1e9)
    return [struct.unpack("<Q", struct.pack("<d", value))[0] for value in seconds]


def corpus_bytes(values):
    return b"".join(struct.pack("<Q", value) for value in values)


class LatencySummary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="shb-latency-summary-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        cls.source = (ROOT / "benchmarks/latency-summary.rs").read_text()
        cls.binaries = cls.compile_variant("fixture", cls.source)

    @classmethod
    def compile_variant(cls, name, source):
        folder = cls.folder / name
        (folder / "benchmarks").mkdir(parents=True)
        (folder / "src").mkdir()
        shutil.copyfile(ROOT / "src/stats.rs", folder / "src/stats.rs")
        harness = folder / "benchmarks/latency-summary.rs"
        harness.write_text(source)
        binaries = {}
        for profile, flags in [("debug", []), ("release", ["-O", "-C", "lto=fat",
                                                            "-C", "codegen-units=1"])]:
            binary = folder / profile
            result = subprocess.run(["rustc", "--edition=2024", "-D", "warnings", *flags,
                                     str(harness), "-o", str(binary)],
                                    capture_output=True, text=True, timeout=120)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            binaries[profile] = binary
        return binaries

    def run_fixture(self, binary, pattern="random", length=0, repeats=2, seed=336,
                    warmups=1, extra=None):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("SUMMARY_")}
        if warmups is not None:
            env["SUMMARY_WARMUPS"] = str(warmups)
        env.update({key: str(value) for key, value in (extra or {}).items()})
        return subprocess.run([str(binary), pattern, str(length), str(repeats), str(seed)],
                              env=env, capture_output=True, text=True, timeout=30)

    def assert_report(self, result, values, pattern="random", seed=336,
                      repeats=2, source="generated"):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), repeats)
        expected = expected_bits(values)
        for iteration, row in enumerate(rows):
            for counter in ["wall_ns", "cpu_ns"]:
                self.assertIs(type(row[counter]), int)
                self.assertGreaterEqual(row.pop(counter), 0)
            self.assertEqual(row, dict(pattern=pattern, len=len(values), seed=seed,
                                       input=source, iteration=iteration, allocations=0,
                                       allocated_bytes=0, summary_bits=expected))
        return rows

    def assert_failure(self, result, message):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn(message, result.stderr)

    def test_patterns_and_selection_boundaries(self):
        for profile, binary in self.binaries.items():
            for pattern in PATTERNS:
                lengths = [0, 1, 7, 1023, 1024, 1025]
                if pattern in ["wide", "wide-duplicates", "boundaries"]:
                    lengths += [16383, 16384, 16385]
                for length in lengths:
                    with self.subTest(profile=profile, pattern=pattern, length=length):
                        values = generate(pattern, length, 336)
                        result = self.run_fixture(binary, pattern, length)
                        self.assert_report(result, values, pattern)

    def test_save_and_replay_exact_bytes(self):
        for profile, binary in self.binaries.items():
            for pattern in PATTERNS:
                with self.subTest(profile=profile, pattern=pattern):
                    path = self.folder / f"{profile}-{pattern}.bin"
                    copy = path.with_suffix(".copy")
                    values = generate(pattern, 1025, MAX)
                    saved = self.run_fixture(binary, pattern, len(values), seed=MAX,
                                             extra={"SUMMARY_SAVE_INPUT": path})
                    self.assert_report(saved, values, pattern, seed=MAX)
                    self.assertEqual(path.read_bytes(), corpus_bytes(values))
                    # Deliberately different pattern and seed: only the corpus
                    # controls samples, and output labels it as replayed input.
                    replay = self.run_fixture(binary, length=len(values),
                                              extra={"SUMMARY_INPUT": path,
                                                     "SUMMARY_SAVE_INPUT": copy})
                    self.assert_report(replay, values, source="replay")
                    self.assertEqual(path.read_bytes(), copy.read_bytes())

    def test_handwritten_totals_orders_and_empty_corpus(self):
        cases = [[], [MAX], [0x0102030405060708], BOUNDARIES]
        for boundary in [1 << 32, 1 << 53, 1 << 64]:
            cases += [[boundary // 2, boundary // 2 + delta] for delta in [-1, 0, 1]]
        cases += [[MAX] * 16385, BOUNDARIES * 1640,
                  [0] + [MAX] * 1024 + [1], [42] * 16384 + [0, MAX, 1]]
        path = self.folder / "handwritten.bin"
        for profile, binary in self.binaries.items():
            for index, values in enumerate(cases):
                for order, samples in [("original", values), ("sorted", sorted(values)),
                                       ("reverse", sorted(values, reverse=True))]:
                    with self.subTest(profile=profile, case=index, order=order):
                        path.write_bytes(corpus_bytes(samples))
                        result = self.run_fixture(binary, length=len(samples),
                                                  extra={"SUMMARY_INPUT": path})
                        self.assert_report(result, samples, source="replay")

    def test_invalid_corpus_sizes(self):
        path = self.folder / "invalid-size.bin"
        for profile, binary in self.binaries.items():
            for size, length in [(0, 1), (7, 1), (9, 1), (8, 0), (8, 2), (16, 1)]:
                with self.subTest(profile=profile, bytes=size, length=length):
                    path.write_bytes(b"\0" * size)
                    result = self.run_fixture(binary, length=length,
                                              extra={"SUMMARY_INPUT": path})
                    self.assert_failure(result, "input byte length mismatch")
            self.assert_failure(self.run_fixture(binary, extra={
                "SUMMARY_INPUT": self.folder / "missing.bin"}), "open input corpus")

    def test_refuses_overwrite_even_when_input_equals_output(self):
        path = self.folder / "preserved.bin"
        data = corpus_bytes([1, MAX])
        path.write_bytes(data)
        link = self.folder / "output-link.bin"
        link.symlink_to(path)
        for profile, binary in self.binaries.items():
            for output in [path, link]:
                for replay in [False, True]:
                    with self.subTest(profile=profile, output=output.name, replay=replay):
                        extra = {"SUMMARY_SAVE_INPUT": output}
                        if replay:
                            extra["SUMMARY_INPUT"] = path
                        self.assert_failure(self.run_fixture(binary, length=2, extra=extra),
                                            "create new output corpus")
                        self.assertEqual(path.read_bytes(), data)

    def test_invalid_arguments_before_creating_output(self):
        maximum = 2 * sys.maxsize + 1  # Rust usize on the native target.
        cases = [({"pattern": "invalid"}, "unknown pattern"),
                 ({"pattern": 'bad"json'}, "unknown pattern"),
                 ({"seed": 0}, "seed must be nonzero"),
                 ({"length": maximum // 8 + 1}, "input byte length overflow"),
                 ({"length": sys.maxsize // 8 + 1}, "input exceeds Vec capacity"),
                 ({"repeats": maximum}, "iteration count overflow"),
                 ({"length": -1}, "ParseIntError"),
                 ({"length": maximum + 1}, "ParseIntError"),
                 ({"warmups": "invalid"}, "ParseIntError")]
        output = self.folder / "invalid-arguments.bin"
        for profile, binary in self.binaries.items():
            for args, message in cases:
                with self.subTest(profile=profile, args=args):
                    result = self.run_fixture(binary, **args,
                                              extra={"SUMMARY_SAVE_INPUT": output})
                    self.assert_failure(result, message)
                    self.assertFalse(output.exists())

    def test_repeats_and_warmups(self):
        for profile, binary in self.binaries.items():
            for repeats, warmups in [(0, 0), (0, 2), (1, 0), (3, 2), (1, None)]:
                with self.subTest(profile=profile, repeats=repeats, warmups=warmups):
                    result = self.run_fixture(binary, length=7, repeats=repeats, warmups=warmups)
                    self.assert_report(result, generate("random", 7, 336), repeats=repeats)

    def test_u64_oracle_mutant_fails_only_on_wide_totals(self):
        needle = "sorted.iter().map(|&ns| u128::from(ns)).sum::<u128>()"
        self.assertEqual(self.source.count(needle), 1)
        mutants = self.compile_variant("u64-oracle", self.source.replace(
            needle, "sorted.iter().copied().sum::<u64>()"))
        for profile, binary in mutants.items():
            with self.subTest(profile=profile):
                ordinary = self.run_fixture(binary, length=32)
                self.assert_report(ordinary, generate("random", 32, 336))
                wide = self.run_fixture(binary, "wide-equal", 2)
                self.assert_failure(wide, "overflow" if profile == "debug" else "summary bits changed")

    def test_checks_multiset_during_warmup_before_reset(self):
        needle = "let summary_bits = bits(&summary);"
        self.assertEqual(self.source.count(needle), 1)
        mutants = self.compile_variant("corrupt-warmup", self.source.replace(
            needle, "if iteration == 0 && samples.len() == 1024 { samples[2] = samples[3]; }\n"
            + needle))
        for profile, binary in mutants.items():
            with self.subTest(profile=profile):
                self.assert_report(self.run_fixture(binary, length=1), generate("random", 1, 336))
                self.assert_failure(self.run_fixture(binary, "sorted", 1024),
                                    "sample multiset changed")

    def test_rejects_allocations_inside_measured_call(self):
        needle = "black_box(stats::latency_summary(black_box(samples)))"
        self.assertEqual(self.source.count(needle), 1)
        mutants = self.compile_variant("allocate", self.source.replace(
            needle, "if samples.len() == 2 { black_box(Vec::<u8>::with_capacity(8)); }\n" + needle))
        for profile, binary in mutants.items():
            with self.subTest(profile=profile):
                self.assert_report(self.run_fixture(binary, length=1), generate("random", 1, 336))
                self.assert_failure(self.run_fixture(binary, length=2), "summary allocated")


if __name__ == "__main__":
    unittest.main()
