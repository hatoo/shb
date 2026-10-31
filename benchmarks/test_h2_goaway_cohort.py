"""Hostile report tests for the aggregate measurement oracle."""
from copy import deepcopy
from pathlib import Path
import json
import tempfile
import unittest

import h2_goaway_cohort as cohort


class CohortOracle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.metadata = dict(requests_per_child=2053, start_ns=1_000_000_000,
                             end_ns=21_000_000_000, children=[])
        self.report = dict(requests=dict(total=2053, ok=2053, errors=0, connectErrors=0),
                           latencySamples=2053, statusCodes={"200": 2053}, protocol="HTTP/2",
                           threads=1, connections=1, durationSeconds=18, requestsPerSec=2053/18,
                           bytesSent=5949, bytesReceived=3000,
                           latencySeconds=dict(min=.1, mean=.5, max=1,
                               percentiles={k: v / 100 for k, v in zip(
                                   ["p10", "p25", "p50", "p75", "p90", "p95", "p99", "p99.9", "p99.99"],
                                   [10, 25, 50, 75, 90, 95, 99, 99.9, 99.99])}))
        self.ledger = [dict(headers=h, accepted=a, rejected=h-a, complete_bodies=a,
                            body_bytes=0, bytes_read=2000, bytes_sent=1000,
                            client_goaway_bytes=17, goaways=g)
                       for h, a, g in [(2053, 1024, 1), (1029, 1024, 1), (5, 5, 0)]]
        self.ledger.append(dict(done=2053, connections=3))
        for i in range(8):
            address = f"127.0.0.1:{30000+i}"
            self.metadata["children"].append(dict(index=i, address=address, peer_core=1+i%2,
                  client_exit=0, peer_exit=0, launch_ns=1_000_000_001+i,
                  complete_ns=21_000_000_000))
            report = dict(self.report, url="http://" + address + "/")
            (self.folder / f"child-{i}.json").write_text(json.dumps(report))
            (self.folder / f"child-{i}.peer.raw").write_text(address + "\n" +
                        "\n".join(json.dumps(x) for x in self.ledger) + "\n")
            (self.folder / f"child-{i}.cpu").write_text("1 1 19 4096\n")
            (self.folder / f"child-{i}.peer.cpu").write_text(".1 .1 20 1024\n")

    def result(self):
        return cohort.validate_cohort(self.folder, self.metadata)

    def test_common_interval_not_sum_of_overlapping_rates(self):
        result = self.result()
        self.assertEqual(result["requests"], 16424)
        self.assertEqual(result["latency_samples"], 16424)
        self.assertEqual(result["requests_per_sec"], 16424/20)
        self.assertEqual(result["client_cores"], .8)
        self.assertEqual(result["peer_cores"], {"1": .04, "2": .04})
        self.assertNotEqual(result["requests_per_sec"], sum(x["report"]["requestsPerSec"] for x in result["rows"]))

    def test_missing_or_duplicate_child(self):
        original = deepcopy(self.metadata)
        for children in [original["children"][:-1], original["children"][:-1] + [original["children"][0]]]:
            with self.subTest(children=len(children)):
                self.metadata["children"] = children
                with self.assertRaises(ValueError):
                    self.result()

    def test_missing_malformed_empty_report(self):
        path = self.folder / "child-7.json"
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.result()
        for data in ["", "{broken", "{}"]:
            path.write_text(data)
            with self.subTest(data=data), self.assertRaises((ValueError, KeyError)):
                self.result()

    def test_nonzero_client_or_peer_exit(self):
        for key in ["client_exit", "peer_exit"]:
            self.metadata["children"][7][key] = 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()
            self.metadata["children"][7][key] = 0

    def test_duplicate_peer_or_changed_cpu_layout(self):
        original = deepcopy(self.metadata)
        for key, value in [("address", "127.0.0.1:30000"), ("peer_core", 1)]:
            self.metadata = deepcopy(original)
            self.metadata["children"][7][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()

    def test_cohort_interval_cannot_end_before_or_after_last_child(self):
        for end in [20_000_000_999, 21_000_000_001]:
            self.metadata["end_ns"] = end
            with self.subTest(end=end), self.assertRaises(ValueError):
                self.result()

    def test_invalid_reports(self):
        path = self.folder / "child-7.json"
        original = json.loads(path.read_text())
        cases = [
            ("requests", dict(total=2053, ok=2052, errors=1, connectErrors=0)),
            ("requests", dict(total=2052, ok=2052, errors=0, connectErrors=0)),
            ("latencySamples", 2052), ("statusCodes", {"200": 2052, "500": 1}),
            ("bytesSent", 6000), ("bytesReceived", 2999), ("threads", 2),
            ("protocol", "HTTP/1.1"), ("requestsPerSec", float("nan")),
            ("durationSeconds", 0), ("durationSeconds", 20), ("url", "http://wrong/"),
        ]
        for key, value in cases:
            path.write_text(json.dumps(dict(original, **{key: value})))
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.result()

    def test_latency_corruption(self):
        path = self.folder / "child-7.json"
        original = json.loads(path.read_text())
        for key, value in [("min", -.1), ("mean", float("nan")), ("mean", 2), ("max", .2)]:
            report = deepcopy(original)
            report["latencySeconds"][key] = value
            path.write_text(json.dumps(report))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()
        for key, value in [("p50", .99), ("p99.99", 2)]:
            report = deepcopy(original)
            report["latencySeconds"]["percentiles"][key] = value
            path.write_text(json.dumps(report))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()

    def test_ledger_corruption(self):
        path = self.folder / "child-7.peer.raw"
        for key, value in [("headers", 2052), ("accepted", 1023), ("rejected", 0),
                           ("complete_bodies", 1023), ("body_bytes", 1),
                           ("goaways", 0), ("bytes_read", -1)]:
            ledger = deepcopy(self.ledger)
            ledger[0][key] = value
            path.write_text("127.0.0.1:30007\n" + "\n".join(map(json.dumps, ledger)))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()
        for ledger in [self.ledger[:-1], self.ledger[1:], self.ledger + [self.ledger[-1]]]:
            path.write_text("127.0.0.1:30007\n" + "\n".join(map(json.dumps, ledger)))
            with self.subTest(length=len(ledger)), self.assertRaises((ValueError, KeyError)):
                self.result()

    def test_invalid_clock_boundaries(self):
        for key, value in [("launch_ns", 0), ("complete_ns", 22_000_000_000)]:
            original = self.metadata["children"][7][key]
            self.metadata["children"][7][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()
            self.metadata["children"][7][key] = original

    def test_missing_or_invalid_cpu_report(self):
        path = self.folder / "child-7.cpu"
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.result()
        for data in ["", "nan 0 19 1", "-1 0 19 1"]:
            path.write_text(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.result()


if __name__ == "__main__":
    unittest.main(verbosity=2)
