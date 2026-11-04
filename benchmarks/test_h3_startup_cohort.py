"""Adversarial ledgers: aggregate success must never conceal missing peers."""
import copy
import unittest

from h3_startup_cohort import PREFIXES, GetCompletion, release_cohort, validate_cohort


def peer(cid, status=200):
    return dict(cid=cid, tls=True, aborted=False,
                events=[dict(id=sid, data=data.hex(), fin=False)
                        for sid, data in PREFIXES.items()],
                requests=[dict(id=0, status=status)], responses=[])


def report(count=2, aborts=0):
    return dict(requests=dict(total=count + aborts, ok=count, errors=aborts,
                              connectErrors=aborts), statusCodes={'200': count},
                latencySamples=count, latencySeconds={})


class StartupCohortTests(unittest.TestCase):
    def setUp(self):
        self.peers = [peer('a'), peer('b')]

    def finish(self, peers=None, aborts=0, result=None):
        peers = self.peers if peers is None else peers
        for p in peers:
            p['responses'] = copy.deepcopy(p['requests'])
        validate_cohort(peers, 2, aborts, report(aborts=aborts) if result is None else result)

    def test_distinct_complete_connections(self):
        self.assertEqual(release_cohort(self.peers, 2, 0), [0, 1])
        self.finish()

    def test_fast_connection_cannot_supply_missing_peer(self):
        # Mutation of an otherwise successful aggregate: both responses came
        # from the same connection. Counts and status totals still match.
        fast = self.peers[:1]
        fast[0]['requests'].append(dict(id=4, status=200))
        with self.assertRaisesRegex(AssertionError, 'multiple requests'):
            self.finish(fast)

    def test_barrier_does_not_shrink(self):
        self.assertEqual(release_cohort(self.peers[:1], 2, 0), [])
        with self.assertRaisesRegex(AssertionError, 'missing connections'):
            self.finish(self.peers[:1])

    def test_duplicate_identity(self):
        self.peers[1]['cid'] = 'a'
        with self.assertRaisesRegex(AssertionError, 'duplicate connection'):
            self.finish()

    def test_requires_tls_and_complete_open_prefixes(self):
        for mutation in ('tls', 'partial', 'fin', 'duplicate-bytes'):
            with self.subTest(mutation=mutation):
                peers = copy.deepcopy(self.peers)
                if mutation == 'tls':
                    peers[0]['tls'] = False
                elif mutation == 'partial':
                    peers[0]['events'][0]['data'] = '00'
                elif mutation == 'fin':
                    peers[0]['events'][0]['fin'] = True
                else:
                    peers[0]['events'].append(dict(id=6, data='02', fin=False))
                with self.assertRaises(AssertionError):
                    self.finish(peers)

    def test_early_and_missing_response(self):
        self.peers[0]['responses'] = copy.deepcopy(self.peers[0]['requests'])
        with self.assertRaisesRegex(AssertionError, 'before cohort barrier'):
            release_cohort(self.peers, 2, 0)
        with self.assertRaisesRegex(AssertionError, 'missing or mismatched response'):
            validate_cohort(self.peers, 2, 0, report())

    def test_partial_startup_abort_requires_replacement(self):
        aborted = peer('old')
        aborted.update(aborted=True, events=[dict(id=2, data='00', fin=False)], requests=[])
        peers = [aborted] + self.peers
        self.assertEqual(release_cohort(peers[:2], 2, 1), [])
        self.assertEqual(release_cohort(peers, 2, 1), [1, 2])
        self.finish(peers, aborts=1)

    def test_abort_cannot_conceal_completed_work(self):
        self.peers[0]['aborted'] = True
        with self.assertRaisesRegex(AssertionError, 'interrupt startup'):
            release_cohort(self.peers, 2, 1)

    def test_extra_connection_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'extra connections'):
            self.finish(self.peers + [peer('c')])

    def test_samples_errors_and_statuses_remain_exact(self):
        for field in ('latencySamples', 'statusCodes', 'requests'):
            with self.subTest(field=field):
                bad = report()
                bad[field] = {'latencySamples': 1, 'statusCodes': {'503': 2},
                              'requests': dict(total=3, ok=2, errors=1, connectErrors=1)}[field]
                with self.assertRaises((AssertionError, ValueError)):
                    self.finish(result=bad)


class GetCompletionTests(unittest.TestCase):
    def test_separate_fin_completes_once(self):
        gets = GetCompletion()
        self.assertFalse(gets.receive(0, True, False))
        self.assertEqual(gets.pending, {0})
        self.assertFalse(gets.receive(0, False, False))
        self.assertTrue(gets.receive(0, False, True))
        self.assertFalse(gets.pending)
        with self.assertRaises(AssertionError):
            gets.receive(0, False, True)

    def test_combined_headers_and_fin(self):
        gets = GetCompletion()
        self.assertTrue(gets.receive(4, True, True))
        self.assertFalse(gets.pending)

    def test_body_and_duplicate_headers_rejected(self):
        gets = GetCompletion()
        gets.receive(0, True, False)
        with self.assertRaises(AssertionError):
            gets.receive(0, False, True, b'body')
        with self.assertRaises(AssertionError):
            gets.receive(0, True, True)

    def test_fin_on_wrong_stream_cannot_complete_get(self):
        gets = GetCompletion()
        gets.receive(0, True, False)
        with self.assertRaises(AssertionError):
            gets.receive(4, False, True)
        self.assertEqual(gets.pending, {0})


if __name__ == '__main__':
    unittest.main()
