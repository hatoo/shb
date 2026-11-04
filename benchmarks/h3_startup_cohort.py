"""Accounting oracle for distinct encrypted HTTP/3 startup connections."""
from collections import Counter

from report_accounting import validate_sample_accounting

PREFIXES = {2: bytes.fromhex('000409010007000680100000'), 6: b'\x02', 10: b'\x03'}


class GetCompletion:
    """A header-only GET may deliver its FIN after its HEADERS event."""
    def __init__(self):
        self.seen = set()
        self.pending = set()

    def receive(self, stream_id, headers, ended, data=b''):
        assert not data, 'unexpected GET body'
        if headers:
            assert stream_id not in self.seen, 'duplicate GET headers'
            self.seen.add(stream_id)
            self.pending.add(stream_id)
        else:
            assert stream_id in self.pending, 'data without pending GET'
        if ended:
            self.pending.remove(stream_id)
        return ended


def inspect_cohort(peers, count, aborts):
    """Return ready peer indices; reject excess work even before the barrier.

    The request total alone cannot prove that every connection started: a fast
    connection may otherwise supply the entire total. Connection IDs and the
    per-peer request ledger must agree independently.
    """
    assert count > 0 and aborts in (0, 1)
    assert len(peers) <= count + aborts, 'unexpected extra connections'
    ids = [p['cid'] for p in peers]
    assert all(ids) and len(set(ids)) == len(ids), 'duplicate connection identity'
    ready, aborted = [], 0
    for index, peer in enumerate(peers):
        prefixes = {}
        for event in peer['events']:
            sid = event['id']
            assert sid in PREFIXES, 'unexpected critical stream'
            assert not event['fin'], 'critical stream closed'
            prefixes[sid] = prefixes.get(sid, b'') + bytes.fromhex(event['data'])
            assert prefixes[sid] == PREFIXES[sid][:len(prefixes[sid])], 'changed prefix'
        requests = peer['requests']
        assert len(requests) <= 1, 'multiple requests from one connection'
        assert len(peer['responses']) <= 1, 'multiple responses to one connection'
        if peer['aborted']:
            aborted += 1
            assert peer['tls'], 'abort must follow the encrypted handshake'
            assert prefixes and prefixes != PREFIXES, 'abort must interrupt startup'
            assert not requests and not peer['responses'], 'work on aborted connection'
        elif requests:
            assert peer['tls'], 'request before TLS completion'
            assert prefixes == PREFIXES, 'request before complete startup'
            ready.append(index)
        else:
            assert not peer['responses'], 'response without a request'
    assert aborted <= aborts, 'unexpected aborted connection'
    assert len(ready) <= count, 'too many successful connections'
    return ready


def release_cohort(peers, count, aborts):
    """Return the exact response cohort, or no peers until everyone is ready."""
    ready = inspect_cohort(peers, count, aborts)
    assert not any(p['responses'] for p in peers), 'response before cohort barrier'
    if len(ready) != count or sum(p['aborted'] for p in peers) != aborts:
        return []
    return ready


def validate_cohort(peers, count, aborts, report):
    ready = inspect_cohort(peers, count, aborts)
    assert len(peers) == count + aborts, 'missing connections'
    assert len(ready) == count, 'missing ready connections'
    assert sum(p['aborted'] for p in peers) == aborts, 'missing startup abort'
    statuses = Counter()
    for index in ready:
        peer = peers[index]
        assert peer['responses'] == peer['requests'], 'missing or mismatched response'
        statuses[str(peer['responses'][0]['status'])] += 1
    validate_sample_accounting(report)
    assert report['requests'] == dict(total=count + aborts, ok=count, errors=aborts,
                                     connectErrors=aborts), report
    assert report['statusCodes'] == dict(statuses), report
