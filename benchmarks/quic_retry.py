"""Replayable contracts for the independent Retry peer (standard library only)."""

from copy import deepcopy

from report_accounting import validate_sample_accounting

CASES = ('no-retry', 'retry', 'drop', 'reorder', 'forged-second')
REQUESTS = 32
PARALLEL = 4


class RetryFailure(ValueError):
    def __init__(self, code, detail):
        self.code = code
        super().__init__(f'{code}: {detail}')


def require(condition, code, detail):
    if not condition:
        raise RetryFailure(code, detail)


def validate_result(row):
    """Check completion independently of the client's success flag or wire counts."""
    case = row['case']
    require(case in CASES, 'workload', case)
    require(row['client_exit'] == 0, 'client-exit', row['client_exit'])
    require(not row['failures'], 'peer-failure', row['failures'])
    ledger, report = row['ledger'], row['report']
    require(ledger['handshakes'] == 1 and ledger['peers'] == 1,
            'handshake', (ledger['handshakes'], ledger['peers']))
    require(isinstance(report, dict), 'missing-report', report)
    require(report['requests'] == dict(total=REQUESTS, ok=REQUESTS, errors=0, connectErrors=0),
            'request-budget', report['requests'])
    require('latencySamples' in report, 'missing-samples', 'latencySamples absent')
    require(type(report['latencySamples']) is int and report['latencySamples'] == REQUESTS,
            'sample-count', report['latencySamples'])
    require(report['statusCodes'] == {'200': REQUESTS}, 'status-count', report['statusCodes'])
    try:
        validate_sample_accounting(report)
    except (KeyError, ValueError) as exc:
        raise RetryFailure('report-accounting', str(exc)) from exc
    require(report['protocol'] == 'HTTP/3' and report['threads'] == 1
            and report['connections'] == 1, 'client-configuration', report)
    require(sorted(ledger['streams']) == list(range(0, REQUESTS * 4, 4)),
            'request-ids', ledger['streams'])
    require(ledger['responses'] == ledger['streams'], 'response-ids', ledger['responses'])
    initials, retries, deliveries = ledger['initials'], ledger['retries'], ledger['deliveries']
    require(initials and initials[0]['token_length'] == 0, 'first-initial', initials)
    require(all(type(p['pn']) is int and p['pn'] >= 0 and p['wire_bytes'] >= 1200
                for p in initials), 'initial-packet', initials)
    require([p['seq'] for p in initials] == sorted({p['seq'] for p in initials}),
            'receive-order', initials)
    for packet in initials:
        offset = 0
        for chunk in packet['crypto']:
            require(chunk['offset'] == offset and chunk['length'] > 0
                    and len(chunk['sha256']) == 64, 'crypto-layout', packet)
            offset += chunk['length']
    require(initials[0]['crypto'], 'crypto-missing', initials[0])
    if case == 'no-retry':
        require(not retries and all(p['token_length'] == 0 for p in initials),
                'unexpected-retry', ledger)
    else:
        kinds = ['forged', 'authentic', 'second'] if case == 'forged-second' else ['authentic']
        require([r['kind'] for r in retries] == kinds, 'retry-schedule', retries)
        authentic = next(r for r in retries if r['kind'] == 'authentic')
        require(authentic['token_length'] == 256 and authentic['integrity_valid'] is True,
                'retry-token', authentic)
        require(len(initials) >= 2, 'retry-initial', initials)
        post = initials[1:]
        require(all(p['token_length'] == authentic['token_length']
                    and p['token_sha256'] == authentic['token_sha256'] for p in post),
                'token-identity', post)
        # Once the server answers, shb adopts its new source CID. Only the
        # withheld first flight and its PTO replacement still target the Retry CID.
        before_reply = post[:2] if case in ('drop', 'reorder') else post[:1]
        require(all(p['dcid'] == authentic['scid'] for p in before_reply), 'retry-cid', before_reply)
        require(initials[0]['seq'] < authentic['seq'] < post[0]['seq'],
                'retry-order', (initials, retries))
        require(post[0]['crypto'] == initials[0]['crypto'], 'retry-crypto', post[0])
        require(all(a['pn'] < b['pn'] for a, b in zip(initials, post)),
                'packet-number', initials)
        if case in ('drop', 'reorder'):
            require(len(post) >= 2, 'missing-retransmission', post)
            require(post[1]['crypto'] == post[0]['crypto'], 'retransmit-crypto', post[:2])
        if case == 'forged-second':
            forged, _, second = retries
            require(forged['integrity_valid'] is False and second['integrity_valid'] is True
                    and forged['token_sha256'] != authentic['token_sha256']
                    and second['token_sha256'] != authentic['token_sha256']
                    and second['scid'] != authentic['scid'], 'retry-forgeries', retries)
            require(initials[0]['seq'] < forged['seq'] < authentic['seq']
                    < post[0]['seq'] < second['seq'], 'forgery-order', retries)

    expected = list(range(len(initials)))
    actions = ['deliver'] * len(initials)
    if case in ('drop', 'reorder'):
        actions[1] = case
        if case == 'drop':
            expected.remove(1)
        else:
            expected[1:3] = [2, 1]
    require([p['action'] for p in initials] == actions, 'impairment', initials)
    require([d['initial'] for d in deliveries] == expected, 'delivery-order', deliveries)
    require([d['seq'] for d in deliveries] == sorted({d['seq'] for d in deliveries})
            and all(d['seq'] > initials[d['initial']]['seq'] for d in deliveries),
            'delivery-sequence', deliveries)
    if case == 'forged-second':
        require(retries[-1]['seq'] < next(d['seq'] for d in deliveries if d['initial'] == 1),
                'second-retry-order', deliveries)
    require(all(row['cleanup'].get(key) is True for key in (
        'client_reaped', 'transport_closed', 'peers_closed', 'callbacks_cancelled')),
        'cleanup', row['cleanup'])


def negative_controls(row):
    """Each damaged copy must fail for the intended reason; require a healthy input."""
    validate_result(row)
    controls = []

    def check(name, code, mutate):
        changed = deepcopy(row)
        mutate(changed)
        try:
            validate_result(changed)
        except RetryFailure as exc:
            require(exc.code == code, 'wrong-control-failure', (name, code, exc.code))
        else:
            raise RetryFailure('undetected-control', name)
        controls.append(dict(name=name, rejected_by=code))

    check('missing samples', 'missing-samples', lambda r: r['report'].pop('latencySamples'))
    for delta in [-1, 1]:
        check(f'samples {delta:+}', 'sample-count',
              lambda r: r['report'].__setitem__('latencySamples', REQUESTS + delta))
    check('wrong budget', 'request-budget',
          lambda r: r['report']['requests'].__setitem__('total', REQUESTS + 1))
    check('lost status', 'status-count',
          lambda r: r['report']['statusCodes'].__setitem__('200', REQUESTS - 1))
    check('duplicate request', 'request-ids',
          lambda r: r['ledger']['streams'].__setitem__(1, 0))
    check('missing response', 'response-ids', lambda r: r['ledger']['responses'].pop())
    check('empty Initial CRYPTO', 'crypto-missing',
          lambda r: r['ledger']['initials'][0].__setitem__('crypto', []))
    check('missing delivery', 'delivery-order', lambda r: r['ledger']['deliveries'].pop())
    check('delivery before receive', 'delivery-sequence',
          lambda r: r['ledger']['deliveries'][0].__setitem__('seq', 0))
    for key in row['cleanup']:
        check(f'unclean {key}', 'cleanup', lambda r: r['cleanup'].__setitem__(key, False))
    if row['case'] == 'no-retry':
        check('unexpected token', 'unexpected-retry',
              lambda r: r['ledger']['retries'].append({}))
    else:
        check('missing Retry', 'retry-schedule', lambda r: r['ledger']['retries'].clear())
        for field, value in [('token_length', 0), ('token_sha256', '0' * 64)]:
            check(f'changed {field}', 'token-identity',
                  lambda r: r['ledger']['initials'][1].__setitem__(field, value))
        check('wrong destination CID', 'retry-cid',
              lambda r: r['ledger']['initials'][1].__setitem__('dcid', '00'))
        check('reset packet number', 'packet-number',
              lambda r: r['ledger']['initials'][1].__setitem__('pn', 0))
        check('missing retry CRYPTO', 'retry-crypto',
              lambda r: r['ledger']['initials'][1].__setitem__('crypto', []))
    if row['case'] in ('drop', 'reorder'):
        check('changed retransmitted CRYPTO', 'retransmit-crypto',
              lambda r: r['ledger']['initials'][2]['crypto'][0].__setitem__('sha256', '0' * 64))
        check('missing impairment', 'impairment',
              lambda r: r['ledger']['initials'][1].__setitem__('action', 'deliver'))
    if row['case'] == 'forged-second':
        check('valid supposed forgery', 'retry-forgeries',
              lambda r: r['ledger']['retries'][0].__setitem__('integrity_valid', True))
        check('late second Retry', 'second-retry-order',
              lambda r: r['ledger']['retries'][-1].__setitem__('seq', 10**9))
    return controls
