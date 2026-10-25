"""Shared checks for reports used by complete-upload benchmark validators."""


def validate_sample_accounting(report):
    """Require an explicit live count; never infer missing samples from successes.

    Keep the count separate from peer body/END_STREAM ledgers and raw samples.
    Older clients without this field cannot pass this validation.
    """
    def count(value, name):
        if type(value) is not int or value < 0:
            raise ValueError(f'{name} must be a nonnegative integer: {value!r}')
        return value

    requests = report['requests']
    ok = count(requests['ok'], 'requests.ok')
    errors = count(requests['errors'], 'requests.errors')
    total = count(requests['total'], 'requests.total')
    samples = count(report['latencySamples'], 'latencySamples')
    statuses = sum(count(n, 'status count') for n in report['statusCodes'].values())
    if samples != ok or statuses != ok or total != ok + errors:
        raise ValueError(f'inconsistent request/status/sample counts: {report}')
    latency = report['latencySeconds']
    if (ok == 0 and latency is not None) or (ok > 0 and not isinstance(latency, dict)):
        raise ValueError(f'latency summary does not match sample count: {report}')
