# Encrypted HTTP/3 startup cohorts

`-n N -c N` alone does not establish that every connection completed startup: a
fast peer can supply multiple requests while another is still connecting. The
independent aioquic startup oracle has a response barrier for this check:

```sh
python3 -m unittest discover -s benchmarks -p 'test_h3_startup_cohort.py'
python3 benchmarks/check-h3-startup-credit.py --shb ./target/release/shb --cohort 8
```

Use Python with `aioquic==1.3.0` installed. Each connection must complete TLS with
ALPN h3, send the exact control and both QPACK prefixes without FIN, and queue
one complete GET before any response is sent. The ledger checks distinct
original destination connection IDs, one request and response per peer, mixed
200/503 statuses, exact error totals, and the client's explicit latency-sample
count. It does not export individual latency samples or measure throughput.

All five existing startup cases also run in cohort mode: ordinary credit,
one-byte credit, five-byte credit, packet loss followed by a new-packet-number
retry and late duplicate originals, and a partial-startup close followed by a
replacement connection. In the last case, `N+1` attempts account for one expected
connect error while still requiring `N` successful, distinct peers.

The barrier expires after five seconds (`--barrier-timeout` can change this to
a positive value below ten). Failure diagnostics include the peer ledger,
ready indices and observed connection count. The expected cohort never shrinks.
Adversarial unit fixtures reject a fast connection supplying the entire total,
duplicate identities, incomplete/TLS-less startup, early or missing responses,
closed critical streams, and inconsistent request/status/sample counts.

The required CI job keeps the original single-connection cases and adds an
eight-connection cohort plus the adversarial tests. It retains both wire-ledger
JSON artifacts. Baseline and candidate performance experiments can reuse this
oracle to establish equivalent completed work; passing it does not establish
a performance improvement.
