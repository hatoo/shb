# Bounded HTTP/2 duration drain

Validated 2026-11-25 against baseline `d29fae1`. This is a correctness and
benchmark-accounting feature, with no throughput improvement claim.

The default `-z` mode stops at the deadline. A peer holding two old response
tails per connection demonstrated why matching reported totals and sample
counts alone does not establish a complete response drain: the old mode could
close with eight tails open and 98–128 more peer-accepted requests than reported
completions at four connections, 32 streams and 250ms.

`--http2 -z 250ms --drain-timeout 3s` stops opening streams and reconnecting at
the issuing deadline, then services outstanding responses, uploads and control
frames until completion or the drain bound. Outstanding requests and refusals
that cannot be retried become errors, without synthetic success samples. The
original request timestamps and kernel I/O retirement barriers are retained.
Counted runs and default cutoff behavior remain available.

Elapsed time and request rate include the drain. The opt-in path also checks a
monotonic deadline while starting requests and processing completions. Any
performance comparison must use the same mode and bounds on both binaries.

## Validation

- Debug and release: 640 unit tests and 78 end-to-end tests pass per profile;
  two existing external QUIC tests remain ignored.
- Rust 1.91 unit suite and production Clippy pass; stable formatting and strict
  all-target Clippy pass.
- The new raw-wire matrix has 36 cases across cleartext/TLS and one/two workers:
  complete and partial bodies, missing final bytes, reset/refusal, GOAWAY,
  disconnect, credit-blocked 64KiB uploads, request timeout, and default cutoff.
  Peer request counts reconcile with successes, errors, statuses and samples.
  No new streams or reconnects appear after the held responses are released.
- Unit tests cover delayed timer observation, retry settlement, exact original
  timestamps, deadline overflow, and a real blocked send canceled before its
  buffer is reused. Existing stale-CQE and connection-retirement tests pass.
- Independent hyper-h2 verification passes with one and two workers: 3,208
  exact samples in the final checker run, complete held bodies and final PING
  acknowledgments. A wrapper removing only the drain option fails the same
  oracle with incomplete response ledgers, as expected.
- The fixed hfast persistent-pin diagnostic peer from
  [hfast PR101](https://github.com/hatoo/hfast/pull/101) independently verifies
  1,043,313 requests across four cleartext/TLS, one/two-worker cases. All 16
  close ledgers have zero pending responses/pins and accepted counts equal
  client completions and samples. Each 250ms issuing phase finishes after the
  held one-second response tails, with zero request/connect errors.
- Eight namespace trials (including warmups) verify 10,882,219 shb samples and
  11,667,638 fixed xdp-http control samples, with zero unexpected errors or
  dispatch drops. All 256 shb connection-close ledgers match. The xdp client
  starts, completions and samples match; its final server fence can race runner
  teardown and is not claimed here.

The namespace checks use WSL/veth, generic/SKB XDP with copy mode, offloads off,
64 connections × 32 streams, 13-byte bodies, one/two client workers on physical
CPUs 17/19 and eight fixed server workers on 0,2,...,14. A new wrapper adds the
drain flag to the frozen candidate; shared runner/configuration are unchanged.
These are correctness checks with a traced server, not performance evidence.
An early negative-control check also overlapped namespace startup; timing from
this validation must not be used for an optimization claim.

Run the committed independent check with a binary built from this revision:

```sh
python3 -m venv /tmp/h2-drain-venv
/tmp/h2-drain-venv/bin/pip install h2==4.3.0
/tmp/h2-drain-venv/bin/python benchmarks/check-h2-duration-drain.py \
  --shb ./target/release/shb --output /tmp/new-h2-drain-result.json
```

The required `ci` workflow runs the same checker and retains its ledgers and
binary digest. Local experiment C456 stores detailed logs and binary/source
bindings under `optimization-results/c456-h2-duration-drain-20261125/`; raw
namespace output is under xdp-http's `benchmark-results/c456-drain-validation/`.
The separate C454 stream-storage candidate remains experimental until compared
against its own baseline with this same drain behavior on both revisions.
