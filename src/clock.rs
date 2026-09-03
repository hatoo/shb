//! The clock every latency in a run is measured against
//!
//! One request costs shb a few hundred instructions, and two of the reads that
//! make it up are the timestamps at either end of that request. Asking the
//! kernel for the time twice per request was 15% of the worker's userspace at
//! full HTTP/2 multiplexing, where there is little else left to pay for.
//!
//! `minstant::Instant` reads the timestamp counter instead, which is a register
//! rather than a call into the vDSO. It is a drop-in for the standard one -
//! same methods, same ordering, same arithmetic with `Duration` - and where the
//! counter cannot be trusted (anything but Linux on x86, or a CPU without an
//! invariant TSC) it falls back to exactly what we had before.
//!
//! Nothing here reaches the kernel: io_uring is handed relative timeouts, never
//! an absolute deadline, so there is no clock domain to agree on.
pub use minstant::Instant;

// Two things differ from the standard clock, and both are only ever visible to
// a test that builds instants by hand:
//
//   - It rounds. Cycles reach nanoseconds through a scale factor, so
//     `(t + d) - t` comes back within a tick of `d` rather than exactly `d`.
//     Measured against the kernel's monotonic clock the rate is good to well
//     under a part per million, which is far finer than anything a run reports.
//   - It starts when the run does. There is no time before that for it to
//     name, so subtracting a duration from an instant near the start is an
//     overflow. Nothing outside tests ever looks backwards.
