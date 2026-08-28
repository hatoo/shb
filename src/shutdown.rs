//! Ctrl-C shutdown flag
//!
//! The SIGINT handler only stores an atomic flag (async-signal-safe). Workers
//! poll the flag at the top of their event loop; combined with the bounded
//! wait in [`crate::uring::submit_and_wait_timeout`] they notice a shutdown
//! request within ~100ms even when idle, then return their stats normally so
//! the final report is printed.

use std::sync::atomic::{AtomicBool, Ordering};

static REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    REQUESTED.store(true, Ordering::Relaxed);
    // A second Ctrl-C falls back to the default handler and kills the process
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
}

/// Install the SIGINT handler (call once at startup)
pub fn install() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigint as extern "C" fn(libc::c_int) as usize;
        // No SA_RESTART: a blocking io_uring_enter on the signaled thread
        // returns EINTR immediately instead of resuming the wait
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

/// Whether a shutdown was requested via Ctrl-C
pub fn requested() -> bool {
    REQUESTED.load(Ordering::Relaxed)
}
