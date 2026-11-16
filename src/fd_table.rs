//! Reserve Linux's FD table before workers share it. Growing a shared table
//! can stall concurrent socket creation while the kernel waits for RCU readers.
//! Closing a temporary high-numbered descriptor leaves the capacity available.

use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

fn limits() -> io::Result<libc::rlimit> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limits points to writable storage for one rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(limits)
}

pub fn reserve(connections: usize, workers: usize) -> io::Result<()> {
    // Account for inherited descriptors, including sparse high-numbered ones.
    let open_end = std::fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<usize>().ok())
        .max()
        .unwrap_or(2)
        .saturating_add(1);
    // One socket per connection and one io_uring FD per worker, with spare
    // slots for temporary setup descriptors and connection replacement.
    let slots = open_end
        .saturating_add(connections)
        .saturating_add(workers)
        .saturating_add(64);
    let Some(last_allowed) = limits()?.rlim_cur.checked_sub(1) else {
        return Ok(());
    };
    let target = (slots.saturating_sub(1) as u64)
        .min(last_allowed)
        .min(i32::MAX as u64) as i32;
    let file = File::open("/dev/null")?;
    // SAFETY: file owns a valid FD. This duplicates it without replacing any
    // existing descriptor and marks the new descriptor close-on-exec.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, target) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new descriptor, whose ownership we take here.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_in_child(name: &str, limited: bool) {
        // Isolate resource limits and FD capacity from the other tests.
        if std::env::var_os("SHB_FD_TABLE_TEST_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("SHB_FD_TABLE_TEST_CHILD", "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }
        if limited {
            let mut limit = limits().unwrap();
            limit.rlim_cur = 128;
            // SAFETY: limit points to an initialized rlimit; only this child
            // process's soft limit is changed.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        }
        let before_limits = limits().unwrap();
        let before_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
        reserve(if limited { usize::MAX } else { 100 }, 4).unwrap();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let capacity: usize = status
            .lines()
            .find_map(|line| line.strip_prefix("FDSize:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(capacity >= if limited { 128 } else { 168 });
        assert_eq!(
            std::fs::read_dir("/proc/self/fd").unwrap().count(),
            before_fds
        );
        let after_limits = limits().unwrap();
        assert_eq!(after_limits.rlim_cur, before_limits.rlim_cur);
        assert_eq!(after_limits.rlim_max, before_limits.rlim_max);
    }

    #[test]
    fn reserves_without_leaking_fds() {
        check_in_child("fd_table::tests::reserves_without_leaking_fds", false);
    }

    #[test]
    fn respects_fd_limit_and_handles_overflow() {
        check_in_child(
            "fd_table::tests::respects_fd_limit_and_handles_overflow",
            true,
        );
    }
}
