use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::FromRawFd;

// Other tests create sockets concurrently. Count descriptors in a child running
// only this test, on one still-live thread; thread/process teardown must not
// conceal a leaked descriptor or a retained fixed-file reference.
fn isolated(name: &str, check: impl FnOnce()) {
    let name = format!("uring::connect_tests::{name}");
    if std::env::var("SHB_CONNECT_TEST").as_deref() == Ok(&name) {
        check();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env("SHB_CONNECT_TEST", &name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{name}: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn registration_failure_releases_every_socket() {
    isolated("registration_failure_releases_every_socket", || {
        let addr = "127.0.0.1:9".parse().unwrap();
        let raw_addr = socket2::SockAddr::from(addr);
        let timeout = types::Timespec::from(Duration::from_secs(1));
        let mut ring = IoUring::new(2).unwrap();
        let (submitter, mut sq, _) = ring.split();
        submitter.register_files_sparse(1).unwrap();
        let before = fd_count();
        for generation in 0..128 {
            let error = start_connect(
                &submitter, &mut sq, 1, generation, &addr, &raw_addr, &timeout,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "register_files_update failed");
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::EINVAL),
            );
            assert!(sq.is_empty(), "failed registration queued a connect");
        }
        let after = fd_count();
        println!("registration failures=128 fd_before={before} fd_after={after}");
        assert_eq!(after, before, "failed registrations leaked raw sockets");
    });
}

#[test]
fn submit_failure_keeps_the_slot_empty_and_releases_every_socket() {
    isolated(
        "submit_failure_keeps_the_slot_empty_and_releases_every_socket",
        || {
            let addr = "127.0.0.1:9".parse().unwrap();
            let raw_addr = socket2::SockAddr::from(addr);
            let timeout = types::Timespec::from(Duration::from_secs(1));
            // A disabled ring accepts registrations but rejects submissions.
            // No invalid pointers, closed ring fds, or mocked syscalls needed.
            let mut ring: IoUring = IoUring::builder().setup_r_disabled().build(2).unwrap();
            let (submitter, mut sq, mut cq) = ring.split();
            submitter.register_files_sparse(1).unwrap();
            unsafe { sq.push(&opcode::Nop::new().build().user_data(10)).unwrap() };
            let before = fd_count();
            for generation in 0..128 {
                let error = start_connect(
                    &submitter, &mut sq, 0, generation, &addr, &raw_addr, &timeout,
                )
                .unwrap_err();
                assert_eq!(error.to_string(), "io_uring submit failed");
                assert_eq!(
                    error
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .raw_os_error(),
                    Some(libc::EBADFD),
                );
                assert_eq!(sq.len(), 1, "failed submission changed the queued NOP");
            }
            let after = fd_count();
            submitter.register_enable_rings().unwrap();
            // An actual fixed-file operation distinguishes an empty slot from
            // a socket retained only by the ring (invisible in /proc/self/fd).
            let probe = opcode::Send::new(types::Fixed(0), b"x".as_ptr(), 1)
                .flags(libc::MSG_NOSIGNAL)
                .build()
                .user_data(11);
            unsafe { sq.push(&probe).unwrap() };
            sq.sync();
            submitter.submit_and_wait(2).unwrap();
            cq.sync();
            let mut completions: Vec<_> = cq.map(|c| (c.user_data(), c.result())).collect();
            completions.sort_unstable();
            println!(
                "submit failures=128 fd_before={before} fd_after={after} cqes={completions:?}"
            );
            assert_eq!(completions, [(10, 0), (11, -libc::EBADF)]);
            assert_eq!(after, before, "failed submissions leaked raw sockets");
        },
    );
}

#[test]
fn insufficient_capacity_never_queues_half_a_connect_pair() {
    isolated(
        "insufficient_capacity_never_queues_half_a_connect_pair",
        || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let raw_addr = socket2::SockAddr::from(addr);
            let timeout = types::Timespec::from(Duration::from_secs(1));
            // Keep both pointed-to values alive beyond ring teardown, even when
            // running this regression against a baseline that queues half a pair.
            let mut ring = IoUring::new(1).unwrap();
            let (submitter, mut sq, _) = ring.split();
            submitter.register_files_sparse(1).unwrap();
            let before = fd_count();
            let error =
                start_connect(&submitter, &mut sq, 0, 0, &addr, &raw_addr, &timeout).unwrap_err();
            assert_eq!(error.to_string(), "submission queue full");
            let after = fd_count();
            println!(
                "capacity=1 fd_before={before} fd_after={after} queued={}",
                sq.len()
            );
            assert_eq!((sq.len(), after), (0, before));
        },
    );
}

fn complete_pair(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    cq: &mut io_uring::cqueue::CompletionQueue<'_>,
) -> Vec<(u64, i32)> {
    sq.sync();
    let mut result = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while result.len() < 3 && std::time::Instant::now() < deadline {
        submit_and_wait_timeout(submitter, Duration::from_millis(20), 1).unwrap();
        cq.sync();
        result.extend(cq.map(|c| (c.user_data(), c.result())));
    }
    result.sort_unstable();
    sq.sync();
    result
}

#[test]
fn successful_handoff_and_refusal_preserve_the_linked_pair() {
    isolated(
        "successful_handoff_and_refusal_preserve_the_linked_pair",
        || {
            for host in ["127.0.0.1:0", "[::1]:0"] {
                let listener = TcpListener::bind(host).unwrap();
                let addr = listener.local_addr().unwrap();
                let raw_addr = socket2::SockAddr::from(addr);
                let timeout = types::Timespec::from(Duration::from_secs(1));
                let mut ring = IoUring::new(2).unwrap();
                let (submitter, mut sq, mut cq) = ring.split();
                submitter.register_files_sparse(1).unwrap();
                let before = fd_count();
                for generation in 1..=8 {
                    // One free SQE forces the reservation path to flush existing
                    // work before publishing the two linked entries together.
                    unsafe { sq.push(&opcode::Nop::new().build().user_data(10)).unwrap() };
                    let fd = start_connect(
                        &submitter, &mut sq, 0, generation, &addr, &raw_addr, &timeout,
                    )
                    .unwrap();
                    let mut client = unsafe { TcpStream::from_raw_fd(fd) };
                    assert!(client.nodelay().unwrap());
                    assert_eq!(sq.len(), 2);
                    assert_eq!(
                        complete_pair(&submitter, &mut sq, &mut cq),
                        [
                            (10, 0),
                            (user_data(0, generation, OP_CONNECT), 0),
                            (
                                user_data(0, generation, OP_CONNECT_TIMEOUT),
                                -libc::ECANCELED
                            ),
                        ],
                    );
                    let (mut peer, _) = listener.accept().unwrap();
                    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    client.write_all(b"handoff intact").unwrap();
                    submitter.register_files_update(0, &[-1]).unwrap();
                    drop(client);
                    let mut received = Vec::new();
                    peer.read_to_end(&mut received).unwrap();
                    assert_eq!(received, b"handoff intact");
                }
                assert_eq!(fd_count(), before);

                // Binding without listening holds the port while connect is
                // refused, so a concurrent test cannot claim it in between.
                let refused = socket2::Socket::new(
                    socket2::Domain::for_address(addr),
                    socket2::Type::STREAM,
                    None,
                )
                .unwrap();
                refused
                    .bind(&socket2::SockAddr::from(
                        host.parse::<SocketAddr>().unwrap(),
                    ))
                    .unwrap();
                let addr = refused.local_addr().unwrap().as_socket().unwrap();
                let raw_addr = socket2::SockAddr::from(addr);
                unsafe { sq.push(&opcode::Nop::new().build().user_data(10)).unwrap() };
                let fd =
                    start_connect(&submitter, &mut sq, 0, 9, &addr, &raw_addr, &timeout).unwrap();
                let client = unsafe { TcpStream::from_raw_fd(fd) };
                assert_eq!(
                    complete_pair(&submitter, &mut sq, &mut cq),
                    [
                        (10, 0),
                        (user_data(0, 9, OP_CONNECT), -libc::ECONNREFUSED),
                        (user_data(0, 9, OP_CONNECT_TIMEOUT), -libc::ECANCELED),
                    ],
                );
                submitter.register_files_update(0, &[-1]).unwrap();
                drop(client);
                drop(refused);
                assert_eq!(fd_count(), before);
            }
        },
    );
}
