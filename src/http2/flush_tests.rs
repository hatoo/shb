use super::*;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[test]
fn repeated_marks_and_reconnects_cannot_grow_the_worklist_past_the_slot_count() {
    let mut conns: Vec<_> = (0..129).map(|_| Conn::new()).collect();
    let mut pending = PendingFlush::new(conns.len());
    let storage = pending.words.as_ptr();
    let capacity = pending.words.capacity();
    let mut ring = io_uring::IoUring::new(8).unwrap();
    let (submitter, mut sq, _) = ring.split();
    for round in 0..256 {
        // Multiplication permutes the slots, with repeated marks both before
        // and after closing. A generation change must not create a new entry.
        for n in 0..conns.len() {
            let i = (n * 17 + round) % conns.len();
            pending.mark(i);
            pending.mark(i);
            conns[i].close();
            pending.mark(i);
        }
        assert_eq!(
            pending
                .words
                .iter()
                .map(|w| w.count_ones() as usize)
                .sum::<usize>(),
            conns.len()
        );
        flush_pending(&submitter, &mut sq, &mut conns, &mut pending).unwrap();
        assert!(pending.words.iter().all(|&w| w == 0));
        assert_eq!(sq.len(), 0, "closed slots have no output");
        assert_eq!(
            (pending.words.as_ptr(), pending.words.capacity()),
            (storage, capacity)
        );
    }
}

#[test]
fn a_queued_reconnected_slot_sends_only_its_current_generation() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut conns = [Conn::new()];
    let mut pending = PendingFlush::new(1);
    let mut ring = io_uring::IoUring::new(8).unwrap();
    ring.submitter()
        .register_files(&[socket.as_raw_fd()])
        .unwrap();
    let (submitter, mut sq, mut cq) = ring.split();

    let conn = &mut conns[0];
    conn.h2 = Some(Connection::new());
    conn.h2.as_mut().unwrap().send_goaway();
    pending.mark(0);
    let old_generation = conn.generation;
    conn.close();
    let mut current = Connection::new();
    current.initiate();
    conn.h2 = Some(current);
    pending.mark(0);
    assert_eq!(pending.words, [1]);
    assert_ne!(conn.generation, old_generation);

    flush_pending(&submitter, &mut sq, &mut conns, &mut pending).unwrap();
    assert_eq!(sq.len(), 1);
    sq.sync();
    submitter.submit_and_wait(1).unwrap();
    cq.sync();
    let cqe = cq.next().unwrap();
    assert_eq!(
        uring::decode_user_data(cqe.user_data()),
        (OP_SEND, 0, conns[0].generation)
    );
    assert_eq!(cqe.result() as usize, conns[0].out.len());
    let mut received = vec![0; conns[0].out.len()];
    peer.read_exact(&mut received).unwrap();
    let mut expected = Connection::new();
    expected.initiate();
    assert_eq!(received, expected.take_output().unwrap());
    assert!(pending.words.iter().all(|&w| w == 0));
}

#[test]
fn output_during_a_send_waits_for_completion_without_touching_the_send_buffer() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut conns = [Conn::new()];
    let mut pending = PendingFlush::new(1);
    let mut ring = io_uring::IoUring::new(8).unwrap();
    ring.submitter()
        .register_files(&[socket.as_raw_fd()])
        .unwrap();
    let (submitter, mut sq, mut cq) = ring.split();
    let mut h2 = Connection::new();
    h2.initiate();
    conns[0].h2 = Some(h2);
    pending.mark(0);
    flush_pending(&submitter, &mut sq, &mut conns, &mut pending).unwrap();
    let first = conns[0].out.clone();
    let pointer = conns[0].out.as_ptr();
    sq.sync();
    submitter.submit_and_wait(1).unwrap();
    sq.sync();

    // The Send CQE has not been handled. A receive produces more output,
    // but flushing this batch must leave the in-flight bytes untouched.
    conns[0].h2.as_mut().unwrap().send_goaway();
    for _ in 0..8 {
        pending.mark(0);
    }
    conns[0].out_off = 1; // also preserve the offset of a partial send
    flush_pending(&submitter, &mut sq, &mut conns, &mut pending).unwrap();
    assert_eq!(sq.len(), 0);
    assert_eq!(conns[0].out, first);
    assert_eq!(conns[0].out.as_ptr(), pointer);
    assert_eq!(conns[0].out_off, 1);
    assert!(conns[0].sending);

    cq.sync();
    assert_eq!(cq.next().unwrap().result() as usize, first.len());
    conns[0].sending = false;
    // A successful final Send CQE requeues the slot for any waiting output.
    pending.mark(0);
    flush_pending(&submitter, &mut sq, &mut conns, &mut pending).unwrap();
    assert_eq!(sq.len(), 1);
    sq.sync();
    submitter.submit_and_wait(1).unwrap();
    cq.sync();
    assert_eq!(cq.next().unwrap().result() as usize, conns[0].out.len());
    assert_eq!(conns[0].out_off, 0);
    let mut received = vec![0; first.len() + conns[0].out.len()];
    peer.read_exact(&mut received).unwrap();
    let mut expected = first;
    let mut h2 = Connection::new();
    h2.send_goaway();
    expected.extend(h2.take_output().unwrap());
    assert_eq!(received, expected);
}

#[test]
fn sparse_marks_drain_once_in_slot_order_across_word_boundaries() {
    let mut pending = PendingFlush::new(257);
    for _ in 0..3 {
        for index in [256, 128, 63, 0, 64, 128, 63] {
            pending.mark(index);
        }
        let mut seen = Vec::new();
        pending
            .drain(|index| {
                seen.push(index);
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, [0, 63, 64, 128, 256]);
        pending
            .drain(|_| panic!("drained marks must not survive into another batch"))
            .unwrap();
    }
}

#[test]
fn full_words_and_sparse_words_share_the_same_flush_order() {
    let mut pending = PendingFlush::new(257);
    for index in (64..128).rev().chain([256, 0, 200, 63, 128]) {
        pending.mark(index);
    }
    let mut seen = Vec::new();
    pending
        .drain(|index| {
            seen.push(index);
            Ok(())
        })
        .unwrap();
    let expected: Vec<_> = [0, 63]
        .into_iter()
        .chain(64..129)
        .chain([200, 256])
        .collect();
    assert_eq!(seen, expected);
    assert!(pending.words.iter().all(|&word| word == 0));
}
