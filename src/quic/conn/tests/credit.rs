//! Queue lifecycle tests use real receive streams, frame budgets and wire bytes.
use super::*;

fn fixture(count: usize) -> (Connection, Vec<u64>) {
    let mut conn = client();
    conn.stream_window = 64;
    conn.max_streams_bidi = count as u64 + 16;
    conn.max_data_local = 1 << 40;
    conn.max_data_window = 1 << 40;
    let mut ids: Vec<_> = (0..count).map(|_| conn.open_bi().unwrap()).collect();
    for id in [3, 7, 11] {
        conn.on_stream(id, 0, b"", false).unwrap();
        ids.push(id);
    }
    (conn, ids)
}

fn flush(conn: &mut Connection, budget: usize) -> Vec<(u64, u64)> {
    // A nonzero starting position catches errors in the packet-room calculation.
    let mut out = vec![0xaa; 13];
    let mut frames = Vec::new();
    conn.fill_data_payload(&mut out, budget, 13, &mut frames, true)
        .unwrap();
    assert!(out.len() - 13 <= budget);
    let wire: Vec<_> = frame::Iter::new(&out[13..])
        .map(|frame| match frame.unwrap() {
            Frame::MaxStreamData { id, limit } => (id, limit),
            other => panic!("unexpected credit packet: {other:?}"),
        })
        .collect();
    let ledger: Vec<_> = frames
        .into_iter()
        .map(|frame| match frame {
            SentFrame::MaxStreamData { id, limit } => (id, limit),
            other => panic!("unexpected credit ledger: {other:?}"),
        })
        .collect();
    assert_eq!(wire, ledger);
    wire
}

#[test]
fn credit_queue_matches_lifo_model_across_duplicate_losses_and_packet_budgets() {
    let (mut conn, ids) = fixture(64);
    let mut model = Vec::new();
    let mut seed = 0x123456789abcdefu64;
    let mut emitted = 0;
    for step in 0..10_000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let id = ids[seed as usize % ids.len()];
        conn.on_frame_lost(Space::Data, SentFrame::MaxStreamData { id, limit: 1 });
        if !model.contains(&id) {
            model.push(id);
        }
        if step % 7 == 0 {
            let budget = [0, 23, 24, 30, 47, 1200][(seed >> 24) as usize % 6];
            let mut room = budget;
            let mut expected = Vec::new();
            while room >= 24 {
                let Some(id) = model.pop() else { break };
                expected.push((id, 64));
                let mut frame = Vec::new();
                frame::put_max_stream_data(&mut frame, id, 64);
                room -= frame.len();
            }
            let actual = flush(&mut conn, budget);
            emitted += actual.len();
            assert_eq!(actual, expected, "step {step}");
        }
        assert_eq!(conn.credit_pending, model, "step {step}");
    }
    assert_eq!(
        flush(&mut conn, 65_536),
        model
            .into_iter()
            .rev()
            .map(|id| (id, 64))
            .collect::<Vec<_>>()
    );
    assert!(emitted > 1000);
}

#[test]
fn credit_consumption_failure_and_repeated_reads_keep_one_current_grant() {
    let (mut conn, ids) = fixture(1);
    for id in ids {
        conn.on_stream(id, 0, &[1; 32], false).unwrap();
        assert!(
            conn.consume(id, |_| anyhow::bail!("application rejected data"))
                .is_err()
        );
        assert!(conn.credit_pending.is_empty());
        assert_eq!(
            conn.consume(id, |data| {
                assert_eq!(data, &[1; 32]);
                Ok(())
            })
            .unwrap(),
            32
        );
        for _ in 0..10 {
            assert_eq!(conn.consume(id, |_| panic!("no new bytes")).unwrap(), 0);
            conn.on_frame_lost(Space::Data, SentFrame::MaxStreamData { id, limit: 64 });
        }
        assert_eq!(conn.credit_pending, vec![id]);
        assert!(flush(&mut conn, 23).is_empty());
        assert_eq!(conn.credit_pending, vec![id]);
        assert_eq!(flush(&mut conn, 24), vec![(id, 96)]);
        // An old lost grant must be regenerated from the newly consumed offset.
        conn.on_stream(id, 32, &[2; 32], false).unwrap();
        conn.consume(id, |_| Ok(())).unwrap();
        conn.on_frame_lost(Space::Data, SentFrame::MaxStreamData { id, limit: 64 });
        assert_eq!(flush(&mut conn, 24), vec![(id, 128)]);
        conn.on_frame_lost(Space::Data, SentFrame::MaxStreamData { id, limit: 96 });
        assert_eq!(flush(&mut conn, 24), vec![(id, 128)]);
    }
}

#[test]
fn credit_fin_and_reset_before_emission_discard_grants_after_budget_deferral() {
    let (mut conn, ids) = fixture(2);
    for (n, id) in ids.into_iter().enumerate() {
        conn.on_stream(id, 0, &[1; 32], false).unwrap();
        conn.consume(id, |_| Ok(())).unwrap();
        assert!(flush(&mut conn, 0).is_empty());
        if n % 2 == 0 {
            conn.on_stream(id, 32, b"", true).unwrap();
        } else {
            conn.on_reset(id, 0, 32).unwrap();
        }
        assert!(flush(&mut conn, 24).is_empty());
        assert!(conn.credit_pending.is_empty());
        conn.on_frame_lost(Space::Data, SentFrame::MaxStreamData { id, limit: 64 });
        assert!(flush(&mut conn, 24).is_empty());
        assert!(conn.credit_pending.is_empty());
    }
}

#[test]
fn credit_retirement_and_sparse_send_acks_do_not_poison_reused_buffers() {
    let (mut conn, _) = fixture(0);
    conn.params.initial_max_stream_data_bidi_remote = 64;
    for n in 0..16 {
        let (id, len) = conn.send_oneshot(b"abcdefgh").unwrap();
        assert_eq!(len, 8);
        conn.send_mut(id).unwrap().on_sent(0, 8, true);
        conn.on_stream(id, 0, &[3; 32], false).unwrap();
        conn.consume(id, |_| Ok(())).unwrap();
        assert_eq!(conn.credit_pending, vec![id]);
        conn.retire(id, 0x10c);
        conn.on_frame_acked(SentFrame::Stream {
            id,
            offset: 4,
            len: 4,
            fin: true,
        });
        assert!(conn.stream_mut(id).is_some());
        conn.on_frame_acked(SentFrame::Stream {
            id,
            offset: 0,
            len: 4,
            fin: false,
        });
        assert!(conn.stream_mut(id).is_none());
        // A credit lost after retirement must not resurrect the old stream.
        conn.on_frame_lost(Space::Data, SentFrame::MaxStreamData { id, limit: 64 });
        assert!(flush(&mut conn, 1200).is_empty());
        assert!(conn.credit_pending.is_empty());
        assert_eq!(conn.spare_bufs.len(), 1, "cycle {n}");
    }
}
