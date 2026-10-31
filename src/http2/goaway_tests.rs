use super::*;

#[test]
fn goaway_suffixes_preserve_event_order_retries_and_samples_with_holes() {
    use Notice::*;
    for n in [1_u32, 8, 128, 512] {
        let ids: Vec<_> = (0..n).map(|i| 2 * i + 1).collect();
        for prefix in [0, n / 2] {
            let mut live: BTreeMap<_, _> = ids.iter().map(|&id| (id, ())).collect();
            let mut frames = Vec::new();
            for (i, &id) in ids.iter().enumerate() {
                if i < prefix as usize || i % 7 == 3 {
                    live.remove(&id);
                    frames.push(frame(1, 5, id, &[0x88], &[Status(id, 200), End(id)]));
                }
            }
            // Repeated and increasing boundaries must not return a stream
            // twice. Reserved bits are ignored; even ids split odd streams.
            for last in [
                u32::MAX,
                2 * n - 2,
                2 * n - 2,
                u32::MAX,
                n | 0x8000_0000,
                n / 2,
            ] {
                let mut notices = Vec::new();
                let rejected: Vec<_> = live
                    .keys()
                    .copied()
                    .filter(|&id| id > (last & 0x7fff_ffff))
                    .collect();
                for id in rejected {
                    live.remove(&id);
                    notices.push(Retry(id));
                }
                notices.push(Goaway);
                let mut payload = last.to_be_bytes().to_vec();
                payload.extend_from_slice(&[0; 4]);
                frames.push(frame(7, 0, 0, &payload, &notices));
            }
            for &id in live.keys().rev() {
                frames.push(frame(1, 4, id, &[0x88], &[Status(id, 200)]));
                frames.push(frame(0, 1, id, b"surviving response", &[End(id)]));
            }
            frames.push(frame(7, 0, 0, &[0; 8], &[Goaway]));
            // Late resets on rejected/finished requests cannot count again.
            for &id in &ids {
                frames.push(frame(3, 0, id, &[0, 0, 0, 7], &[]));
            }
            run_schedule_with_ids(&frames, &[], &ids);
            let wire_len = frames.iter().map(|f| f.bytes.len()).sum();
            let step = if n <= 8 { 1 } else { 17 };
            run_schedule_with_ids(
                &frames,
                &(step..wire_len).step_by(step).collect::<Vec<_>>(),
                &ids,
            );
        }
    }
}
