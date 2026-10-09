use super::*;

fn payload(start: usize, end: usize) -> Vec<u8> {
    (start..end).map(|i| (i * 37 % 251) as u8).collect()
}

// An independent byte occupancy model: no fragment list, sorting, or drain.
struct Model {
    bytes: Vec<Option<u8>>,
    read: usize,
    highest: usize,
    limit: u64,
    final_size: Option<u64>,
}

impl Model {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![None; size],
            read: 0,
            highest: 0,
            limit: 32,
            final_size: None,
        }
    }

    fn head(&self) -> usize {
        (self.read..self.bytes.len())
            .find(|&i| self.bytes[i].is_none())
            .unwrap_or(self.bytes.len())
    }

    fn check(&self, stream: &RecvStream) {
        let head = self.head();
        assert_eq!(stream.ready, payload(self.read, head));
        assert_eq!(stream.read_offset, self.read as u64);
        assert_eq!(stream.received, self.highest as u64);
        assert_eq!(stream.max_data, self.limit);
        assert_eq!(stream.has_data(), head > self.read);
        assert_eq!(stream.size_known(), self.final_size.is_some());
        assert_eq!(stream.final_size, self.final_size);
        assert_eq!(
            stream.is_finished(),
            self.final_size.is_some_and(|n| head as u64 >= n)
        );
        assert_eq!(
            stream.wants_credit(32),
            self.final_size.is_none() && self.read as u64 + 16 >= self.limit
        );
    }

    fn push(&mut self, stream: &mut RecvStream, start: usize, end: usize, fin: bool) {
        let data = payload(start, end);
        let new = end.saturating_sub(self.highest.max(self.read));
        for (slot, &byte) in self.bytes[start..end].iter_mut().zip(&data) {
            *slot = Some(byte);
        }
        self.highest = self.highest.max(end);
        if fin {
            self.final_size = Some(end as u64);
        }
        assert_eq!(stream.push(start as u64, &data, fin).unwrap(), new as u64);
        self.check(stream);
    }

    fn consume(&mut self, stream: &mut RecvStream, succeed: bool) {
        let head = self.head();
        let mut called = false;
        let result = stream.consume(|data| {
            called = true;
            assert_eq!(data, payload(self.read, head));
            if succeed {
                Ok(())
            } else {
                bail!("consumer refused this batch")
            }
        });
        assert_eq!(called, head > self.read);
        if succeed || head == self.read {
            assert_eq!(result.unwrap(), head - self.read);
            self.read = head;
        } else {
            assert!(result.is_err());
        }
        self.check(stream);
    }

    fn grant(&mut self, stream: &mut RecvStream) {
        self.limit = self.limit.max(self.read as u64 + 32);
        assert_eq!(stream.grant(32), self.limit);
        self.check(stream);
    }
}

#[test]
fn every_small_arrival_order_matches_the_byte_model() {
    fn permute(order: &mut [usize], at: usize, cases: &mut usize) {
        if at < order.len() {
            for i in at..order.len() {
                order.swap(at, i);
                permute(order, at + 1, cases);
                order.swap(at, i);
            }
            return;
        }
        let fragments = [(0, 4), (4, 8), (8, 12), (12, 16), (2, 10), (6, 16)];
        for consume_each in [false, true] {
            let mut stream = RecvStream::new(32);
            let mut model = Model::new(16);
            // An early FIN declares the end without filling any gap.
            model.push(&mut stream, 16, 16, true);
            for &i in order.iter() {
                let (start, end) = fragments[i];
                model.push(&mut stream, start, end, false);
                model.push(&mut stream, start, end, false);
                model.consume(&mut stream, false);
                if consume_each {
                    model.consume(&mut stream, true);
                }
                model.grant(&mut stream);
            }
            model.consume(&mut stream, true);
            assert_eq!(model.read, 16);
            assert!(stream.pending.is_empty());
            *cases += 1;
        }
    }
    let mut cases = 0;
    permute(&mut [0, 1, 2, 3, 4, 5], 0, &mut cases);
    assert_eq!(cases, 1440);
}

#[test]
fn mixed_gap_closures_and_partial_reads_keep_exact_credit() {
    for seed in 1..=32u64 {
        let mut state = seed;
        let mut stream = RecvStream::new(32);
        let mut model = Model::new(512);
        for step in 0..512 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let start = state as usize % 512;
            let end = (start + (state >> 32) as usize % 49).min(512);
            model.push(&mut stream, start, end, false);
            if step % 7 == 0 {
                model.consume(&mut stream, false);
            }
            if step % 11 == 0 {
                model.consume(&mut stream, true);
                model.grant(&mut stream);
            }
            if step % 17 == 0 {
                let start = step / 17 * 16;
                model.push(&mut stream, start, start + 16, false);
            }
        }
        model.push(&mut stream, 0, 512, true);
        model.consume(&mut stream, true);
        assert_eq!(model.read, 512);
        assert!(stream.pending.is_empty());
    }
}

#[test]
fn a_large_prefix_preserves_the_retained_fragments_and_their_storage() {
    for n in [1, 32, 256, 4096] {
        for prefix in [0, 1, n / 2, n] {
            let mut stream = RecvStream::new(u64::MAX);
            for i in 0..n {
                let offset = 8 + i * 4 + if i >= prefix { 8 } else { 0 };
                stream
                    .push(offset as u64, &payload(offset, offset + 4), i + 1 == n)
                    .unwrap();
            }
            let pending_ptr = stream.pending.as_ptr();
            let capacity = stream.pending.capacity();
            let retained: Vec<_> = stream.pending[prefix..]
                .iter()
                .map(|(offset, data)| (*offset, data.as_ptr(), data.len(), data.capacity()))
                .collect();
            let highest = stream.received;
            assert_eq!(stream.push(0, &payload(0, 8), false).unwrap(), 0);
            assert_eq!(stream.received, highest);
            let head = 8 + prefix * 4;
            assert_eq!(stream.ready, payload(0, head));
            assert_eq!(stream.pending.as_ptr(), pending_ptr);
            assert_eq!(stream.pending.capacity(), capacity);
            let actual: Vec<_> = stream
                .pending
                .iter()
                .map(|(offset, data)| (*offset, data.as_ptr(), data.len(), data.capacity()))
                .collect();
            assert_eq!(actual, retained);
            assert_eq!(stream.consume(|_| Ok(())).unwrap(), head);
            if prefix < n {
                assert!(!stream.is_finished());
                assert_eq!(
                    stream
                        .push(head as u64, &payload(head, head + 8), false)
                        .unwrap(),
                    0
                );
                assert_eq!(stream.ready, payload(head, highest as usize));
                assert_eq!(stream.consume(|_| Ok(())).unwrap(), highest as usize - head);
            }
            assert_eq!(stream.read_offset, highest);
            assert!(stream.is_finished());
            assert!(stream.pending.is_empty());
        }
    }
}

#[test]
fn overlaps_at_a_nonzero_read_offset_are_delivered_once() {
    let mut stream = RecvStream::new(32);
    let mut model = Model::new(48);
    model.push(&mut stream, 0, 12, false);
    model.consume(&mut stream, true);
    for (start, end) in [(20, 28), (20, 28), (22, 24), (26, 36), (40, 48)] {
        model.push(&mut stream, start, end, false);
    }
    model.push(&mut stream, 8, 22, false);
    model.consume(&mut stream, false);
    model.consume(&mut stream, true);
    assert_eq!(stream.read_offset, 36);
    model.grant(&mut stream);
    model.push(&mut stream, 32, 44, false);
    model.push(&mut stream, 48, 48, true);
    model.consume(&mut stream, true);
    assert_eq!(stream.read_offset, 48);
    assert!(stream.pending.is_empty());
}

#[test]
fn final_size_errors_and_reset_preserve_a_pending_gap() {
    for finish_with_reset in [false, true] {
        let mut stream = RecvStream::new(32);
        let mut model = Model::new(32);
        model.push(&mut stream, 16, 32, !finish_with_reset);
        if finish_with_reset {
            stream.reset(32).unwrap();
            model.final_size = Some(32);
        }
        for _ in 0..2 {
            assert!(stream.push(32, b"x", false).is_err());
            assert!(stream.push(31, &[], true).is_err());
            assert!(stream.reset(33).is_err());
            model.check(&stream);
            assert_eq!(stream.pending, vec![(16, payload(16, 32))]);
        }
        assert!(stream.reset(32).is_ok());
        model.push(&mut stream, 0, 16, false);
        model.consume(&mut stream, false);
        model.consume(&mut stream, true);
        assert!(stream.is_finished());
        let buf = stream.take_buf();
        let reused = RecvStream::with_buf(64, buf);
        assert!(!reused.has_data());
        assert!(!reused.size_known());
        assert_eq!(reused.read_offset, 0);
        assert_eq!(reused.received, 0);
        assert_eq!(reused.max_data, 64);
    }
}
