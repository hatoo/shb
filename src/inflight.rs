//! Requests in flight, found by stream number rather than searched for
//!
//! Both HTTP/2 and HTTP/3 hand out stream ids in order and evenly spaced, so a
//! request's id already says where it is: one slot per id, with the front
//! trimmed as requests finish. Scanning a list instead cost a third of the
//! HTTP/2 worker's userspace at 128 streams a connection, and grew with the
//! parallelism the run asked for.
//!
//! A delayed response can leave arbitrarily many completed slots behind it.
//! Once holes dominate, retain the ids explicitly and pack away those holes.
//! The ids stay sorted because only this client opens streams, so binary
//! search bounds lookup by the active window without changing iteration order.

/// `SHIFT` is the gap between consecutive ids, as a power of two, and `OFFSET`
/// is what ours leave in the bits below it. Both belong to the protocol rather
/// than to the run, so they are constants: the mask and the shift below fold
/// into immediates, and what is left of a lookup is an `and` and a subtract.
pub struct Ring<T, const SHIFT: u32, const OFFSET: u64> {
    /// In stream order, oldest first. A `VecDeque` is the obvious shape for
    /// this and was what it used to be, but wrapping a logical index onto a
    /// ring buffer cost more than everything else the lookup does: a plain
    /// vector with a moving front indexes by adding.
    slots: Vec<Option<T>>,
    /// Where the oldest request still in flight sits in `slots`. Everything
    /// below it has finished, and `slots[head]` is never a hole.
    head: usize,
    /// Stream number of `slots[head]` in dense mode
    base: u64,
    /// How many slots hold a request
    open: usize,
    /// The `head` at which the retired prefix has grown enough to be worth
    /// moving the rest down over it
    compact_at: usize,
    /// Allocated only after a stalled request makes direct indexing wasteful.
    sparse: Option<Box<SparseIds>>,
}

struct SparseIds {
    /// Stream numbers parallel to `slots`, including any remaining holes.
    ids: Vec<u64>,
    /// Packing may discard the last completed id; the next push still follows it.
    next: u64,
}

/// Never move fewer than this many slots at a time, so a connection carrying
/// one request at a time does not memmove on every one of them.
const COMPACT_FLOOR: usize = 64;

/// HTTP/2 client streams are 1, 3, 5 (RFC 9113 Section 5.1.1)
pub type H2Ring<T> = Ring<T, 1, 1>;

/// HTTP/3 client bidirectional streams are 0, 4, 8 (RFC 9000 Section 2.1)
pub type H3Ring<T> = Ring<T, 2, 0>;

impl<T, const SHIFT: u32, const OFFSET: u64> Ring<T, SHIFT, OFFSET> {
    /// An id that leaves anything but `OFFSET` below the shift has no slot: it
    /// belongs to the peer or to the connection, and shifting it would land it
    /// on a request of ours.
    const MASK: u64 = (1 << SHIFT) - 1;

    pub fn new() -> Self {
        debug_assert!(OFFSET <= Self::MASK);
        Self {
            slots: Vec::new(),
            head: 0,
            base: 0,
            open: 0,
            compact_at: COMPACT_FLOOR,
            sparse: None,
        }
    }

    /// How many requests are in flight
    #[inline]
    pub fn len(&self) -> usize {
        self.open
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.open == 0
    }

    pub fn clear(&mut self) {
        self.slots.clear();
        self.head = 0;
        self.base = 0;
        self.open = 0;
        self.compact_at = COMPACT_FLOOR;
        self.sparse = None;
    }

    pub fn push(&mut self, stream_id: u64, item: T) {
        debug_assert_eq!(stream_id & Self::MASK, OFFSET);
        // Prefix compaction cannot reclaim holes behind a stalled request.
        // Packing at most once per window of completed requests amortizes the
        // copy while bounding both retained slots and callers' positional scans.
        if self.live() >= self.open.max(COMPACT_FLOOR).saturating_mul(2) {
            self.pack();
        }
        let n = stream_id >> SHIFT;
        if let Some(sparse) = &mut self.sparse {
            debug_assert_eq!(n, sparse.next, "streams are opened in order");
            sparse.ids.push(n);
            sparse.next = n + 1;
        } else {
            if self.slots.is_empty() {
                self.base = n;
            }
            debug_assert_eq!(
                n,
                self.base + self.live() as u64,
                "streams are opened in order, so they land in order"
            );
        }
        self.slots.push(Some(item));
        self.open += 1;
    }

    /// Slots from the front onwards, holes included
    #[inline(always)]
    fn live(&self) -> usize {
        self.slots.len() - self.head
    }

    #[inline(always)]
    fn index(&self, stream_id: u64) -> Option<usize> {
        if stream_id & Self::MASK != OFFSET {
            return None;
        }
        if let Some(sparse) = &self.sparse {
            return sparse.ids[self.head..]
                .binary_search(&(stream_id >> SHIFT))
                .ok()
                .map(|i| self.head + i);
        }
        let i = (stream_id >> SHIFT).checked_sub(self.base)?;
        (i < self.live() as u64).then(|| self.head + i as usize)
    }

    #[inline(always)]
    pub fn get_mut(&mut self, stream_id: u64) -> Option<&mut T> {
        let i = self.index(stream_id)?;
        self.slots[i].as_mut()
    }

    #[inline(always)]
    pub fn take(&mut self, stream_id: u64) -> Option<T> {
        let i = self.index(stream_id)?;
        let taken = self.slots[i].take()?;
        self.open -= 1;
        // Emptying anything but the front leaves the front where it was, so
        // only the front can start a trim, and the slot just emptied is the
        // first to go. Requests finish in order almost always, which makes
        // that one pop the whole of it; the loop is for the times they do
        // not, and stays out of line so the rest of this inlines.
        if i == self.head {
            self.head += 1;
            self.base += 1;
            // `None` here is the ring having drained, `Some(None)` a request
            // that finished ahead of this one; both are for `settle` to sort
            // out, and neither is the common case.
            if matches!(self.slots.get(self.head), None | Some(None)) {
                self.settle();
            } else if self.head >= self.compact_at {
                self.compact();
            }
        }
        Some(taken)
    }

    /// Step the front over the holes left by requests that finished early, and
    /// then decide what to do with the retired prefix.
    #[cold]
    fn settle(&mut self) {
        while matches!(self.slots.get(self.head), Some(None)) {
            self.head += 1;
            self.base += 1;
        }
        if self.head == self.slots.len() {
            self.slots.clear();
            self.head = 0;
            self.compact_at = COMPACT_FLOOR;
            // A drained connection can use direct indexing again.
            self.sparse = None;
        } else if self.head >= self.compact_at {
            self.compact();
        }
    }

    /// Move what is still in flight down over the slots that have finished, so
    /// the vector does not grow for the life of the run. Waiting until as much
    /// has retired as is in flight keeps this to one slot moved per request;
    /// waiting four times as long moves a quarter as much and was slower,
    /// because what it saved in copying it spent on pages.
    #[cold]
    fn compact(&mut self) {
        if self.sparse.is_some() {
            self.pack();
            return;
        }
        self.slots.drain(..self.head);
        self.head = 0;
        self.compact_at = self.slots.len().max(COMPACT_FLOOR);
    }

    /// Preserve stream order and positional access while dropping every hole.
    /// Ordinary dense compaction cannot do this: the position encodes the id.
    fn pack(&mut self) {
        if let Some(sparse) = &mut self.sparse {
            let (mut read, mut kept) = (0, 0);
            self.slots.retain(|slot| {
                let keep = slot.is_some();
                if keep {
                    sparse.ids[kept] = sparse.ids[read];
                    kept += 1;
                }
                read += 1;
                keep
            });
            sparse.ids.truncate(kept);
            // Once the old gap closes, a contiguous suffix ending at the last
            // opened id can encode its ids by position again. Trailing retired
            // ids must keep sparse mode, or the next push would skip a slot.
            if let Some(&first) = sparse.ids.first()
                && sparse.next - first == kept as u64
            {
                self.base = first;
                self.sparse = None;
            }
        } else {
            let next = self.base + self.live() as u64;
            let capacity = self.open.max(COMPACT_FLOOR);
            let mut slots = Vec::with_capacity(capacity);
            let mut ids = Vec::with_capacity(capacity);
            for (i, slot) in self.slots.drain(self.head..).enumerate() {
                if let Some(item) = slot {
                    slots.push(Some(item));
                    ids.push(self.base + i as u64);
                }
            }
            // Release the old allocation, including any large retired prefix.
            self.slots = slots;
            self.sparse = Some(Box::new(SparseIds { ids, next }));
        }
        self.head = 0;
        self.compact_at = self.slots.len().max(COMPACT_FLOOR);
    }

    /// Slots the vector is holding on to, retired ones included. Only the
    /// tests care: it is what compacting exists to bound.
    #[cfg(test)]
    fn footprint(&self) -> usize {
        self.slots.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots[self.head..].iter().flatten()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots[self.head..].iter_mut().flatten()
    }

    /// How many slots there are, holes included, for a caller that walks them
    /// by position rather than by id. Positions remain stable until a push,
    /// take or clear; packing never changes the order of surviving requests.
    #[inline]
    pub fn slot_count(&self) -> usize {
        self.live()
    }

    #[inline]
    pub fn slot_mut(&mut self, i: usize) -> Option<&mut T> {
        self.slots.get_mut(self.head + i)?.as_mut()
    }

    #[inline]
    pub fn slot(&self, i: usize) -> Option<&T> {
        self.slots.get(self.head + i)?.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP/3: client bidirectional streams are 0, 4, 8
    fn h3() -> H3Ring<u32> {
        H3Ring::new()
    }

    /// HTTP/2: client streams are 1, 3, 5
    fn h2() -> H2Ring<u32> {
        H2Ring::new()
    }

    #[test]
    fn a_request_is_found_by_its_stream_id() {
        let mut r = h3();
        for (n, id) in [0u64, 4, 8].iter().enumerate() {
            r.push(*id, n as u32);
        }
        assert_eq!(r.get_mut(4).copied(), Some(1));
        assert_eq!(r.len(), 3);
        assert_eq!(r.take(4), Some(1));
        assert_eq!(r.get_mut(4), None, "taken once only");
        assert_eq!(r.len(), 2);
    }

    /// The bug this replaced: stream 3 is the peer's control stream, and
    /// dividing it by four lands it on the first request we opened
    #[test]
    fn an_id_that_is_not_ours_has_no_slot() {
        let mut r = h3();
        r.push(0, 7);
        assert_eq!(r.get_mut(3), None);
        assert_eq!(r.take(3), None);
        assert_eq!(r.get_mut(0).copied(), Some(7));

        let mut r = h2();
        r.push(1, 7);
        assert_eq!(r.get_mut(0), None, "the connection itself");
        assert_eq!(r.get_mut(2), None, "a stream the server opened");
        assert_eq!(r.get_mut(1).copied(), Some(7));
    }

    #[test]
    fn finishing_the_front_trims_the_ring() {
        let mut r = h2();
        for (n, id) in [1u64, 3, 5].iter().enumerate() {
            r.push(*id, n as u32);
        }
        assert_eq!(r.slot_count(), 3);
        // Out of order: the middle one leaves a hole the front cannot cross
        assert_eq!(r.take(3), Some(1));
        assert_eq!(r.slot_count(), 3, "still pinned by stream 1");
        assert_eq!(r.take(1), Some(0));
        assert_eq!(r.slot_count(), 1, "both holes go at once");
        assert_eq!(r.get_mut(5).copied(), Some(2), "and 5 is still there");
    }

    #[test]
    fn a_stalled_request_bounds_storage_and_iteration() {
        stalled_request::<1, 1>();
        stalled_request::<2, 0>();
    }

    fn stalled_request<const SHIFT: u32, const OFFSET: u64>() {
        let mut r = Ring::<u64, SHIFT, OFFSET>::new();
        let id = |n| (n << SHIFT) | OFFSET;
        r.push(id(0), 0);
        for batch in 0..3_125 {
            let start = 1 + batch * 32;
            for n in start..start + 32 {
                r.push(id(n), n);
            }
            // Descending completions leave holes behind the oldest request.
            for n in (start..start + 32).rev() {
                assert_eq!(r.get_mut(id(n)).copied(), Some(n));
                assert_eq!(r.take(id(n)), Some(n));
                assert_eq!(r.take(id(n)), None);
            }
        }
        assert_eq!(r.len(), 1);
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), [0]);
        assert!(r.slot_count() <= 128, "scans {} slots", r.slot_count());
        assert!(
            r.slots.capacity() <= 256,
            "retains {} slots",
            r.slots.capacity()
        );
        assert_eq!(r.take(id(0)), Some(0));
        assert!(r.is_empty());
        r.push(id(100_001), 100_001);
        assert_eq!(r.take(id(100_001)), Some(100_001));
    }

    /// One at a time, each finishing before the next starts: the ring empties
    /// every time, and holding on to what it retired would mean a slot per
    /// request for the length of the run.
    #[test]
    fn a_ring_that_empties_keeps_nothing() {
        let mut r = h2();
        for i in 0..10_000u64 {
            r.push(1 + i * 2, i as u32);
            assert_eq!(r.take(1 + i * 2), Some(i as u32));
        }
        assert!(r.is_empty());
        assert_eq!(r.footprint(), 0);
    }

    /// A steady eight in flight: the front chases the back for ever, so the
    /// retired prefix has to be reclaimed as it grows rather than only when
    /// the ring happens to empty.
    #[test]
    fn a_ring_that_never_empties_still_settles() {
        let mut r = h2();
        let (mut next, mut oldest) = (1u64, 1u64);
        for n in 0..8u32 {
            r.push(next, n);
            next += 2;
        }
        for n in 8..10_000u32 {
            r.push(next, n);
            next += 2;
            assert!(r.take(oldest).is_some());
            oldest += 2;
        }
        assert_eq!(r.len(), 8);
        assert!(
            r.footprint() <= COMPACT_FLOOR + 8,
            "grew to {}",
            r.footprint()
        );
    }

    #[test]
    fn an_id_below_the_base_has_no_slot() {
        let mut r = h2();
        r.push(1, 0);
        r.push(3, 1);
        assert_eq!(r.take(1), Some(0));
        assert_eq!(r.get_mut(1), None, "retired and trimmed away");
        assert_eq!(r.get_mut(3).copied(), Some(1));
    }

    #[test]
    fn sparse_storage_matches_an_ordered_reference() {
        reference::<1, 1>();
        reference::<2, 0>();
    }

    fn reference<const SHIFT: u32, const OFFSET: u64>() {
        use std::collections::BTreeMap;
        let mut r = Ring::<(u64, u64), SHIFT, OFFSET>::new();
        let mut model = BTreeMap::new();
        let id = |n| (n << SHIFT) | OFFSET;
        let mut rng = 0x71cd_908a_1542_u64;
        let mut next = 0;
        for round in 0..3 {
            // A nonzero retired prefix exercises the dense-to-sparse id mapping.
            for _ in 0..12 {
                r.push(id(next), (next, 0));
                model.insert(id(next), (next, 0));
                next += 1;
            }
            for key in model.keys().copied().take(7).collect::<Vec<_>>() {
                assert_eq!(r.take(key), model.remove(&key));
            }
            for _ in 0..400 {
                r.push(id(next), (next, next));
                assert_eq!(r.take(id(next)), Some((next, next)));
                next += 1;
            }
            assert!(r.sparse.is_some());
            for step in 0..10_000 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                if model.len() < 64 && (model.len() < 2 || rng & 1 == 0) {
                    r.push(id(next), (next, rng));
                    model.insert(id(next), (next, rng));
                    next += 1;
                } else {
                    let key = *model
                        .keys()
                        .nth((rng >> 32) as usize % model.len())
                        .unwrap();
                    assert_eq!(r.take(key), model.remove(&key));
                    assert!(r.take(key).is_none(), "taken once only");
                }
                assert_eq!(r.len(), model.len());
                assert_eq!(
                    r.iter().copied().collect::<Vec<_>>(),
                    model.values().copied().collect::<Vec<_>>()
                );
                assert_eq!(
                    (0..r.slot_count())
                        .filter_map(|i| r.slot(i).copied())
                        .collect::<Vec<_>>(),
                    model.values().copied().collect::<Vec<_>>()
                );
                for (key, value) in &model {
                    assert_eq!(r.get_mut(*key).as_deref(), Some(value));
                    assert!(r.get_mut(*key ^ 1).is_none(), "peer id must not alias");
                }
                if step % 31 == 0 {
                    for value in r.iter_mut() {
                        value.1 ^= 1;
                    }
                    for value in model.values_mut() {
                        value.1 ^= 1;
                    }
                    for i in 0..r.slot_count() {
                        if let Some(value) = r.slot_mut(i) {
                            value.1 ^= 2;
                        }
                    }
                    for value in model.values_mut() {
                        value.1 ^= 2;
                    }
                }
            }
            r.clear();
            model.clear();
            assert_eq!(r.slot_count(), 0);
            assert!(r.sparse.is_none(), "reconnect restores direct indexing");
            next = round;
        }
    }

    #[test]
    fn sparse_completion_orders_preserve_identity() {
        fn permute(order: &mut [u64; 6], at: usize) {
            if at < order.len() {
                for i in at..order.len() {
                    order.swap(at, i);
                    permute(order, at + 1);
                    order.swap(at, i);
                }
                return;
            }
            let mut r = H3Ring::new();
            for n in 0..6 {
                r.push(n * 4, n);
            }
            for n in 6..200 {
                r.push(n * 4, n);
                assert_eq!(r.take(n * 4), Some(n));
            }
            assert!(r.sparse.is_some());
            for n in order {
                assert_eq!(r.take(*n * 4), Some(*n));
                assert_eq!(r.take(*n * 4), None);
            }
            assert!(r.is_empty());
            assert!(r.sparse.is_none());
            r.push(800, 200);
            assert_eq!(r.take(800), Some(200));
        }
        permute(&mut [0, 1, 2, 3, 4, 5], 0);
    }

    #[test]
    fn sparse_large_ids_and_packed_tail_keep_the_next_id() {
        let mut r = H3Ring::new();
        let first = (1_u64 << 60) - 300;
        r.push(first * 4, first);
        for n in first + 1..first + 200 {
            r.push(n * 4, n);
            assert_eq!(r.take(n * 4), Some(n));
        }
        r.pack();
        assert_eq!(r.slot_count(), 1);
        assert!(
            r.sparse.is_some(),
            "the retired tail still prevents direct indexing"
        );
        let next = first + 200;
        r.push(next * 4, next);
        assert_eq!(r.get_mut(next * 4).copied(), Some(next));
        assert_eq!(r.take(first * 4), Some(first));
        assert_eq!(r.take(next * 4), Some(next));
    }

    #[test]
    fn closing_the_gap_restores_direct_indexing_without_draining() {
        let mut r = h2();
        r.push(1, 0);
        for n in 1..200 {
            r.push(n * 2 + 1, n as u32);
            r.take(n * 2 + 1).unwrap();
        }
        assert!(r.sparse.is_some());
        for n in 200..232 {
            r.push(n * 2 + 1, n as u32);
        }
        assert_eq!(r.take(1), Some(0));
        for n in 232..1_000 {
            r.push(n * 2 + 1, n as u32);
            assert_eq!(r.take((n - 32) * 2 + 1), Some((n - 32) as u32));
            assert_eq!(r.len(), 32);
        }
        assert!(r.sparse.is_none());
        assert_eq!(
            r.iter().copied().collect::<Vec<_>>(),
            (968..1_000).collect::<Vec<_>>()
        );
    }

    #[test]
    fn packing_and_clear_drop_each_value_once() {
        use std::cell::Cell;
        struct Item<'a>(&'a Cell<usize>);
        impl Drop for Item<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let mut r = H2Ring::new();
        r.push(1, Item(&drops));
        for n in 1..1_000 {
            r.push(n * 2 + 1, Item(&drops));
            drop(r.take(n * 2 + 1).unwrap());
        }
        assert_eq!(drops.get(), 999);
        assert!(r.sparse.is_some());
        r.clear();
        assert_eq!(drops.get(), 1_000);
        r.push(1, Item(&drops));
        drop(r);
        assert_eq!(drops.get(), 1_001);
    }
}
