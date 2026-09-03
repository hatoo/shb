//! Requests in flight, found by stream number rather than searched for
//!
//! Both HTTP/2 and HTTP/3 hand out stream ids in order and evenly spaced, so a
//! request's id already says where it is: one slot per id, with the front
//! trimmed as requests finish. Scanning a list instead cost a third of the
//! HTTP/2 worker's userspace at 128 streams a connection, and grew with the
//! parallelism the run asked for.

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
    /// Stream number of `slots[head]`
    base: u64,
    /// How many slots hold a request
    open: usize,
    /// The `head` at which the retired prefix has grown enough to be worth
    /// moving the rest down over it
    compact_at: usize,
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
    }

    pub fn push(&mut self, stream_id: u64, item: T) {
        let n = stream_id >> SHIFT;
        if self.slots.is_empty() {
            self.base = n;
        }
        debug_assert_eq!(
            n,
            self.base + self.live() as u64,
            "streams are opened in order, so they land in order"
        );
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
        } else if self.head >= self.compact_at {
            self.compact();
        }
    }

    /// Move what is still in flight down over the slots that have finished, so
    /// the vector does not grow for the life of the run. Waiting until as much
    /// has retired as is in flight keeps this to one slot moved per request;
    /// waiting four times as long moves a quarter as much and was slower,
    /// because what it saved in copying it spent on pages. A request that never
    /// ends pins the front and nothing here can move it; the run's timeout is
    /// what bounds that.
    #[cold]
    fn compact(&mut self) {
        self.slots.drain(..self.head);
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
    /// by position rather than by id
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

    /// A request that never ends pins the front, and the ring grows behind it
    /// one slot per request. Nothing here fixes that; the run's timeout does.
    #[test]
    fn a_stalled_request_pins_the_front() {
        let mut r = h2();
        r.push(1, 0);
        for i in 1..10u64 {
            r.push(1 + i * 2, i as u32);
            assert_eq!(r.take(1 + i * 2), Some(i as u32));
        }
        assert_eq!(r.len(), 1);
        assert_eq!(r.slot_count(), 10);
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
}
