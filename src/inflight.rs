//! Requests in flight, found by stream number rather than searched for
//!
//! Both HTTP/2 and HTTP/3 hand out stream ids in order and evenly spaced, so a
//! request's id already says where it is: one slot per id, with the front
//! trimmed as requests finish. Scanning a list instead cost a third of the
//! HTTP/2 worker's userspace at 128 streams a connection, and grew with the
//! parallelism the run asked for.

use std::collections::VecDeque;

pub struct Ring<T> {
    slots: VecDeque<Option<T>>,
    /// Stream number of `slots[0]`
    base: u64,
    /// How many slots hold a request
    open: usize,
    /// The gap between the ids we are handed, as a shift: HTTP/3 client
    /// bidirectional streams are 0, 4, 8 (RFC 9000 Section 2.1) and HTTP/2
    /// client streams are 1, 3, 5 (RFC 9113 Section 5.1.1). Held as a shift
    /// rather than a divisor because it is read on every event, and a
    /// division there is worth more than the whole lookup.
    shift: u32,
    /// What ours leave in the bits below the shift. An id that does not match
    /// has no slot: it belongs to the peer or to the connection, and shifting
    /// it would land it on a request of ours.
    offset: u64,
}

impl<T> Ring<T> {
    /// `stride` is the gap between consecutive ids and has to be a power of
    /// two, which both protocols' numbering gives.
    pub fn new(stride: u64, offset: u64) -> Self {
        debug_assert!(stride.is_power_of_two());
        debug_assert!(offset < stride);
        Self {
            slots: VecDeque::new(),
            base: 0,
            open: 0,
            shift: stride.trailing_zeros(),
            offset,
        }
    }

    #[inline]
    fn mask(&self) -> u64 {
        (1 << self.shift) - 1
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
        self.base = 0;
        self.open = 0;
    }

    pub fn push(&mut self, stream_id: u64, item: T) {
        let n = stream_id >> self.shift;
        if self.slots.is_empty() {
            self.base = n;
        }
        debug_assert_eq!(
            n,
            self.base + self.slots.len() as u64,
            "streams are opened in order, so they land in order"
        );
        self.slots.push_back(Some(item));
        self.open += 1;
    }

    #[inline(always)]
    fn index(&self, stream_id: u64) -> Option<usize> {
        if stream_id & self.mask() != self.offset {
            return None;
        }
        (stream_id >> self.shift)
            .checked_sub(self.base)
            .map(|i| i as usize)
            .filter(|&i| i < self.slots.len())
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
        if i == 0 {
            self.slots.pop_front();
            self.base += 1;
            if matches!(self.slots.front(), Some(None)) {
                self.trim();
            }
        }
        Some(taken)
    }

    /// Drop the rest of the holes at the front, so the ring does not grow for
    /// the life of the run. A request that never ends pins them all; the run's
    /// timeout is what bounds that.
    #[cold]
    fn trim(&mut self) {
        while matches!(self.slots.front(), Some(None)) {
            self.slots.pop_front();
            self.base += 1;
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().flatten()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots.iter_mut().flatten()
    }

    /// How many slots there are, holes included, for a caller that walks them
    /// by position rather than by id
    #[inline]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    #[inline]
    pub fn slot_mut(&mut self, i: usize) -> Option<&mut T> {
        self.slots.get_mut(i)?.as_mut()
    }

    #[inline]
    pub fn slot(&self, i: usize) -> Option<&T> {
        self.slots.get(i)?.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP/3: client bidirectional streams are 0, 4, 8
    fn h3() -> Ring<u32> {
        Ring::new(4, 0)
    }

    /// HTTP/2: client streams are 1, 3, 5
    fn h2() -> Ring<u32> {
        Ring::new(2, 1)
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
