//! Worker request accounting, bounded by peak concurrency even when a peer
//! leaves an old response open. The protocol engine's positional ring is separate.
//!
//! The bounded-span policy follows hatoo/xdp-http's src/http2/streams.rs
//! (b4e6075). Unlike an exclusive sparse mode, old pins spill separately so
//! younger requests retain direct lookup in shb's existing vector ring.

use crate::inflight::H2Ring;
use std::collections::HashMap;

pub(super) struct Streams<T> {
    dense: H2Ring<T>,
    sparse: Sparse<T>,
    next: u64,
    /// IDs below this boundary may be sparse; newer IDs always use the ring.
    sparse_end: u64,
    /// At most twice the highest concurrency observed under span pressure.
    /// Updating only under pressure keeps peak bookkeeping off normal pushes.
    span_limit: usize,
}

const NONE: usize = usize::MAX;

/// Slots are recycled without allocating a node per request. Live slots form
/// an insertion-order list, so the oldest timestamp never needs a map scan.
/// The same `next` link connects free slots; only the ID index exposes slots.
struct Sparse<T> {
    index: HashMap<u64, usize>,
    slots: Vec<Slot<T>>,
    first: usize,
    last: usize,
    free: usize,
}

struct Slot<T> {
    value: Option<T>,
    prev: usize,
    next: usize,
}

impl<T> Sparse<T> {
    fn new(capacity: usize) -> Self {
        Self {
            index: HashMap::with_capacity(capacity.saturating_mul(2)),
            slots: Vec::with_capacity(capacity),
            first: NONE,
            last: NONE,
            free: NONE,
        }
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    fn push(&mut self, id: u64, value: T) {
        let slot = Slot {
            value: Some(value),
            prev: self.last,
            next: NONE,
        };
        let position = if self.free == NONE {
            let position = self.slots.len();
            self.slots.push(slot);
            position
        } else {
            let position = self.free;
            self.free = self.slots[position].next;
            self.slots[position] = slot;
            position
        };
        let previous = self.index.insert(id, position);
        debug_assert!(previous.is_none());
        if self.last == NONE {
            self.first = position;
        } else {
            self.slots[self.last].next = position;
        }
        self.last = position;
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut T> {
        let &position = self.index.get(&id)?;
        self.slots[position].value.as_mut()
    }

    fn take(&mut self, id: u64) -> Option<T> {
        let position = self.index.remove(&id)?;
        let Slot { prev, next, .. } = self.slots[position];
        if prev == NONE {
            self.first = next;
        } else {
            self.slots[prev].next = next;
        }
        if next == NONE {
            self.last = prev;
        } else {
            self.slots[next].prev = prev;
        }
        let slot = &mut self.slots[position];
        slot.prev = NONE;
        slot.next = self.free;
        self.free = position;
        slot.value.take()
    }

    fn first(&self) -> Option<&T> {
        self.slots.get(self.first)?.value.as_ref()
    }

    fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.first = NONE;
        self.last = NONE;
        self.free = NONE;
    }
}

impl<T> Streams<T> {
    pub(super) fn new() -> Self {
        Self {
            dense: H2Ring::new(),
            sparse: Sparse::new(0),
            next: 1,
            sparse_end: 0,
            span_limit: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.dense.len() + self.sparse.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(super) fn push(&mut self, id: u64, value: T) {
        debug_assert!(id & 1 == 1 && id <= 0x7fff_ffff);
        debug_assert!(self.is_empty() || id == self.next);
        if self.dense.slot_count() >= self.span_limit {
            self.make_room();
        }
        self.dense.push(id, value);
        self.next = id + 2;
    }

    fn make_room(&mut self) {
        self.span_limit = self.span_limit.max((self.len() + 1).saturating_mul(2));
        if self.dense.slot_count() < self.span_limit {
            return;
        }
        // Move only the oldest live prefix. Taking its first value lets the
        // ring trim holes itself, without inspecting every younger live value.
        // Freeing half the span amortizes this work across subsequent pushes.
        while self.dense.slot_count() > self.span_limit / 2 {
            let id = self.next - 2 * self.dense.slot_count() as u64;
            let value = self.dense.take(id).expect("dense front is live");
            self.sparse.push(id, value);
            self.sparse_end = id + 2;
        }
    }

    pub(super) fn get_mut(&mut self, id: u64) -> Option<&mut T> {
        if id >= self.sparse_end {
            self.dense.get_mut(id)
        } else {
            self.sparse.get_mut(id)
        }
    }

    pub(super) fn take(&mut self, id: u64) -> Option<T> {
        if id >= self.sparse_end {
            self.dense.take(id)
        } else {
            self.sparse.take(id)
        }
    }

    pub(super) fn first(&self) -> Option<&T> {
        self.sparse.first().or_else(|| self.dense.slot(0))
    }

    pub(super) fn clear(&mut self) {
        self.dense.clear();
        self.sparse.clear();
        self.next = 1;
        self.sparse_end = 0;
    }

    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        let mut position = self.sparse.first;
        std::iter::from_fn(move || {
            let slot = self.sparse.slots.get(position)?;
            position = slot.next;
            slot.value.as_ref()
        })
        .chain(self.dense.iter())
    }
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod tests;
