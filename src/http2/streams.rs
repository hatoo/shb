//! Worker request accounting, bounded by peak concurrency even when a peer
//! leaves an old response open. The protocol engine's positional ring is separate.
//!
//! The dense/sparse policy follows hatoo/xdp-http's src/http2/streams.rs
//! (b4e6075). Keep shb's existing vector ring for ordinary ordered traffic.

use crate::inflight::H2Ring;
use std::collections::HashMap;

pub(super) struct Streams<T> {
    storage: Storage<T>,
    high_water: usize,
}

enum Storage<T> {
    Dense { ring: H2Ring<T>, next: u64 },
    Sparse(Sparse<T>),
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
            storage: Storage::Dense {
                ring: H2Ring::new(),
                next: 1,
            },
            high_water: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        match &self.storage {
            Storage::Dense { ring, .. } => ring.len(),
            Storage::Sparse(sparse) => sparse.len(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(super) fn push(&mut self, id: u64, value: T) {
        debug_assert!(id & 1 == 1 && id <= 0x7fff_ffff);
        match &mut self.storage {
            Storage::Dense { ring, next } => {
                debug_assert!(ring.is_empty() || id == *next);
                self.high_water = self.high_water.max(ring.len() + 1);
                let span = ring.slot_count();
                if span < self.high_water.saturating_mul(2) {
                    ring.push(id, value);
                    *next = id + 2;
                } else {
                    // Promotion visits the bounded span in ID order, including
                    // holes, so insertion order remains timestamp order.
                    let base = *next - 2 * span as u64;
                    let mut sparse = Sparse::new(self.high_water);
                    for index in 0..span {
                        let stream = base + 2 * index as u64;
                        if let Some(item) = ring.take(stream) {
                            sparse.push(stream, item);
                        }
                    }
                    sparse.push(id, value);
                    self.storage = Storage::Sparse(sparse);
                }
            }
            Storage::Sparse(sparse) => {
                if sparse.len() == 0 {
                    // Only empty windows recover. No live timestamp moves,
                    // and dense traffic can again reuse a positional ring.
                    let mut ring = H2Ring::new();
                    ring.push(id, value);
                    self.storage = Storage::Dense { ring, next: id + 2 };
                } else {
                    self.high_water = self.high_water.max(sparse.len() + 1);
                    sparse.push(id, value);
                }
            }
        }
    }

    pub(super) fn get_mut(&mut self, id: u64) -> Option<&mut T> {
        match &mut self.storage {
            Storage::Dense { ring, .. } => ring.get_mut(id),
            Storage::Sparse(sparse) => sparse.get_mut(id),
        }
    }

    pub(super) fn take(&mut self, id: u64) -> Option<T> {
        match &mut self.storage {
            Storage::Dense { ring, .. } => ring.take(id),
            Storage::Sparse(sparse) => sparse.take(id),
        }
    }

    pub(super) fn first(&self) -> Option<&T> {
        match &self.storage {
            Storage::Dense { ring, .. } => ring.slot(0),
            Storage::Sparse(sparse) => sparse.first(),
        }
    }

    pub(super) fn clear(&mut self) {
        match &mut self.storage {
            Storage::Dense { ring, .. } => ring.clear(),
            Storage::Sparse(sparse) => sparse.clear(),
        }
    }

    #[cfg(test)]
    pub(super) fn iter(&self) -> Box<dyn Iterator<Item = &T> + '_> {
        match &self.storage {
            Storage::Dense { ring, .. } => Box::new(ring.iter()),
            Storage::Sparse(sparse) => {
                let mut position = sparse.first;
                Box::new(std::iter::from_fn(move || {
                    let slot = sparse.slots.get(position)?;
                    position = slot.next;
                    slot.value.as_ref()
                }))
            }
        }
    }
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod tests;
