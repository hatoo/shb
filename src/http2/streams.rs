//! Worker request accounting, bounded by peak concurrency even when a peer
//! leaves an old response open. The protocol engine's positional ring is separate.
//!
//! The dense/sparse policy follows hatoo/xdp-http's src/http2/streams.rs
//! (b4e6075). Keep shb's existing vector ring for ordinary ordered traffic.

use crate::inflight::H2Ring;
use std::collections::BTreeMap;

pub(super) struct Streams<T> {
    storage: Storage<T>,
    high_water: usize,
}

enum Storage<T> {
    Dense { ring: H2Ring<T>, next: u64 },
    Sparse(BTreeMap<u64, T>),
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
            Storage::Sparse(tree) => tree.len(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(super) fn push(&mut self, id: u64, value: T) {
        debug_assert!(id & 1 == 1 && id <= 0x7fff_ffff);
        self.high_water = self.high_water.max(self.len() + 1);
        if matches!(&self.storage, Storage::Sparse(tree) if tree.is_empty()) {
            // Only an empty window recovers: no live timestamps move, and an
            // ordinary later window can again reuse its allocation.
            self.storage = Storage::Dense {
                ring: H2Ring::new(),
                next: id,
            };
        }
        match &mut self.storage {
            Storage::Dense { ring, next } => {
                debug_assert!(ring.is_empty() || id == *next);
                let span = ring.slot_count();
                if span < self.high_water.saturating_mul(2) {
                    ring.push(id, value);
                    *next = id + 2;
                } else {
                    // The retained span is still bounded here. Preserve holes
                    // by using IDs, not the rank among surviving requests.
                    let base = *next - 2 * span as u64;
                    let mut tree = BTreeMap::new();
                    for index in 0..span {
                        let stream = base + 2 * index as u64;
                        if let Some(item) = ring.take(stream) {
                            tree.insert(stream, item);
                        }
                    }
                    tree.insert(id, value);
                    // Release the dense allocation as well as its empty slots.
                    self.storage = Storage::Sparse(tree);
                }
            }
            Storage::Sparse(tree) => {
                let previous = tree.insert(id, value);
                debug_assert!(previous.is_none());
            }
        }
    }

    pub(super) fn get_mut(&mut self, id: u64) -> Option<&mut T> {
        match &mut self.storage {
            Storage::Dense { ring, .. } => ring.get_mut(id),
            Storage::Sparse(tree) => tree.get_mut(&id),
        }
    }

    pub(super) fn take(&mut self, id: u64) -> Option<T> {
        match &mut self.storage {
            Storage::Dense { ring, .. } => ring.take(id),
            Storage::Sparse(tree) => tree.remove(&id),
        }
    }

    pub(super) fn first(&self) -> Option<&T> {
        match &self.storage {
            Storage::Dense { ring, .. } => ring.slot(0),
            Storage::Sparse(tree) => tree.first_key_value().map(|(_, value)| value),
        }
    }

    pub(super) fn clear(&mut self) {
        match &mut self.storage {
            Storage::Dense { ring, .. } => ring.clear(),
            Storage::Sparse(tree) => tree.clear(),
        }
    }

    #[cfg(test)]
    pub(super) fn iter(&self) -> Box<dyn Iterator<Item = &T> + '_> {
        match &self.storage {
            Storage::Dense { ring, .. } => Box::new(ring.iter()),
            Storage::Sparse(tree) => Box::new(tree.values()),
        }
    }
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod tests;
