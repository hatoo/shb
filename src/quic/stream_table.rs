//! Client bidirectional streams in opening order. Ordinary traffic indexes a
//! deque directly; a delayed old stream must not retain every completed slot.

use std::collections::VecDeque;

pub(super) struct StreamTable<T> {
    slots: VecDeque<Option<T>>,
    base: u64,
    open: usize,
    sparse: Option<Box<SparseIds>>,
}

struct SparseIds {
    /// Stream numbers parallel to slots, sorted even when slots contain holes.
    ids: VecDeque<u64>,
    /// Packing can discard completed tail slots, but their ids cannot be reused.
    next: u64,
}

const PACK_FLOOR: usize = 64;

impl<T> StreamTable<T> {
    pub(super) fn new() -> Self {
        Self {
            slots: VecDeque::new(),
            base: 0,
            open: 0,
            sparse: None,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(super) fn push(&mut self, id: u64, item: T) {
        debug_assert_eq!(id & 3, 0);
        // Amortize packing over at least a window of completed streams. This
        // check does not allocate or move anything on the ordinary dense path.
        if self.slots.len() >= self.open.max(PACK_FLOOR).saturating_mul(2) {
            self.pack();
        }
        let n = id / 4;
        if let Some(sparse) = &mut self.sparse {
            debug_assert_eq!(n, sparse.next, "streams are opened in order");
            sparse.ids.push_back(n);
            sparse.next = n + 1;
        } else {
            if self.slots.is_empty() {
                self.base = n;
            }
            debug_assert_eq!(n, self.base + self.slots.len() as u64);
        }
        self.slots.push_back(Some(item));
        self.open += 1;
    }

    fn index(&self, id: u64) -> Option<usize> {
        if id & 3 != 0 {
            return None;
        }
        let n = id / 4;
        if let Some(sparse) = &self.sparse {
            return sparse.ids.binary_search(&n).ok();
        }
        let i = n.checked_sub(self.base)?;
        (i < self.slots.len() as u64).then_some(i as usize)
    }

    pub(super) fn get(&self, id: u64) -> Option<&T> {
        self.slots[self.index(id)?].as_ref()
    }

    pub(super) fn get_mut(&mut self, id: u64) -> Option<&mut T> {
        let i = self.index(id)?;
        self.slots[i].as_mut()
    }

    /// The just-opened stream, avoiding another id lookup in send_oneshot.
    pub(super) fn back_mut(&mut self) -> Option<&mut T> {
        self.slots.back_mut()?.as_mut()
    }

    pub(super) fn take(&mut self, id: u64) -> Option<T> {
        let i = self.index(id)?;
        let item = self.slots[i].take()?;
        self.open -= 1;
        if i == 0 {
            while matches!(self.slots.front(), Some(None)) {
                self.slots.pop_front();
                if let Some(sparse) = &mut self.sparse {
                    sparse.ids.pop_front();
                } else {
                    self.base += 1;
                }
            }
            self.restore_dense();
        }
        Some(item)
    }

    /// A contiguous suffix ending at the last opened id can use positions as
    /// ids again. A packed-away tail must keep sparse mode until it is crossed.
    fn restore_dense(&mut self) {
        let Some(sparse) = &self.sparse else {
            return;
        };
        if let Some(&first) = sparse.ids.front() {
            if sparse.next - first != self.slots.len() as u64 {
                return;
            }
            self.base = first;
        } else {
            self.base = sparse.next;
        }
        self.sparse = None;
        self.slots.shrink_to(self.open.max(PACK_FLOOR));
    }

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
            self.restore_dense();
        } else {
            let next = self.base + self.slots.len() as u64;
            let capacity = self.open.max(PACK_FLOOR);
            let mut slots = VecDeque::with_capacity(capacity);
            let mut ids = VecDeque::with_capacity(capacity);
            for (i, slot) in self.slots.drain(..).enumerate() {
                if let Some(item) = slot {
                    slots.push_back(Some(item));
                    ids.push_back(self.base + i as u64);
                }
            }
            self.slots = slots;
            self.sparse = Some(Box::new(SparseIds { ids, next }));
        }
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.slots.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn a_delayed_stream_bounds_storage_by_the_live_window() {
        let mut table = StreamTable::new();
        for n in 0..32 {
            table.push(n * 4, n);
        }
        for n in 32..100_032 {
            table.push(n * 4, n);
            assert_eq!(table.take((n - 31) * 4), Some(n - 31));
            assert_eq!(table.get(0), Some(&0));
            assert!(table.capacity() <= 128);
            assert_eq!(table.open, 32);
        }
        assert!(table.sparse.is_some());
        // The connection stays nonempty as the gap closes.
        assert_eq!(table.take(0), Some(0));
        assert!(table.sparse.is_none());
        assert_eq!(table.capacity(), 64);
        for n in 100_032..101_032 {
            table.push(n * 4, n);
            assert_eq!(table.take((n - 31) * 4), Some(n - 31));
        }
        assert!(table.sparse.is_none());
        assert_eq!(table.open, 31);
    }

    #[test]
    fn sparse_storage_matches_an_ordered_reference() {
        let mut table = StreamTable::new();
        let mut model = BTreeMap::new();
        let mut next = 0;
        let mut rng = 0x7289_034f_9170_u64;
        for _ in 0..4 {
            // Wrap the deque and advance its base before migration.
            for _ in 0..37 {
                table.push(next * 4, (next, 0));
                assert_eq!(table.take(next * 4), Some((next, 0)));
                next += 1;
            }
            for _ in 0..7 {
                table.push(next * 4, (next, next));
                model.insert(next * 4, (next, next));
                next += 1;
            }
            for _ in 0..400 {
                table.push(next * 4, (next, 0));
                assert_eq!(table.take(next * 4), Some((next, 0)));
                next += 1;
            }
            assert!(table.sparse.is_some());
            for _ in 0..10_000 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                if model.len() < 64 && (model.len() < 2 || rng & 1 == 0) {
                    table.push(next * 4, (next, rng));
                    model.insert(next * 4, (next, rng));
                    next += 1;
                } else {
                    let id = *model
                        .keys()
                        .nth((rng >> 32) as usize % model.len())
                        .unwrap();
                    assert_eq!(table.take(id), model.remove(&id));
                    assert_eq!(table.take(id), None);
                }
                assert_eq!(table.open, model.len());
                for (&id, value) in &mut model {
                    value.1 ^= 1;
                    table.get_mut(id).unwrap().1 ^= 1;
                    assert_eq!(table.get(id), Some(&*value));
                    for wrong in 1..=3 {
                        assert!(table.get(id | wrong).is_none());
                    }
                }
                assert!(table.get(next * 4).is_none());
            }
            for (id, value) in std::mem::take(&mut model) {
                assert_eq!(table.take(id), Some(value));
            }
            assert_eq!(table.open, 0);
            assert_eq!(table.len(), 0);
            assert!(table.sparse.is_none());
        }
    }

    #[test]
    fn sparse_completion_orders_preserve_identity() {
        fn permute(ids: &mut [u64; 6], at: usize) {
            if at != ids.len() {
                for i in at..ids.len() {
                    ids.swap(at, i);
                    permute(ids, at + 1);
                    ids.swap(at, i);
                }
                return;
            }
            let mut table = StreamTable::new();
            for n in 0..6 {
                table.push(n * 4, n);
            }
            for n in 6..400 {
                table.push(n * 4, n);
                assert_eq!(table.take(n * 4), Some(n));
            }
            assert!(table.sparse.is_some());
            for &mut n in ids {
                assert_eq!(table.take(n * 4), Some(n));
                assert_eq!(table.take(n * 4), None);
            }
            assert!(table.sparse.is_none());
            table.push(1600, 400);
            assert_eq!(table.take(1600), Some(400));
        }
        permute(&mut [0, 1, 2, 3, 4, 5], 0);
    }

    #[test]
    fn packed_tails_and_large_ids_cannot_alias_new_streams() {
        let first = (1_u64 << 60) - 512;
        let mut table = StreamTable::new();
        table.push(first * 4, first);
        for n in first + 1..first + 300 {
            table.push(n * 4, n);
            assert_eq!(table.take(n * 4), Some(n));
        }
        table.pack();
        assert_eq!(table.len(), 1);
        assert!(
            table.sparse.is_some(),
            "the discarded tail prevents dense indexing"
        );
        assert!(table.get((first + 1) * 4).is_none());
        table.push((first + 300) * 4, first + 300);
        assert_eq!(table.back_mut().copied(), Some(first + 300));
        assert_eq!(table.take(first * 4), Some(first));
        assert!(table.sparse.is_none());
        assert_eq!(table.get((first + 300) * 4), Some(&(first + 300)));
    }

    #[test]
    fn packing_and_drop_release_each_value_once() {
        use std::cell::Cell;
        struct Item<'a>(&'a Cell<usize>);
        impl Drop for Item<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let mut table = StreamTable::new();
        table.push(0, Item(&drops));
        for n in 1..10_000 {
            table.push(n * 4, Item(&drops));
            drop(table.take(n * 4).unwrap());
        }
        assert_eq!(drops.get(), 9999);
        drop(table);
        assert_eq!(drops.get(), 10_000);
    }
}
