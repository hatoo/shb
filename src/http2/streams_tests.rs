use super::*;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

fn check(slots: &mut Streams<u64>, model: &BTreeMap<u64, u64>) {
    assert_eq!(slots.len(), model.len());
    assert_eq!(slots.is_empty(), model.is_empty());
    assert_eq!(slots.first(), model.first_key_value().map(|(_, v)| v));
    assert!(slots.iter().eq(model.values()));
    for (&id, &value) in model {
        assert_eq!(slots.get_mut(id).copied(), Some(value));
        assert_eq!(slots.get_mut(id - 1), None);
    }
    if let Storage::Dense { ring, .. } = &slots.storage {
        assert!(ring.slot_count() <= 2 * slots.high_water);
    } else if let Storage::Sparse(sparse) = &slots.storage {
        assert!(sparse.slots.len() <= slots.high_water);
        let mut visited = vec![false; sparse.slots.len()];
        let mut position = sparse.first;
        let mut prev = NONE;
        for &id in model.keys() {
            assert_eq!(sparse.index[&id], position);
            assert!(!visited[position]);
            visited[position] = true;
            let slot = &sparse.slots[position];
            assert_eq!(slot.prev, prev);
            assert!(slot.value.is_some());
            prev = position;
            position = slot.next;
        }
        assert_eq!(position, NONE);
        assert_eq!(prev, sparse.last);
        position = sparse.free;
        while position != NONE {
            assert!(!visited[position]);
            visited[position] = true;
            assert!(sparse.slots[position].value.is_none());
            position = sparse.slots[position].next;
        }
        assert!(visited.iter().all(|v| *v));
    }
}

#[test]
fn pinned_cohorts_keep_exact_values_without_lifetime_slots() {
    let mut slots = Streams::new();
    let mut model = BTreeMap::new();
    slots.push(1, 123);
    model.insert(1, 123);
    let mut next = 3;
    for _ in 0..1000 {
        let start = next;
        for _ in 0..31 {
            slots.push(next, next);
            model.insert(next, next);
            next += 2;
        }
        check(&mut slots, &model);
        for index in (0..31).rev() {
            let id = start + 2 * index;
            *slots.get_mut(id).unwrap() += 1;
            *model.get_mut(&id).unwrap() += 1;
            assert_eq!(slots.take(id), model.remove(&id));
            assert_eq!(slots.take(id), None);
            assert_eq!(slots.get_mut(id), None);
        }
        check(&mut slots, &model);
    }
    assert!(matches!(&slots.storage, Storage::Sparse(tree) if tree.len() == 1));
    assert_eq!(slots.take(1), Some(123));
    assert_eq!(slots.first(), None);
    slots.push(next, 456);
    assert!(matches!(slots.storage, Storage::Dense { .. }));
    assert_eq!(slots.take(next), Some(456));
}

#[test]
fn ordinary_sliding_windows_stay_dense() {
    let mut slots = Streams::new();
    for id in (1..64).step_by(2) {
        slots.push(id, id);
    }
    for id in (65..200_001).step_by(2) {
        assert_eq!(slots.take(id - 64), Some(id - 64));
        slots.push(id, id);
        assert_eq!(slots.first(), Some(&(id - 62)));
        assert_eq!(slots.len(), 32);
        assert!(matches!(slots.storage, Storage::Dense { .. }));
    }
}

#[test]
fn mixed_lifecycles_match_an_independent_ordered_ledger() {
    for seed in 1..=16u64 {
        let mut random = seed;
        let mut slots = Streams::new();
        let mut model = BTreeMap::new();
        let mut next = 1;
        for _ in 0..5000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            match random % 8 {
                0..=3 if model.len() < 32 => {
                    slots.push(next, random);
                    model.insert(next, random);
                    next += 2;
                }
                4 => {
                    let id = (random % next) | 1;
                    assert_eq!(slots.take(id), model.remove(&id));
                }
                5 => {
                    if let Some((&id, _)) = model.first_key_value() {
                        assert_eq!(slots.take(id), model.remove(&id));
                    }
                }
                6 if random & 0xff == 6 => {
                    slots.clear();
                    model.clear();
                    next = 1;
                }
                _ => {}
            }
            check(&mut slots, &model);
        }
    }
}

#[test]
fn promotion_clear_recovery_and_drop_own_every_value_once() {
    struct Item(Rc<Cell<usize>>);
    impl Drop for Item {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops: Vec<_> = (0..1024).map(|_| Rc::new(Cell::new(0))).collect();
    let mut slots = Streams::new();
    for cycle in 0..4 {
        let base = cycle * 256;
        for i in 0..256 {
            slots.push(1 + 2 * i as u64, Item(drops[base + i].clone()));
            if i % 8 != 0 {
                drop(slots.take(1 + 2 * i as u64).unwrap());
            }
        }
        assert!(matches!(slots.storage, Storage::Sparse(_)));
        for i in 0..256 {
            assert_eq!(drops[base + i].get(), usize::from(i % 8 != 0));
        }
        if cycle < 3 {
            slots.clear();
            assert!(slots.is_empty());
            assert!(drops[..base + 256].iter().all(|d| d.get() == 1));
        }
    }
    drop(slots);
    assert!(drops.iter().all(|d| d.get() == 1));
}

#[test]
fn near_stream_id_limit_and_reconnect_cannot_alias_old_slots() {
    let mut slots = Streams::new();
    let first = 0x7fff_ffff - 256;
    slots.push(first, first);
    for id in ((first + 2)..=0x7fff_ffff).step_by(2) {
        slots.push(id, id);
        assert_eq!(slots.take(id - 1), None);
        assert_eq!(slots.take(id), Some(id));
    }
    assert!(matches!(slots.storage, Storage::Sparse(_)));
    assert_eq!(slots.first(), Some(&first));
    assert_eq!(slots.get_mut(0x8000_0001), None);
    slots.clear();
    slots.push(1, 99);
    assert_eq!(slots.take(first), None);
    assert_eq!(slots.take(1), Some(99));
    assert!(slots.is_empty());
}

#[test]
fn sparse_slots_recycle_after_arbitrary_unlinks_without_stale_aliases() {
    let mut slots = Streams::new();
    let mut model = BTreeMap::new();
    slots.push(1, 1);
    model.insert(1, 1);
    // Force promotion before growing concurrency; exercise arena and map growth.
    for id in (3..19).step_by(2) {
        slots.push(id, id);
        assert_eq!(slots.take(id), Some(id));
    }
    assert!(matches!(slots.storage, Storage::Sparse(_)));
    for id in (19..147).step_by(2) {
        slots.push(id, id);
        model.insert(id, id);
    }
    let mut next = 147;
    let mut stale = Vec::new();
    for round in 0..256 {
        // Alternate oldest, newest and middle: both adjacent links and the
        // oldest pointer must survive slots being reused in a different order.
        let rank = match round % 3 {
            0 => 0,
            1 => model.len() - 1,
            _ => model.len() / 2,
        };
        let id = *model.keys().nth(rank).unwrap();
        assert_eq!(slots.take(id), model.remove(&id));
        stale.push(id);
        slots.push(next, next);
        model.insert(next, next);
        next += 2;
        for &id in &stale {
            assert_eq!(slots.get_mut(id), None);
            assert_eq!(slots.take(id), None);
        }
        check(&mut slots, &model);
    }
    let Storage::Sparse(sparse) = &slots.storage else {
        panic!("a nonempty sparse window must stay sparse");
    };
    assert_eq!(sparse.slots.len(), 65);
    assert!(sparse.slots.capacity() < 4 * 65);
    // No lifetime growth in the stream-ID index after repeated deletions.
    assert!(sparse.index.capacity() < 4 * 65);
}
