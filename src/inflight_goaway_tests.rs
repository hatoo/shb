use super::*;
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

fn check(ring: &mut H2Ring<u32>, model: &BTreeMap<u32, u32>) {
    assert_eq!(ring.len(), model.len());
    assert_eq!(
        ring.iter().copied().collect::<Vec<_>>(),
        model.values().copied().collect::<Vec<_>>()
    );
    assert_eq!(ring.slots.iter().flatten().count(), ring.open);
    assert!(ring.slots[..ring.head].iter().all(Option::is_none));
    if let Some((&first, _)) = model.first_key_value() {
        assert!(ring.slots[ring.head].is_some());
        assert_eq!((ring.base << 1) | 1, u64::from(first));
    } else {
        assert!(ring.slots.is_empty());
        assert_eq!(ring.head, 0);
        assert_eq!(ring.compact_at, COMPACT_FLOOR);
    }
    for (&id, &value) in model {
        assert_eq!(ring.get_mut(id.into()).copied(), Some(value));
        assert_eq!(ring.get_mut(u64::from(id - 1)), None);
    }
}

fn retire(ring: &mut H2Ring<u32>, model: &mut BTreeMap<u32, u32>, last: u32) {
    let expected: Vec<_> = model
        .range((Excluded(last), Unbounded))
        .map(|(&id, &v)| (id, v))
        .collect();
    let mut actual = Vec::new();
    ring.retire_after(last, |value| actual.push(value));
    assert_eq!(actual, expected.iter().map(|&(_, v)| v).collect::<Vec<_>>());
    for (id, _) in expected {
        model.remove(&id);
    }
    check(ring, model);
}

#[test]
fn suffix_retirement_matches_a_map_with_holes_moved_heads_and_high_ids() {
    for first in [1, 0x7fff_fd01] {
        for removed_prefix in [0, 1, 63, 64, 65, 129] {
            for boundary in [0, 1, 62, 63, 128, 255, 384, 510, 511, 512] {
                let mut ring = H2Ring::new();
                let mut model = BTreeMap::new();
                for i in 0..256 {
                    let id = first + 2 * i;
                    ring.push(id.into(), id);
                    model.insert(id, id);
                }
                for i in 0..256 {
                    if i < removed_prefix || i % 7 == 3 {
                        let id = first + 2 * i;
                        assert_eq!(ring.take(id.into()), model.remove(&id));
                    }
                }
                for last in [
                    u32::MAX,
                    first - 1 + boundary,
                    first - 1 + boundary,
                    first + 10,
                    0,
                ] {
                    retire(&mut ring, &mut model, last);
                }
                // Emptying the ring permits a new connection's id sequence.
                ring.push(1, 19);
                assert_eq!(ring.take(1), Some(19));
                check(&mut ring, &BTreeMap::new());
            }
        }
    }
}

#[test]
fn suffix_holes_keep_the_next_stream_position_until_the_prefix_finishes() {
    let mut ring = H2Ring::new();
    for id in [1, 3, 5, 7] {
        ring.push(id, id as u32);
    }
    ring.retire_after(2, |_| {});
    assert_eq!(ring.slot_count(), 4);
    ring.push(9, 9);
    assert_eq!(ring.take(1), Some(1));
    assert_eq!(ring.slot_count(), 1);
    assert_eq!(ring.take(9), Some(9));
    assert!(ring.is_empty());
}

#[test]
fn suffix_retirement_matches_independent_operation_sequences() {
    for mut rng in [1_u64, 71, 0x1234_5678, 0xfeed_beef] {
        let mut ring = H2Ring::new();
        let mut model = BTreeMap::new();
        let mut next = 1_u32;
        for step in 0..4000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            match rng % 10 {
                0..=4 => {
                    for _ in 0..1 + (rng >> 8) % 9 {
                        ring.push(next.into(), step);
                        model.insert(next, step);
                        next += 2;
                    }
                }
                5 | 6 => {
                    let id = (rng >> 16) as u32 % next;
                    assert_eq!(ring.take(id.into()), model.remove(&id));
                }
                7 => {
                    if let Some((&id, _)) = model.first_key_value() {
                        assert_eq!(ring.take(id.into()), model.remove(&id));
                    }
                }
                8 => retire(&mut ring, &mut model, (rng >> 24) as u32 % (next + 4)),
                _ => {
                    ring.clear();
                    model.clear();
                    next = 1;
                }
            }
            check(&mut ring, &model);
        }
    }
}

#[test]
fn unwinding_a_retirement_callback_preserves_ownership_and_ring_invariants() {
    use std::cell::RefCell;
    use std::rc::Rc;
    struct Item(u32, Rc<RefCell<Vec<u32>>>);
    impl Drop for Item {
        fn drop(&mut self) {
            self.1.borrow_mut().push(self.0);
        }
    }
    for last in [0, 4] {
        let dropped = Rc::new(RefCell::new(Vec::new()));
        let mut ring = H2Ring::new();
        for id in [1, 3, 5, 7] {
            ring.push(id.into(), Item(id, dropped.clone()));
        }
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ring.retire_after(last, |item| {
                assert_eq!(item.0, if last == 0 { 1 } else { 5 });
                panic!("callback unwinds");
            });
        }));
        assert!(panic.is_err());
        if last == 0 {
            assert!(ring.is_empty());
            assert!(ring.slots.is_empty());
        } else {
            assert_eq!(ring.len(), 3);
            assert_eq!(
                ring.iter().map(|item| item.0).collect::<Vec<_>>(),
                [1, 3, 7]
            );
        }
        ring.push(9, Item(9, dropped.clone()));
        drop(ring.take(9));
        drop(ring);
        dropped.borrow_mut().sort_unstable();
        assert_eq!(*dropped.borrow(), [1, 3, 5, 7, 9]);
    }
}
