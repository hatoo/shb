//! Behavioral checks for pending flushes, using an ordered set as the oracle.
//! Keep these independent of the queue's storage representation.

use super::PendingFlush;
use std::collections::BTreeSet;

fn drain(pending: &mut PendingFlush) -> Vec<usize> {
    let mut seen = Vec::new();
    pending
        .drain(|index| {
            seen.push(index);
            Ok(())
        })
        .unwrap();
    seen
}

#[test]
fn ordered_set_oracle_covers_empty_sparse_dense_and_repeated_batches() {
    for count in [0, 1, 63, 64, 65, 127, 128, 4095, 4096, 4097, 16384, 16385] {
        let mut pending = PendingFlush::new(count);
        let mut expected = BTreeSet::new();
        let mut seed = 0xfedc_ba98_7654_3210_u64;
        for round in 0..24 {
            // Independent ordering/deduplication oracle. Alternate empty,
            // random, reverse-dense and repeated marks with the same storage.
            let marks = match round % 4 {
                0 => 0,
                1 => count / 3 + usize::from(count != 0),
                _ => count,
            };
            for n in 0..marks {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let index = if round % 4 == 2 {
                    count - n - 1
                } else {
                    seed as usize % count
                };
                expected.insert(index);
                for _ in 0..=round % 3 {
                    pending.mark(index);
                }
            }
            assert_eq!(
                drain(&mut pending),
                expected.iter().copied().collect::<Vec<_>>(),
                "count={count}, round={round}"
            );
            expected.clear();
            assert!(drain(&mut pending).is_empty());
        }
    }
}

#[test]
fn partial_words_and_large_boundaries_keep_index_order() {
    let marks = [16384, 8192, 8191, 4097, 4096, 4095, 65, 64, 63, 0];
    let expected: Vec<_> = marks
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut pending = PendingFlush::new(16385);
    for _ in 0..4 {
        for index in marks {
            pending.mark(index);
            pending.mark(index);
        }
        assert_eq!(drain(&mut pending), expected);
    }
}

#[test]
fn callback_errors_preserve_all_later_words_for_the_next_drain() {
    for dense in [false, true] {
        for failed in [0, 1, 62, 63, 64, 65, 4095, 4096, 4097, 8192] {
            let mut pending = PendingFlush::new(8257);
            let mut expected: BTreeSet<_> = if dense {
                (0..8257).collect()
            } else {
                [0, 63, 64, 65, 127, 128, 4095, 4096, 4097, 8191, 8192, 8256]
                    .into_iter()
                    .collect()
            };
            expected.insert(failed);
            for &index in expected.iter().rev() {
                pending.mark(index);
            }
            let mut visited = Vec::new();
            let error = pending
                .drain(|index| {
                    visited.push(index);
                    if index == failed {
                        anyhow::bail!("injected flush failure");
                    }
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.to_string(), "injected flush failure");
            assert_eq!(
                visited,
                expected.range(..=failed).copied().collect::<Vec<_>>()
            );

            // A drain consumes the whole 64-slot word before its callbacks.
            // On failure, later words must survive for the next drain.
            expected.retain(|index| index / 64 > failed / 64);
            // New completions may re-mark an already consumed word.
            for index in [0, failed, 64, 4096, 8256] {
                pending.mark(index);
                expected.insert(index);
            }
            assert_eq!(
                drain(&mut pending),
                expected.into_iter().collect::<Vec<_>>()
            );
            assert!(drain(&mut pending).is_empty());
        }
    }
}

#[test]
fn word_boundaries_consume_the_failed_word_before_remarking() {
    for count in [1, 63, 64, 65] {
        for failed in 0..count {
            for dense in [false, true] {
                let mut pending = PendingFlush::new(count);
                let mut expected: BTreeSet<_> = if dense {
                    (0..count).collect()
                } else {
                    [0, failed, count - 1].into_iter().collect()
                };
                for &index in expected.iter().rev() {
                    pending.mark(index);
                    pending.mark(index);
                }
                let mut seen = Vec::new();
                let result = pending.drain(|index| {
                    seen.push(index);
                    if index == failed {
                        anyhow::bail!("boundary failure");
                    }
                    Ok(())
                });
                assert_eq!(result.unwrap_err().to_string(), "boundary failure");
                assert_eq!(seen, expected.range(..=failed).copied().collect::<Vec<_>>());
                expected.retain(|index| index / 64 > failed / 64);
                assert_eq!(
                    drain(&mut pending),
                    expected.into_iter().collect::<Vec<_>>()
                );
                assert!(drain(&mut pending).is_empty());
                for index in [count - 1, failed, 0, failed] {
                    pending.mark(index);
                }
                assert_eq!(
                    drain(&mut pending),
                    [0, failed, count - 1]
                        .into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}
