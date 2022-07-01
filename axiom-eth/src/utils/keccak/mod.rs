use zkevm_hashes::keccak::vanilla::keccak_packed_multi::get_keccak_capacity;

pub mod decorator;

#[cfg(test)]
pub mod tests;

// num_unusable_rows: this is not used in `configure_with_params`, only for auto-circuit tuning
// numbers from empirical tests and also from Scroll: https://github.com/scroll-tech/zkevm-circuits/blob/7d9bc181953cfc6e7baf82ff0ce651281fd70a8a/zkevm-circuits/src/keccak_circuit/keccak_packed_multi.rs#L59C55-L62C7
const UNUSABLE_ROWS_BY_ROWS_PER_ROUND: [usize; 25] = [
    23, 59, 59, 59, 59, 59, 59, 59, 55, 69, 65, 61, 47, 81, 79, 77, 75, 73, 71, 69, 67, 65, 63, 61,
    59,
];

/// Returns unusable rows for keccak circuit configured with `rows_per_round` rows per round.
/// This is only used for circuit tuning.
pub fn get_keccak_unusable_rows(rows_per_round: usize) -> usize {
    *UNUSABLE_ROWS_BY_ROWS_PER_ROUND.get(rows_per_round - 1).unwrap_or(&109)
}

/// Returns (unusable_rows, rows_per_round) that is optimal for the given `k` and `capacity`.
pub fn get_keccak_unusable_rows_from_capacity(k: usize, capacity: usize) -> (usize, usize) {
    let mut rows_per_round = 50;
    // find the largest rows per round that works, capping at 50
    let mut unusable = 109;
    while rows_per_round > 0 {
        unusable = get_keccak_unusable_rows(rows_per_round);
        let num_rows = (1 << k) - unusable;
        let avail_capacity = get_keccak_capacity(num_rows, rows_per_round);
        if avail_capacity >= capacity {
            // this rows_per_round is enough to meet our needs
            break;
        }
        rows_per_round -= 1;
    }
    assert_ne!(
        rows_per_round, 0,
        "k={} is insufficient for requested keccak capacity={}",
        k, capacity
    );
    (unusable, rows_per_round)
}

#[cfg(test)]
#[test]
fn test_get_keccak_unusable() {
    assert_eq!(get_keccak_unusable_rows_from_capacity(20, 500), (109, 50));
    assert_eq!(get_keccak_unusable_rows_from_capacity(18, 500), (69, 20));
    assert_eq!(get_keccak_unusable_rows_from_capacity(18, 2000), (59, 5));
}

#[cfg(test)]
#[test]
#[should_panic]
fn test_get_keccak_insufficient_capacity() {
    get_keccak_unusable_rows_from_capacity(18, 12_000);
}
