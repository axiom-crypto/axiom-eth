//! Aggregation circuit involving both Poseidon and Keccak hashes. This is used for  
//! aggregation of a single column response, from initial circuits such as
//! `Multi{Block,Account,Storage}Circuit`.

use std::rc::Rc;

use halo2_base::{
    gates::{RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::CurveAffine,
    AssignedValue,
};
use itertools::Itertools;
use snark_verifier::{
    loader::halo2::{Halo2Loader, Scalar},
    util::hash::Poseidon,
};

use crate::{
    batch_query::{
        hash::{keccak_packed, poseidon_onion, poseidon_tree_root},
        response::FixedByteArray,
        EccInstructions,
    },
    keccak::KeccakChip,
    util::{bytes_be_to_u128, u128s_to_bytes_be},
    Field,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashStrategy {
    Tree,
    Onion,
}

/// Aggregates snarks and computes keccak and Poseidon Merkle roots of previous public instances.
///
/// We assume public instances in previous `snarks`, other than old accumulators, come in repeating chunks of size `chunk_size`.
///
/// Computes the Keccak Merkle roots
/// * `keccak_strategy[H256(instance[chunk_size * j + i .. chunk_size * j + i + 2]) for all j])` for each `i` in `keccak_indices`.
///
/// and the Poseidon Merkle roots
/// * `poseidon_strategy([instance[chunk_size * j + i] for all j])` for each `i` in `poseidon_indices`
///
/// where `H256([hi,lo])` assumes that `hi, lo` are `u128` and forms the 256-bit integer `hi << 128 | lo`.
///
/// Here `keccak_strategy` means `keccak_merkle_root` if `strategy == Tree` or `keccak(a_0 . keccak(a_1 . keccak( ... )))` if `strategy == Onion`.
/// Similarly for `poseidon`.
///
/// Returns:
/// * Poseidon roots (`poseidon_indices.len()` field elements)
/// * Keccak roots (`keccak_indices.len() * 2` field elements in hi-lo u128 form)
///
/// # Panics
/// If `strategy == Tree` and `instance.len() / chunk_size` is not a power of 2.
#[allow(clippy::too_many_arguments)]
pub fn merklelize_instances<F, C, EccChip, const T: usize, const RATE: usize>(
    strategy: HashStrategy,
    instances: &[AssignedValue<F>],
    chunk_size: usize,
    poseidon_indices: &[usize],
    keccak_indices: &[usize],
    loader: &Rc<Halo2Loader<C, EccChip>>,
    poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
    range: &RangeChip<F>,
    keccak: &mut KeccakChip<F>,
) -> Vec<AssignedValue<F>>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
    EccChip: EccInstructions<F, C>,
{
    for idx in poseidon_indices.iter().chain(keccak_indices.iter()) {
        assert!(*idx < chunk_size, "poseidon and keccak indices must be < chunk_size");
    }
    let mut tmp_builder = loader.ctx_mut();
    // keccak tree root
    let ctx = tmp_builder.main(0);
    // get hi-lo u128s from previous instances and convert to bytes
    let mut keccak_leaves = vec![vec![]; keccak_indices.len()];
    for chunk in instances.chunks_exact(chunk_size) {
        for (leaves, &idx) in keccak_leaves.iter_mut().zip(keccak_indices.iter()) {
            let hi_lo = &chunk[idx..idx + 2];
            leaves.push(u128s_to_bytes_be(ctx, range, hi_lo));
        }
    }
    // compute the keccak merkle roots
    let keccak_roots = keccak_leaves
        .iter()
        .flat_map(|leaves| {
            let bytes = match strategy {
                HashStrategy::Tree => keccak.merkle_tree_root(ctx, range.gate(), leaves),
                HashStrategy::Onion => {
                    let mut onion = FixedByteArray(leaves[0].clone());
                    for leaf in &leaves[1..] {
                        onion = keccak_packed(
                            ctx,
                            range.gate(),
                            keccak,
                            FixedByteArray([onion.as_ref(), &leaf[..]].concat()),
                        );
                    }
                    onion.0
                }
            };
            bytes_be_to_u128(ctx, range.gate(), &bytes)
        })
        .collect_vec();
    debug_assert_eq!(keccak_roots.len(), keccak_indices.len() * 2);
    drop(tmp_builder);

    // compute the poseidon merkle roots
    // load field elements from prev instances to Scalar
    let mut poseidon_leaves = vec![vec![]; poseidon_indices.len()];
    for chunk in instances.chunks_exact(chunk_size) {
        for (leaves, &idx) in poseidon_leaves.iter_mut().zip(poseidon_indices.iter()) {
            leaves.push(loader.scalar_from_assigned(chunk[idx]));
        }
    }
    let poseidon_roots = poseidon_leaves
        .into_iter()
        .map(|leaves| match strategy {
            HashStrategy::Tree => poseidon_tree_root(poseidon, leaves, &[]).into_assigned(),
            HashStrategy::Onion => {
                poseidon_onion(poseidon, leaves.into_iter().map(|leaf| leaf.into())).into_assigned()
            }
        })
        .collect_vec();

    [keccak_roots, poseidon_roots].concat()
}
