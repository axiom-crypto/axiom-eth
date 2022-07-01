use crate::Field;
use ethers_core::{
    types::{Address, H256},
    utils::keccak256,
};
use halo2_base::{
    gates::{GateInstructions, RangeChip},
    halo2_proofs::halo2curves::ff::PrimeField,
    safe_types::{SafeBool, SafeByte, SafeBytes32, SafeTypeChip},
    utils::{decompose, BigPrimeField, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Witness},
};
use itertools::Itertools;

use self::hilo::HiLo;

/// Traits and templates for concrete `Circuit` implementation and compatibility with [snark_verifier_sdk]
pub mod build_utils;
/// Utilities for circuit writing using [halo2_base]
pub mod circuit_utils;
/// Component framework.
pub mod component;
/// Contains convenience `EthCircuitInstructions` to help auto-implement a Halo2 circuit that uses `RlcCircuitBuilder` and `KeccakPromiseLoader`.
pub mod eth_circuit;
/// Same as Word2 from zkevm
pub mod hilo;
/// Shim for keccak circuit from [axiom_eth::zkevm_hashes::keccak]
pub mod keccak;
/// Non-universal aggregation circuit that verifies several snarks and computes the merkle root
/// of snark inputs. See [InputMerkleAggregation] for more details.
#[cfg(feature = "aggregation")]
pub mod merkle_aggregation;
/// Snark verifier SDK helpers (eventually move to snark-verifier-sdk)
#[cfg(feature = "aggregation")]
pub mod snark_verifier;

pub const DEFAULT_RLC_CACHE_BITS: usize = 32;

/// H256 as hi-lo (u128, u128)
pub type AssignedH256<F> = [AssignedValue<F>; 2];

pub fn get_merkle_mountain_range(leaves: &[H256], max_depth: usize) -> Vec<H256> {
    let num_leaves = leaves.len();
    let mut merkle_roots = Vec::with_capacity(max_depth + 1);
    let mut start_idx = 0;
    for depth in (0..max_depth + 1).rev() {
        if (num_leaves >> depth) & 1 == 1 {
            merkle_roots.push(h256_tree_root(&leaves[start_idx..start_idx + (1 << depth)]));
            start_idx += 1 << depth;
        } else {
            merkle_roots.push(H256::zero());
        }
    }
    merkle_roots
}

/// # Assumptions
/// * `leaves` should not be empty
pub fn h256_tree_root(leaves: &[H256]) -> H256 {
    assert!(!leaves.is_empty(), "leaves should not be empty");
    let depth = leaves.len().ilog2();
    assert_eq!(leaves.len(), 1 << depth);
    if depth == 0 {
        return leaves[0];
    }
    keccak256_tree_root(leaves.iter().map(|leaf| leaf.as_bytes().to_vec()).collect())
}

pub fn keccak256_tree_root(mut leaves: Vec<Vec<u8>>) -> H256 {
    assert!(leaves.len() > 1);
    let depth = leaves.len().ilog2();
    assert_eq!(leaves.len(), 1 << depth, "leaves.len() must be a power of 2");
    for d in (0..depth).rev() {
        for i in 0..(1 << d) {
            leaves[i] = keccak256([&leaves[2 * i][..], &leaves[2 * i + 1][..]].concat()).to_vec();
        }
    }
    H256::from_slice(&leaves[0])
}

// Field has PrimeField<Repr = [u8; 32]>
/// Takes `hash` as `bytes32` and returns `(hash[..16], hash[16..])` represented as big endian numbers in the prime field
pub fn encode_h256_to_hilo<F: PrimeField>(hash: &H256) -> HiLo<F> {
    let hash_lo = u128::from_be_bytes(hash[16..].try_into().unwrap());
    let hash_hi = u128::from_be_bytes(hash[..16].try_into().unwrap());
    HiLo::from_lo_hi([hash_lo, hash_hi].map(F::from_u128))
}

pub fn encode_addr_to_field<F: ScalarField<Repr = [u8; 32]>>(input: &Address) -> F {
    let mut bytes = input.as_bytes().to_vec();
    bytes.reverse();
    let mut repr = [0u8; 32];
    repr[..20].copy_from_slice(&bytes);
    F::from_bytes_le(&repr)
}

pub fn bytes_to_fe<F: Field>(bytes: &[u8]) -> Vec<F> {
    bytes.iter().map(|b| F::from(*b as u64)).collect()
}

// circuit utils:

/// Assigns `bytes` as private witnesses **without** range checking.
pub fn unsafe_bytes_to_assigned<F: Field>(
    ctx: &mut Context<F>,
    bytes: &[u8],
) -> Vec<AssignedValue<F>> {
    ctx.assign_witnesses(bytes.iter().map(|b| F::from(*b as u64)))
}

/// **Unsafe:** Resize `bytes` and assign as private witnesses **without** range checking.
pub fn assign_vec<F: ScalarField>(
    ctx: &mut Context<F>,
    bytes: Vec<u8>,
    max_len: usize,
) -> Vec<AssignedValue<F>> {
    let mut newbytes = bytes;
    assert!(newbytes.len() <= max_len);
    newbytes.resize(max_len, 0);
    newbytes.into_iter().map(|byte| ctx.load_witness(F::from(byte as u64))).collect_vec()
}

/// Enforces `lhs` equals `rhs` only if `cond` is true.
///
/// Assumes that `cond` is a bit.
pub fn enforce_conditional_equality<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    lhs: AssignedValue<F>,
    rhs: AssignedValue<F>,
    cond: SafeBool<F>,
) {
    let [lhs, rhs] = [lhs, rhs].map(|x| gate.mul(ctx, x, cond));
    ctx.constrain_equal(&lhs, &rhs);
}

/// Assumes that `bytes` have witnesses that are bytes.
pub fn bytes_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[SafeByte<F>],
) -> Vec<AssignedValue<F>> {
    limbs_be_to_u128(ctx, gate, bytes, 8)
}

pub(crate) fn limbs_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    limbs: &[impl AsRef<AssignedValue<F>>],
    limb_bits: usize,
) -> Vec<AssignedValue<F>> {
    assert!(!limbs.is_empty(), "limbs must not be empty");
    assert_eq!(128 % limb_bits, 0);
    limbs
        .chunks(128 / limb_bits)
        .map(|chunk| {
            gate.inner_product(
                ctx,
                chunk.iter().rev().map(|a| *a.as_ref()),
                (0..chunk.len()).map(|idx| Constant(gate.pow_of_two()[limb_bits * idx])),
            )
        })
        .collect_vec()
}

/// Decomposes `uint` into `num_bytes` bytes, in big-endian, and constrains the decomposition.
/// Here `uint` can be any uint that fits into `F`.
pub fn uint_to_bytes_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    uint: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<SafeByte<F>> {
    let mut bytes_be = uint_to_bytes_le(ctx, range, uint, num_bytes);
    bytes_be.reverse();
    bytes_be
}

/// Decomposes `uint` into `num_bytes` bytes, in little-endian, and constrains the decomposition.
/// Here `uint` can be any uint that fits into `F`.
pub fn uint_to_bytes_le<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    uint: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<SafeByte<F>> {
    // Same logic as RangeChip::range_check
    let pows = range.gate.pow_of_two().iter().step_by(8).take(num_bytes).map(|x| Constant(*x));
    let byte_vals = decompose(uint.value(), num_bytes, 8).into_iter().map(Witness);
    let (acc, bytes_le) = range.gate.inner_product_left(ctx, byte_vals, pows);
    ctx.constrain_equal(&acc, uint);

    let safe = SafeTypeChip::new(range);
    safe.raw_to_fix_len_bytes_vec(ctx, bytes_le, num_bytes).into_bytes()
}

pub fn bytes_be_to_uint<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input: &[SafeByte<F>],
    num_bytes: usize,
) -> AssignedValue<F> {
    gate.inner_product(
        ctx,
        input[..num_bytes].iter().rev().map(|b| *b.as_ref()),
        (0..num_bytes).map(|idx| Constant(gate.pow_of_two()[8 * idx])),
    )
}

/// Converts a fixed length array of `u128` values into a fixed length array of big endian bytes.
pub fn u128s_to_bytes_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    u128s: &[AssignedValue<F>],
) -> Vec<SafeByte<F>> {
    u128s.iter().map(|u128| uint_to_bytes_be(ctx, range, u128, 16)).concat()
}

pub fn constrain_vec_equal<F: Field>(
    ctx: &mut Context<F>,
    a: &[impl AsRef<AssignedValue<F>>],
    b: &[impl AsRef<AssignedValue<F>>],
) {
    for (left, right) in a.iter().zip_eq(b.iter()) {
        let left = left.as_ref();
        let right = right.as_ref();
        // debug_assert_eq!(left.value(), right.value());
        ctx.constrain_equal(left, right);
    }
}

/// Returns 1 if all entries of `input` are zero, 0 otherwise.
pub fn is_zero_vec<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input: &[impl AsRef<AssignedValue<F>>],
) -> AssignedValue<F> {
    let is_zeros = input.iter().map(|x| gate.is_zero(ctx, *x.as_ref())).collect_vec();
    let sum = gate.sum(ctx, is_zeros);
    let total_len = F::from(input.len() as u64);
    gate.is_equal(ctx, sum, Constant(total_len))
}

/// Load [H256] as private witness as [SafeBytes32], where bytes have been range checked.
pub fn load_h256_to_safe_bytes32<F: ScalarField>(
    ctx: &mut Context<F>,
    safe: &SafeTypeChip<F>,
    hash: H256,
) -> SafeBytes32<F> {
    load_bytes32(ctx, safe, hash.0)
}

pub fn load_bytes32<F: ScalarField>(
    ctx: &mut Context<F>,
    safe: &SafeTypeChip<F>,
    bytes: [u8; 32],
) -> SafeBytes32<F> {
    let raw = ctx.assign_witnesses(bytes.map(|b| F::from(b as u64)));
    safe.raw_bytes_to(ctx, raw)
}
