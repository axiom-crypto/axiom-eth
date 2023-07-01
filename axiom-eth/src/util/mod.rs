use super::Field;
use crate::{rlp::builder::RlcThreadBreakPoints, ETH_LOOKUP_BITS};
use ethers_core::{
    types::{Address, H256, U256},
    utils::keccak256,
};
use halo2_base::{
    gates::{
        builder::{FlexGateConfigParams, MultiPhaseThreadBreakPoints},
        flex_gate::GateStrategy,
        GateInstructions, RangeChip, RangeInstructions,
    },
    utils::{bit_length, decompose, decompose_fe_to_u64_limbs, BigPrimeField, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::halo2::aggregation::AggregationConfigParams;
use std::{
    env::{set_var, var},
    fs::File,
    iter,
    path::Path,
};

#[cfg(feature = "aggregation")]
pub mod circuit;
#[cfg(feature = "aggregation")]
pub mod scheduler;

pub(crate) const NUM_BYTES_IN_U128: usize = 16;

pub type AssignedH256<F> = [AssignedValue<F>; 2]; // H256 as hi-lo (u128, u128)

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EthConfigParams {
    pub degree: u32,
    // number of SecondPhase advice columns used in RlcConfig
    pub num_rlc_columns: usize,
    // the number of advice columns in phase _ without lookup enabled that RangeConfig uses
    pub num_range_advice: Vec<usize>,
    // the number of advice columns in phase _ with lookup enabled that RangeConfig uses
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    // for keccak chip you should know the number of unusable rows beforehand
    pub unusable_rows: usize,
    pub keccak_rows_per_round: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_bits: Option<usize>,
}

impl EthConfigParams {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        serde_json::from_reader(File::open(&path).expect("path does not exist")).unwrap()
    }
}

pub trait Halo2ConfigPinning: Serialize {
    type BreakPoints;
    /// Loads configuration parameters from a file and sets environmental variables.
    fn from_path<P: AsRef<Path>>(path: P) -> Self;
    /// Loads configuration parameters into environment variables.
    fn set_var(&self);
    /// Returns break points
    fn break_points(self) -> Self::BreakPoints;
    /// Constructs `Self` from environmental variables and break points
    fn from_var(break_points: Self::BreakPoints) -> Self;
    /// Degree of the circuit, log_2(number of rows)
    fn degree(&self) -> u32;
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EthConfigPinning {
    pub params: EthConfigParams,
    pub break_points: RlcThreadBreakPoints,
}

impl Halo2ConfigPinning for EthConfigPinning {
    type BreakPoints = RlcThreadBreakPoints;

    fn from_path<P: AsRef<Path>>(path: P) -> Self {
        let pinning: Self = serde_json::from_reader(
            File::open(&path)
                .unwrap_or_else(|e| panic!("{:?} does not exist: {e:?}", path.as_ref())),
        )
        .unwrap();
        pinning.set_var();
        pinning
    }

    fn set_var(&self) {
        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&self.params).unwrap());
        set_var("KECCAK_ROWS", self.params.keccak_rows_per_round.to_string());
        let bits = self.params.lookup_bits.unwrap_or(ETH_LOOKUP_BITS);
        set_var("LOOKUP_BITS", bits.to_string());
    }

    fn break_points(self) -> RlcThreadBreakPoints {
        self.break_points
    }

    fn from_var(break_points: RlcThreadBreakPoints) -> Self {
        let params: EthConfigParams =
            serde_json::from_str(&var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        Self { params, break_points }
    }

    fn degree(&self) -> u32 {
        self.params.degree
    }
}

#[derive(Serialize, Deserialize)]
pub struct AggregationConfigPinning {
    pub params: AggregationConfigParams,
    pub break_points: MultiPhaseThreadBreakPoints,
}

impl Halo2ConfigPinning for AggregationConfigPinning {
    type BreakPoints = MultiPhaseThreadBreakPoints;

    fn from_path<P: AsRef<Path>>(path: P) -> Self {
        let pinning: Self = serde_json::from_reader(
            File::open(&path)
                .unwrap_or_else(|e| panic!("{:?} does not exist: {e:?}", path.as_ref())),
        )
        .unwrap();
        pinning.set_var();
        pinning
    }

    fn set_var(&self) {
        let gate_params = FlexGateConfigParams {
            k: self.params.degree as usize,
            num_advice_per_phase: vec![self.params.num_advice],
            num_lookup_advice_per_phase: vec![self.params.num_lookup_advice],
            strategy: GateStrategy::Vertical,
            num_fixed: self.params.num_fixed,
        };
        set_var("FLEX_GATE_CONFIG_PARAMS", serde_json::to_string(&gate_params).unwrap());
        set_var("LOOKUP_BITS", self.params.lookup_bits.to_string());
    }

    fn break_points(self) -> MultiPhaseThreadBreakPoints {
        self.break_points
    }

    fn from_var(break_points: MultiPhaseThreadBreakPoints) -> Self {
        let params: FlexGateConfigParams =
            serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        let lookup_bits = var("LOOKUP_BITS").unwrap().parse().unwrap();
        Self {
            params: AggregationConfigParams {
                degree: params.k as u32,
                num_advice: params.num_advice_per_phase[0],
                num_lookup_advice: params.num_lookup_advice_per_phase[0],
                num_fixed: params.num_fixed,
                lookup_bits,
            },
            break_points,
        }
    }

    fn degree(&self) -> u32 {
        self.params.degree
    }
}

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

pub fn u256_to_bytes32_be(input: &U256) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    input.to_big_endian(&mut bytes);
    bytes
}

// Field is has PrimeField<Repr = [u8; 32]>
/// Takes `hash` as `bytes32` and returns `(hash[..16], hash[16..])` represented as big endian numbers in the prime field
pub fn encode_h256_to_field<F: Field>(hash: &H256) -> [F; 2] {
    let mut bytes = hash.as_bytes().to_vec();
    bytes.reverse();
    // repr is in little endian
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[16..]);
    let val1 = F::from_bytes_le(&repr);
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[..16]);
    let val2 = F::from_bytes_le(&repr);
    [val1, val2]
}

pub fn decode_field_to_h256<F: Field>(fe: &[F]) -> H256 {
    assert_eq!(fe.len(), 2);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&fe[1].to_bytes_le()[..16]);
    bytes[16..].copy_from_slice(&fe[0].to_bytes_le()[..16]);
    bytes.reverse();
    H256(bytes)
}

/// Takes U256, converts to bytes32 (big endian) and returns (hash[..16], hash[16..]) represented as big endian numbers in the prime field
pub fn encode_u256_to_field<F: Field>(input: &U256) -> [F; 2] {
    let mut bytes = vec![0; 32];
    input.to_little_endian(&mut bytes);
    // repr is in little endian
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[16..]);
    let val1 = F::from_bytes_le(&repr);
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[..16]);
    let val2 = F::from_bytes_le(&repr);
    [val1, val2]
}

pub fn decode_field_to_u256<F: Field>(fe: &[F]) -> U256 {
    assert_eq!(fe.len(), 2);
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&fe[0].to_bytes_le()[..16]);
    bytes[..16].copy_from_slice(&fe[1].to_bytes_le()[..16]);
    U256::from_little_endian(&bytes)
}

pub fn encode_addr_to_field<F: Field>(input: &Address) -> F {
    let mut bytes = input.as_bytes().to_vec();
    bytes.reverse();
    let mut repr = [0u8; 32];
    repr[..20].copy_from_slice(&bytes);
    F::from_bytes_le(&repr)
}

pub fn decode_field_to_addr<F: Field>(fe: &F) -> Address {
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&fe.to_bytes_le()[..20]);
    bytes.reverse();
    Address::from_slice(&bytes)
}

// circuit utils:

/// Loads boolean `val` as witness and asserts it is a bit.
pub fn load_bool<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    val: bool,
) -> AssignedValue<F> {
    let bit = ctx.load_witness(F::from(val));
    gate.assert_bit(ctx, bit);
    bit
}

/// Enforces `lhs` equals `rhs` only if `cond` is true.
///
/// Assumes that `cond` is a bit.
pub fn enforce_conditional_equality<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    lhs: AssignedValue<F>,
    rhs: AssignedValue<F>,
    cond: AssignedValue<F>,
) {
    let [lhs, rhs] = [lhs, rhs].map(|x| gate.mul(ctx, x, cond));
    ctx.constrain_equal(&lhs, &rhs);
}

/// `array2d` is an array of fixed length arrays.
/// Assumes:
/// * `array2d[i].len() = array2d[j].len()` for all `i,j`.
/// * the values of `indicator` are boolean and that `indicator` has at most one `1` bit.
/// * the lengths of `array2d` and `indicator` are the same.
///
/// Returns the "dot product" of `array2d` with `indicator` as a fixed length (1d) array of length `array2d[0].len()`.
pub fn select_array_by_indicator<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    array2d: &[impl AsRef<[AssignedValue<F>]>],
    indicator: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    (0..array2d[0].as_ref().len())
        .map(|j| {
            gate.select_by_indicator(
                ctx,
                array2d.iter().map(|array_i| array_i.as_ref()[j]),
                indicator.iter().copied(),
            )
        })
        .collect()
}

/// Assumes that `bytes` have witnesses that are bytes.
pub fn bytes_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    limbs_be_to_u128(ctx, gate, bytes, 8)
}

pub(crate) fn limbs_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    limbs: &[AssignedValue<F>],
    limb_bits: usize,
) -> Vec<AssignedValue<F>> {
    assert!(!limbs.is_empty(), "limbs must not be empty");
    assert_eq!(128 % limb_bits, 0);
    limbs
        .chunks(128 / limb_bits)
        .map(|chunk| {
            gate.inner_product(
                ctx,
                chunk.iter().rev().copied(),
                (0..chunk.len()).map(|idx| Constant(gate.pow_of_two()[limb_bits * idx])),
            )
        })
        .collect_vec()
}

/// Decomposes `num` into `num_bytes` bytes in big endian and constrains the decomposition holds.
///
/// Assumes `num` has value in `u64`.
pub fn num_to_bytes_be<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    num: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<AssignedValue<F>> {
    let mut bytes = Vec::with_capacity(num_bytes);
    // mostly copied from RangeChip::range_check
    let pows = range.gate.pow_of_two().iter().step_by(8).take(num_bytes).map(|x| Constant(*x));
    let byte_vals =
        decompose_fe_to_u64_limbs(num.value(), num_bytes, 8).into_iter().map(F::from).map(Witness);
    let row_offset = ctx.advice.len() as isize;
    let acc = range.gate.inner_product(ctx, byte_vals, pows);
    ctx.constrain_equal(&acc, num);

    for i in (0..num_bytes - 1).rev().map(|i| 1 + 3 * i as isize).chain(iter::once(0)) {
        let byte = ctx.get(row_offset + i);
        range.range_check(ctx, byte, 8);
        bytes.push(byte);
    }
    bytes
}

/// Takes a fixed length array `bytes` and returns a length `out_len` array equal to
/// `[[0; out_len - len], bytes[..len]].concat()`, i.e., we take `bytes[..len]` and
/// zero pad it on the left.
///
/// Assumes `0 < len <= max_len <= out_len`.
pub fn bytes_be_var_to_fixed<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[AssignedValue<F>],
    len: AssignedValue<F>,
    out_len: usize,
) -> Vec<AssignedValue<F>> {
    debug_assert!(bytes.len() <= out_len);
    debug_assert!(bit_length(out_len as u64) < F::CAPACITY as usize);

    // If `bytes` is an RLP field, then `len <= bytes.len()` was already checked during `decompose_rlp_array_phase0` so we don't need to do it again:
    // range.range_check(ctx, len, bit_length(bytes.len() as u64));
    let mut padded_bytes = bytes.to_vec();
    padded_bytes.resize(out_len, padded_bytes[0]);
    // We use a barrel shifter to shift `bytes` to the right by `out_len - len` bits.
    let shift = gate.sub(ctx, Constant(gate.get_field_element(out_len as u64)), len);
    let shift_bits = gate.num_to_bits(ctx, shift, bit_length(out_len as u64));
    for (i, shift_bit) in shift_bits.into_iter().enumerate() {
        let shifted_bytes = (0..out_len)
            .map(|j| {
                if j >= (1 << i) {
                    Existing(padded_bytes[j - (1 << i)])
                } else {
                    Constant(F::zero())
                }
            })
            .collect_vec();
        padded_bytes = padded_bytes
            .into_iter()
            .zip(shifted_bytes)
            .map(|(noshift, shift)| gate.select(ctx, shift, noshift, shift_bit))
            .collect_vec();
    }
    padded_bytes
}

/// Decomposes `uint` into `num_bytes` bytes and constrains the decomposition.
/// Here `uint` can be any uint that fits into `F`.
pub fn uint_to_bytes_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    uint: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<AssignedValue<F>> {
    let mut bytes = Vec::with_capacity(num_bytes);
    // mostly copied from RangeChip::range_check
    let pows = range.gate.pow_of_two().iter().step_by(8).take(num_bytes).map(|x| Constant(*x));
    let byte_vals = decompose(uint.value(), num_bytes, 8).into_iter().map(Witness);
    let row_offset = ctx.advice.len() as isize;
    let acc = range.gate.inner_product(ctx, byte_vals, pows);
    ctx.constrain_equal(&acc, uint);

    for i in (0..num_bytes - 1).rev().map(|i| 1 + 3 * i as isize).chain(iter::once(0)) {
        let byte = ctx.get(row_offset + i);
        range.range_check(ctx, byte, 8);
        bytes.push(byte);
    }
    bytes
}

/// See [`num_to_bytes_be`] for details. Here `uint` can now be any uint that fits into `F`.
pub fn uint_to_bytes_le<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    uint: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<AssignedValue<F>> {
    let mut bytes = Vec::with_capacity(num_bytes);
    // mostly copied from RangeChip::range_check
    let pows = range.gate.pow_of_two().iter().step_by(8).take(num_bytes).map(|x| Constant(*x));
    let byte_vals = decompose(uint.value(), num_bytes, 8).into_iter().map(Witness);
    let row_offset = ctx.advice.len() as isize;
    let acc = range.gate.inner_product(ctx, byte_vals, pows);
    ctx.constrain_equal(&acc, uint);

    for i in iter::once(0).chain((0..num_bytes - 1).map(|i| 1 + 3 * i as isize)) {
        let byte = ctx.get(row_offset + i);
        range.range_check(ctx, byte, 8);
        bytes.push(byte);
    }
    bytes
}

pub fn bytes_be_to_uint<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input: &[AssignedValue<F>],
    num_bytes: usize,
) -> AssignedValue<F> {
    gate.inner_product(
        ctx,
        input[..num_bytes].iter().rev().copied(),
        (0..num_bytes).map(|idx| Constant(gate.pow_of_two()[8 * idx])),
    )
}

/// Converts a fixed length array of `u128` values into a fixed length array of big endian bytes.
pub fn u128s_to_bytes_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    u128s: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    u128s.iter().map(|u128| uint_to_bytes_be(ctx, range, u128, 16)).concat()
}

/// Returns 1 if all entries of `input` are zero, 0 otherwise.
pub fn is_zero_vec<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input: &[AssignedValue<F>],
) -> AssignedValue<F> {
    let is_zeros = input.iter().map(|x| gate.is_zero(ctx, *x)).collect_vec();
    let sum = gate.sum(ctx, is_zeros);
    let total_len = gate.get_field_element(input.len() as u64);
    gate.is_equal(ctx, sum, Constant(total_len))
}
