//! The containers for different query response types

use super::hash::PoseidonWords;
use super::EccInstructions;
use crate::rlp::RlpFieldWitness;
use crate::util::bytes_be_var_to_fixed;
use crate::{mpt::AssignedBytes, util::bytes_be_to_uint};
use halo2_base::gates::{GateChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::CurveAffine;
use halo2_base::{
    gates::GateInstructions, utils::ScalarField, AssignedValue, Context, QuantumCell::Constant,
};
use snark_verifier::loader::halo2::{Halo2Loader, Scalar};
use std::iter;
use std::rc::Rc;

pub mod account;
pub mod block_header;
pub mod mmr_verify;
pub mod native;
pub mod receipts;
pub mod row_consistency;
pub mod storage;
pub mod transaction;
pub mod transaction_receipt;

/// An assigned byte array of known fixed length.
#[derive(Clone, Debug)]
pub struct FixedByteArray<F: ScalarField>(pub AssignedBytes<F>);

impl<'a, F: ScalarField> From<&'a RlpFieldWitness<F>> for FixedByteArray<F> {
    fn from(value: &'a RlpFieldWitness<F>) -> Self {
        assert_eq!(value.field_len.value().get_lower_32() as usize, value.field_cells.len());
        Self(value.field_cells.clone())
    }
}

impl<F: ScalarField> AsRef<[AssignedValue<F>]> for FixedByteArray<F> {
    fn as_ref(&self) -> &[AssignedValue<F>] {
        &self.0
    }
}

/// An assigned byte array. Entries of `bytes` assumed to be bytes.
///
/// If `var_len` is `None`, then the byte array is assumed to be of known fixed length.
/// Otherwise, `var_len` is the variable length of the byte array, and it is assumed that `bytes` has been right padded by 0s to a max fixed length.
#[derive(Clone, Debug)]
pub struct ByteArray<F: ScalarField> {
    pub bytes: AssignedBytes<F>,
    pub var_len: Option<AssignedValue<F>>,
}

impl<'a, F: ScalarField> From<&'a RlpFieldWitness<F>> for ByteArray<F> {
    fn from(value: &'a RlpFieldWitness<F>) -> Self {
        Self { var_len: Some(value.field_len), bytes: value.field_cells.clone() }
    }
}

impl<F: ScalarField> From<FixedByteArray<F>> for ByteArray<F> {
    fn from(value: FixedByteArray<F>) -> Self {
        Self { var_len: None, bytes: value.0 }
    }
}

impl<F: ScalarField> ByteArray<F> {
    /// Evaluates a variable-length byte string to a big endian number.
    ///
    /// If the resulting number is larger than the size of the scalar field `F`, then the result
    /// is modulo the prime of the scalar field. (We do not recommend using it in this setting.)
    pub fn evaluate(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> AssignedValue<F> {
        if let Some(len) = self.var_len {
            evaluate_byte_array(ctx, gate, &self.bytes, len)
        } else {
            bytes_be_to_uint(ctx, gate, &self.bytes, self.bytes.len())
        }
    }

    /// Converts a variable-length byte array to a fixed-length byte array by left padding with 0s.
    /// Assumes that `self.bytes` has been right padded with 0s to a max fixed length.
    pub fn to_fixed(
        self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> FixedByteArray<F> {
        FixedByteArray(if let Some(len) = self.var_len {
            bytes_be_var_to_fixed(ctx, gate, &self.bytes, len, self.bytes.len())
        } else {
            self.bytes
        })
    }
}

impl<F: ScalarField> FixedByteArray<F> {
    /// Loads bytes as witnesses and range checks each witness to be 8 bits.
    pub fn new(ctx: &mut Context<F>, range: &impl RangeInstructions<F>, bytes: &[u8]) -> Self {
        let bytes =
            ctx.assign_witnesses(bytes.iter().map(|x| range.gate().get_field_element(*x as u64)));
        // range check bytes
        for byte in &bytes {
            range.range_check(ctx, *byte, 8);
        }
        Self(bytes)
    }

    /// Loads bytes as constants.
    pub fn new_const(ctx: &mut Context<F>, gate: &impl GateInstructions<F>, bytes: &[u8]) -> Self {
        let bytes =
            bytes.iter().map(|b| ctx.load_constant(gate.get_field_element(*b as u64))).collect();
        Self(bytes)
    }

    /// Evaluates a fixed-length byte string to a big endian number.
    ///
    /// If the resulting number is larger than the size of the scalar field `F`, then the result
    /// is modulo the prime of the scalar field. (We do not recommend using it in this setting.)
    pub fn evaluate(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> AssignedValue<F> {
        bytes_be_to_uint(ctx, gate, &self.0, self.0.len())
    }

    pub fn to_poseidon_words<C, EccChip>(
        &self,
        loader: &Rc<Halo2Loader<C, EccChip>>,
    ) -> PoseidonWords<Scalar<C, EccChip>>
    where
        C: CurveAffine<ScalarExt = F>,
        EccChip: EccInstructions<F, C>,
    {
        assert!(F::CAPACITY >= 128);
        if self.0.is_empty() {
            return PoseidonWords(vec![]);
        }
        let mut builder = loader.ctx_mut();
        let gate: &GateChip<F> = &loader.scalar_chip();
        let ctx = builder.main(0);
        PoseidonWords(if 8 * self.0.len() <= F::CAPACITY as usize {
            vec![loader.scalar_from_assigned(self.evaluate(ctx, gate))]
        } else {
            self.0
                .chunks(16)
                .map(|chunk| {
                    loader.scalar_from_assigned(bytes_be_to_uint(ctx, gate, chunk, chunk.len()))
                })
                .collect()
        })
    }

    pub fn concat(&self, other: &Self) -> Self {
        Self([&self.0[..], &other.0[..]].concat())
    }
}

/// Evaluate a variable length byte array `array[..len]` to a big endian number
pub fn evaluate_byte_array<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    array: &[AssignedValue<F>],
    len: AssignedValue<F>,
) -> AssignedValue<F> {
    let f_256 = gate.get_field_element(256);
    if !array.is_empty() {
        let incremental_evals =
            gate.accumulated_product(ctx, iter::repeat(Constant(f_256)), array.iter().copied());
        let len_minus_one = gate.sub(ctx, len, Constant(F::one()));
        // if `len = 0` then `len_minus_one` will be very large, so `select_from_idx` will return 0.
        gate.select_from_idx(ctx, incremental_evals.iter().copied(), len_minus_one)
    } else {
        ctx.load_zero()
    }
}
