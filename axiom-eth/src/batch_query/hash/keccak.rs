//! Helper module for doing Keccak hashes
use crate::{
    batch_query::{response::FixedByteArray, EccInstructions},
    keccak::KeccakChip,
    Field,
};
use ethers_core::utils::keccak256;
use halo2_base::{gates::GateInstructions, AssignedValue, Context};
use lazy_static::lazy_static;

lazy_static! {
    static ref KECCAK_EMPTY_STRING: [u8; 32] = keccak256([]);
}

pub fn keccak_packed<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    keccak: &mut KeccakChip<F>,
    words: FixedByteArray<F>,
) -> FixedByteArray<F> {
    FixedByteArray(if words.0.is_empty() {
        KECCAK_EMPTY_STRING
            .iter()
            .map(|b| ctx.load_witness(gate.get_field_element(*b as u64)))
            .collect()
    } else {
        let hash_id = keccak.keccak_fixed_len(ctx, gate, words.0, None);
        keccak.fixed_len_queries[hash_id].output_assigned.clone()
    })
}

/// Assumes that `sel` is a bit (either 0 or 1).
/// Returns `bytes` if `sel` is 1, otherwise replaces every byte in `bytes` with 0.
pub(crate) fn bytes_select_or_zero<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    mut bytes: FixedByteArray<F>,
    sel: AssignedValue<F>,
) -> FixedByteArray<F> {
    for byte in bytes.0.iter_mut() {
        *byte = gate.mul(ctx, *byte, sel);
    }
    bytes
}
