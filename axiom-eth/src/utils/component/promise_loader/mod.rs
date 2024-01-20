use crate::{rlc::chip::RlcChip, Field};
use halo2_base::{AssignedValue, Context};

use super::types::Flatten;

pub mod combo;
pub mod comp_loader;
pub mod empty;
pub mod multi;
pub mod single;
#[cfg(test)]
pub mod tests;
/// Utilities to help with creating dummy circuits for proving and verifying key generation.
pub mod utils;

/// A helper function to compute RLC of (flatten input, flattne output).
pub fn flatten_witness_to_rlc<F: Field>(
    rlc_ctx: &mut Context<F>,
    rlc_chip: &RlcChip<F>,
    f: &Flatten<AssignedValue<F>>,
) -> AssignedValue<F> {
    rlc_chip.compute_rlc_fixed_len(rlc_ctx, f.fields.clone()).rlc_val
}
