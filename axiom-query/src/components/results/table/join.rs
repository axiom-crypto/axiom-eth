//! We have virtual tables of different widths for different subquery types.
//! We virtually join them together to get a single table. This is virtual because
//! we actually only compute the RLC of the resulting joined table.

use axiom_codec::{
    constants::{MAX_SUBQUERY_INPUTS, MAX_SUBQUERY_OUTPUTS},
    types::{field_elements::AnySubqueryResult, native::SubqueryType},
};
use axiom_eth::{
    halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue},
    rlc::{chip::RlcChip, circuit::builder::RlcContextPair},
};

#[derive(Clone, Debug)]
pub struct GroupedSubqueryResults<T> {
    /// This is a **constant**
    pub subquery_type: SubqueryType,
    /// This is a fixed length vector of (subquery, value) pairs.
    /// Assumed that subquery[i].len() = subquery[j].len() for all i, j.
    /// Assumed that value[i].len() = value[j].len() for all i, j.
    pub results: Vec<AnySubqueryResult<Vec<T>, Vec<T>>>,
}

impl<F: ScalarField> GroupedSubqueryResults<AssignedValue<F>> {
    /// The width of the key and value differs per subquery type, but we want to put them
    /// into an ungrouped virtual table. Instead of resizing the key/values directly, we
    /// optimize by computing the RLC of the resized key/values since that is all we need
    /// to form the dynamic lookup table.
    //
    // Note: this assumes Solidity Nested Mapping subquery enforces that extra keys
    // beyond mapping depth are 0
    pub fn into_rlc(
        self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        rlc: &RlcChip<F>,
    ) -> Vec<[AssignedValue<F>; 1]> {
        if self.results.is_empty() {
            return vec![];
        }
        let subquery_type = ctx_gate.load_constant(F::from(self.subquery_type as u64));
        let subquery_len = self.results[0].subquery.len();
        assert!(subquery_len <= MAX_SUBQUERY_INPUTS);
        let val_len = self.results[0].value.len();
        assert!(val_len <= MAX_SUBQUERY_OUTPUTS);
        // right now `value` is always HiLo, but we put this here in case of future generalizations
        let val_multiplier = (val_len < MAX_SUBQUERY_OUTPUTS)
            .then(|| rlc.rlc_pow_fixed(ctx_gate, gate, MAX_SUBQUERY_OUTPUTS - val_len));
        let subquery_multiplier = rlc.rlc_pow_fixed(
            ctx_gate,
            gate,
            MAX_SUBQUERY_INPUTS + MAX_SUBQUERY_OUTPUTS - subquery_len,
        );

        self.results
            .into_iter()
            .map(|result| {
                let subquery = result.subquery;
                let value = result.value;
                assert_eq!(subquery.len(), subquery_len);
                assert_eq!(value.len(), val_len);
                // the following has the same effect as: `RLC(value.resize(MAX_SUBQUERY_OUTPUTS, 0))`
                let mut val_rlc = rlc.compute_rlc_fixed_len(ctx_rlc, value.clone()).rlc_val;
                if let Some(multiplier) = val_multiplier {
                    val_rlc = gate.mul(ctx_gate, val_rlc, multiplier);
                }
                // key = subquery_type . subquery
                let key = [vec![subquery_type], subquery].concat();
                // the following has the same effect as: `RLC([key.resize(SUBQUERY_KEY_LEN, 0)), value])`
                // where `value` is already resized
                // This is because RLC(a . b) = RLC(a) * gamma^|b| + RLC(b)
                // if a, b have fixed lengths |a|, |b| respectively
                let key_rlc = rlc.compute_rlc_fixed_len(ctx_rlc, key).rlc_val;
                [gate.mul_add(ctx_gate, key_rlc, subquery_multiplier, val_rlc)]
            })
            .collect()
    }
}

/*
// Unused for now

/// `inputs` has fixed length known at compile time.
/// The true variable length of `inputs` is given by `var_len`, and
/// it is assumed that `min_len <= var_len <= inputs.len()`.
///
/// Let `var_input = inputs[..var_len]`. This function has the effect of:
/// ```ignore
/// var_input.resize(0, padded_len)
/// compute_rlc_fixed(var_input)
/// ```
/// What the function actually does is compute the RLC of `var_input` and multiply by
/// the correct power of the challenge `gamma`.
///
/// The output is the RLC value.
///
/// ## Assumptions
/// - `min_len <= var_len <= inputs.len()`
fn compute_rlc_right_pad_to_fixed<F: ScalarField>(
    (ctx_gate, ctx_rlc): RlcContextPair<F>,
    gate: &impl GateInstructions<F>,
    rlc: &RlcChip<F>,
    inputs: Vec<AssignedValue<F>>,
    var_len: AssignedValue<F>,
    min_len: usize,
    padded_len: usize,
) -> AssignedValue<F> {
    assert!(min_len <= inputs.len());
    let rlc_var = rlc.compute_rlc_with_min_len((ctx_gate, ctx_rlc), gate, inputs, var_len, min_len);
    let shift_len = gate.sub(ctx_gate, Constant(F::from(padded_len as u64)), var_len);
    let multiplier =
        rlc.rlc_pow(ctx_gate, gate, shift_len, bit_length((padded_len - min_len) as u64));
    gate.mul(ctx_gate, rlc_var.rlc_val, multiplier)
}
*/
