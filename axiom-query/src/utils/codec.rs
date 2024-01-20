use axiom_codec::{
    encoder::field_elements::{
        FIELD_ENCODED_SOLIDITY_NESTED_MAPPING_DEPTH_IDX, NUM_FE_ANY,
        NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS,
    },
    types::{field_elements::*, native::SubqueryType},
};
use axiom_eth::halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};

pub type AssignedSubqueryKey<F> = SubqueryKey<AssignedValue<F>>;
pub type AssignedSubqueryOutput<F> = SubqueryOutput<AssignedValue<F>>;

pub type AssignedHeaderSubquery<F> = FieldHeaderSubquery<AssignedValue<F>>;
pub type AssignedAccountSubquery<F> = FieldAccountSubquery<AssignedValue<F>>;
pub type AssignedStorageSubquery<F> = FieldStorageSubquery<AssignedValue<F>>;
pub type AssignedTxSubquery<F> = FieldTxSubquery<AssignedValue<F>>;
pub type AssignedReceiptSubquery<F> = FieldReceiptSubquery<AssignedValue<F>>;
pub type AssignedSolidityNestedMappingSubquery<F> =
    FieldSolidityNestedMappingSubquery<AssignedValue<F>>;

pub type AssignedHeaderSubqueryResult<F> = FieldHeaderSubqueryResult<AssignedValue<F>>;
pub type AssignedAccountSubqueryResult<F> = FieldAccountSubqueryResult<AssignedValue<F>>;
pub type AssignedStorageSubqueryResult<F> = FieldStorageSubqueryResult<AssignedValue<F>>;
pub type AssignedTxSubqueryResult<F> = FieldTxSubqueryResult<AssignedValue<F>>;
pub type AssignedReceiptSubqueryResult<F> = FieldReceiptSubqueryResult<AssignedValue<F>>;
pub type AssignedSolidityNestedMappingSubqueryResult<F> =
    FieldSolidityNestedMappingSubqueryResult<AssignedValue<F>>;

pub type AssignedSubqueryResult<F> = FlattenedSubqueryResult<AssignedValue<F>>;

pub fn assign_flattened_subquery_result<F: ScalarField>(
    ctx: &mut Context<F>,
    f: &FlattenedSubqueryResult<F>,
) -> AssignedSubqueryResult<F> {
    let key = f.key.0.map(|x| ctx.load_witness(x));
    let value = f.value.0.map(|x| ctx.load_witness(x));
    FlattenedSubqueryResult::new(SubqueryKey(key), SubqueryOutput(value))
}

/// Parses the subquery type and determines the actual number of field elements in the
/// field element encoding, **including** the subquery type.
///
/// This is `1` more than the flattened length of `FieldSubquery**` when the subquery type is not SolidityNestedMapping. When the subquery type is SolidityNestedMapping, the number of field elements is `1 + NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS + 2 * mapping_depth`.
pub fn get_num_fe_from_subquery_key<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    key: &AssignedSubqueryKey<F>,
) -> AssignedValue<F> {
    // num_fe_by_type will include 1 field element for the type itself, while NUM_FE_ANY does not
    let num_fe_by_type: Vec<_> = NUM_FE_ANY
        .iter()
        .enumerate()
        .map(|(subtype, &num_fe)| {
            if subtype == SubqueryType::SolidityNestedMapping as usize {
                let num_without_keys =
                    Constant(F::from(NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS as u64 + 1));
                let mapping_depth = key.0[FIELD_ENCODED_SOLIDITY_NESTED_MAPPING_DEPTH_IDX];
                Existing(gate.mul_add(ctx, mapping_depth, Constant(F::from(2)), num_without_keys))
            } else {
                Constant(F::from(num_fe as u64 + 1))
            }
        })
        .collect();
    gate.select_from_idx(ctx, num_fe_by_type, key.0[0])
}
