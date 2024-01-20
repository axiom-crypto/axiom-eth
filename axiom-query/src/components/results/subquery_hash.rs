use std::iter::{self, zip};

use axiom_codec::{
    constants::{NUM_SUBQUERY_TYPES, SUBQUERY_TYPE_BYTES},
    encoder::field_elements::{
        BYTES_PER_FE_ANY, FIELD_SOLIDITY_NESTED_MAPPING_DEPTH_IDX,
        NUM_FE_SOLIDITY_NESTED_MAPPING_MIN, NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS,
    },
    types::native::SubqueryType,
};
use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeChip, RangeInstructions},
        safe_types::{SafeTypeChip, VarLenBytesVec},
        Context,
        QuantumCell::{Constant, Existing},
    },
    keccak::{types::KeccakVarLenQuery, KeccakChip},
    utils::uint_to_bytes_be,
};
use itertools::Itertools;

use crate::utils::codec::AssignedSubqueryKey;
use crate::Field;

/// Bytes `encoded_subquery_key` includes the subquery type ([u16])
pub fn get_subquery_hash<F: Field>(
    ctx: &mut Context<F>,
    keccak: &KeccakChip<F>,
    key: &AssignedSubqueryKey<F>,
    enabled_types: &[bool; NUM_SUBQUERY_TYPES],
) -> KeccakVarLenQuery<F> {
    let range = keccak.range();

    let encoded = transform_subquery_key_to_bytes(ctx, range, key, enabled_types);

    let mut min_len = BYTES_PER_FE_ANY
        .iter()
        .enumerate()
        .filter(|&(subquery_type, _)| enabled_types[subquery_type])
        .map(|(subquery_type, bytes_per_fe)| {
            if subquery_type == SubqueryType::SolidityNestedMapping as usize {
                bytes_per_fe[..NUM_FE_SOLIDITY_NESTED_MAPPING_MIN].iter().sum::<usize>()
            } else {
                bytes_per_fe.iter().sum::<usize>()
            }
        })
        .min()
        .unwrap_or(0);
    min_len += SUBQUERY_TYPE_BYTES;

    let encoded_key = encoded.bytes().iter().map(|b| *b.as_ref()).collect();
    keccak.keccak_var_len(ctx, encoded_key, *encoded.len(), min_len)
}

/// Transform from field element encoding of subquery key into byte encoding
pub fn transform_subquery_key_to_bytes<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    key: &AssignedSubqueryKey<F>,
    enabled_types: &[bool; NUM_SUBQUERY_TYPES],
) -> VarLenBytesVec<F> {
    let subquery_type = key.0[0];
    // The key WITHOUT the subquery type
    let subquery = &key.0[1..];

    let gate = range.gate();
    let type_indicator = gate.idx_to_indicator(ctx, subquery_type, NUM_SUBQUERY_TYPES);

    // max_bytes_per_fe[i] is the max number of bytes the i-th field element can represent
    let max_bytes_per_fe = (0..subquery.len())
        .map(|i| {
            BYTES_PER_FE_ANY
                .iter()
                .enumerate()
                .filter(|&(subtype, _)| enabled_types[subtype])
                .map(|(_, bytes_per_fe)| *bytes_per_fe.get(i).unwrap_or(&0))
                .max()
                .unwrap_or(0)
        })
        .collect_vec();
    let max_total_bytes = max_bytes_per_fe.iter().sum::<usize>();

    let byte_frags = zip(subquery, max_bytes_per_fe)
        .map(|(fe, max_bytes)| uint_to_bytes_be(ctx, range, fe, max_bytes))
        .collect_vec();

    // now I do the very dumb thing: just create the byte array for each type
    let const_zero = SafeTypeChip::unsafe_to_byte(ctx.load_zero());
    let (encoded_bytes_by_type, byte_len_by_type): (Vec<_>, Vec<_>) = BYTES_PER_FE_ANY
        .iter()
        .enumerate()
        .map(|(subtype, &bytes_per_fe)| {
            let bytes_per_fe = if enabled_types[subtype] { bytes_per_fe } else { &[] };
            // byte frags are big-endian, so take correct number of bytes from the end
            let mut encoded = zip(&byte_frags, bytes_per_fe)
                .flat_map(|(frag, &num_bytes)| {
                    frag[frag.len() - num_bytes..frag.len()].iter().copied()
                })
                .collect_vec();
            assert!(encoded.len() <= max_total_bytes);
            encoded.resize(max_total_bytes, const_zero);

            let byte_len = if !enabled_types[subtype] {
                Constant(F::ZERO)
            } else if subtype == SubqueryType::SolidityNestedMapping as usize {
                // length depends on mapping_depth
                let mapping_depth = subquery[FIELD_SOLIDITY_NESTED_MAPPING_DEPTH_IDX];
                let pre_len = bytes_per_fe[..NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS]
                    .iter()
                    .sum::<usize>();
                Existing(gate.mul_add(
                    ctx,
                    Constant(F::from(32)),
                    mapping_depth,
                    Constant(F::from(pre_len as u64)),
                ))
            } else {
                Constant(F::from(bytes_per_fe.iter().sum::<usize>() as u64))
            };

            (encoded, byte_len)
        })
        .unzip();

    let encoded_subquery =
        gate.select_array_by_indicator(ctx, &encoded_bytes_by_type, &type_indicator);
    let mut encoded_len = gate.select_by_indicator(ctx, byte_len_by_type, type_indicator);

    let encoded_type = uint_to_bytes_be(ctx, range, &subquery_type, SUBQUERY_TYPE_BYTES);
    let encoded: Vec<_> = iter::empty()
        .chain(encoded_type)
        .chain(encoded_subquery.into_iter().map(SafeTypeChip::unsafe_to_byte))
        .collect();
    encoded_len = gate.add(ctx, encoded_len, Constant(F::from(SUBQUERY_TYPE_BYTES as u64)));

    VarLenBytesVec::new(encoded, encoded_len, max_total_bytes + SUBQUERY_TYPE_BYTES)
}
