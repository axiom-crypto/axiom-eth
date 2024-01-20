use halo2_base::{utils::ScalarField, AssignedValue};

use crate::rlc::types::RlcTrace;

#[derive(Clone, Debug)]
pub struct RlpFieldPrefixParsed<F: ScalarField> {
    pub is_not_literal: AssignedValue<F>,
    pub is_big: AssignedValue<F>,

    pub next_len: AssignedValue<F>,
    pub len_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayPrefixParsed<F: ScalarField> {
    // is_empty: AssignedValue<F>,
    pub is_big: AssignedValue<F>,

    pub next_len: AssignedValue<F>,
    pub len_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct RlpPrefixParsed<F: ScalarField> {
    pub is_not_literal: AssignedValue<F>,
    pub is_big: AssignedValue<F>,

    pub next_len: AssignedValue<F>,
    pub len_len: AssignedValue<F>,
}

/// All witnesses involved in the RLP decoding of (prefix + length + payload)
/// where payload can be either a byte string or a list.
#[derive(Clone, Debug)]
pub struct RlpFieldWitness<F: ScalarField> {
    // The RLP encoding is decomposed into: prefix, length, payload
    pub prefix: AssignedValue<F>, // value of the prefix
    pub prefix_len: AssignedValue<F>,
    pub len_len: AssignedValue<F>,
    pub len_cells: Vec<AssignedValue<F>>,

    /// The byte length of the payload bytes (decoded byte string)
    pub field_len: AssignedValue<F>,
    /// The payload (decoded byte string)
    pub field_cells: Vec<AssignedValue<F>>,
    pub max_field_len: usize,

    /// This is the original raw RLP encoded byte string, padded with zeros to a known fixed maximum length
    pub encoded_item: Vec<AssignedValue<F>>,
    /// This is variable length of `encoded_item` in bytes
    pub encoded_item_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
/// The outputed values after RLP decoding of (prefix + length + payload) in SecondPhase.
/// This contains RLC of substrings from the decomposition. Payload can be either a byte string or a list.
pub struct RlpFieldTrace<F: ScalarField> {
    pub prefix: AssignedValue<F>, // value of the prefix
    pub prefix_len: AssignedValue<F>,
    pub len_trace: RlcTrace<F>,
    pub field_trace: RlcTrace<F>,
    // to save memory maybe we don't need this
    /// This is the rlc of the full rlp (prefix + len + payload)
    pub rlp_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayWitness<F: ScalarField> {
    pub field_witness: Vec<RlpFieldWitness<F>>,

    pub len_len: AssignedValue<F>,
    pub len_cells: Vec<AssignedValue<F>>,

    /// Length of the full RLP encoding (bytes) of the array
    pub rlp_len: AssignedValue<F>,
    /// The original raw RLP encoded array, padded with zeros to a known fixed maximum length
    pub rlp_array: Vec<AssignedValue<F>>,

    /// The length of the array/list this is an encoding of. Only stored if
    /// this is the encoding of a variable length array.
    pub list_len: Option<AssignedValue<F>>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayTrace<F: ScalarField> {
    pub len_trace: RlcTrace<F>,
    pub field_trace: Vec<RlpFieldTrace<F>>,
    // to save memory we don't need this
    // pub array_trace: RlcTrace<F>,
}
