//TODO: Replace arrays and gate with &impl
use crate::Field;
use crate::{keccak::types::KeccakVarLenQuery, rlc::types::ConcatVarFixedArrayTrace};
use halo2_base::{
    safe_types::{SafeBytes32, VarLenBytesVec},
    AssignedValue,
};

/// Witness for the computation of a nested mapping
#[derive(Debug, Clone)]
pub struct NestedMappingWitness<F: Field> {
    pub witness: Vec<MappingWitness<F>>,
    pub slot: SafeBytes32<F>,
    pub nestings: AssignedValue<F>,
}

/// Witness for the computation of a mapping with a variable length (Non-Value) key.
#[derive(Debug, Clone)]
pub struct VarMappingWitness<F: Field> {
    pub mapping_slot: SafeBytes32<F>,
    pub key: VarLenBytesVec<F>,
    /// The output of this hash is the storage slot for the mapping key
    pub hash_query: KeccakVarLenQuery<F>,
}

pub type VarMappingTrace<F> = ConcatVarFixedArrayTrace<F>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum MappingWitness<F: Field> {
    /// The storage slot corresponding to mapping key of value type
    Value(SafeBytes32<F>),
    /// Witness for mapping key of non-value type
    NonValue(VarMappingWitness<F>),
}

impl<F: Field> MappingWitness<F> {
    pub fn slot(&self) -> SafeBytes32<F> {
        match self {
            MappingWitness::Value(slot) => slot.clone(),
            MappingWitness::NonValue(witness) => witness.hash_query.output_bytes.clone(),
        }
    }
}

/// Return after phase1 of mapping computation. None if the mapping key is of Value type.
pub type MappingTrace<F> = Option<VarMappingTrace<F>>;

/// Enum whose variants which represents different primitive types of Solidity types that can be represented in circuit.
/// Each variant wraps a `Vec<AssignedValue<F>>` representing the bytes of primitive type.
///
/// Fixed Length Types (Value):
/// --------------------------
/// * `UInt256`: 32 bytes
/// Fixed length primitive types are represented by a fixed length `Vec<AssignedValue<F>>` converted to a `SafeBytes32<F>`.
/// SafeTypes range check that each AssignedValue<F> of the vector is within byte range 0-255 and the vector has length 32.
///
/// Variable Length Types (NonValue):
/// ---------------------------------
/// * `NonValue`: Variable length byte array
#[derive(Debug, Clone)]
pub enum SolidityType<F: Field> {
    Value(SafeBytes32<F>),
    NonValue(VarLenBytesVec<F>),
}

#[derive(Debug, Clone)]
pub struct SolidityStoragePosition<F: Field> {
    pub slot: SafeBytes32<F>,
    pub byte_offset: AssignedValue<F>,
    pub item_byte_len: AssignedValue<F>,
}
