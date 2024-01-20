use crate::Field;
use crate::{
    keccak::KeccakChip,
    mpt::{MPTChip, MPTProof},
    rlc::{
        chip::RlcChip,
        circuit::builder::RlcContextPair,
        concat_array::{concat_var_fixed_array_phase0, concat_var_fixed_array_phase1},
        types::{AssignedVarLenVec, ConcatVarFixedArrayWitness},
    },
    rlp::RlpChip,
    solidity::types::VarMappingTrace,
    storage::{EthStorageChip, EthStorageTrace, EthStorageWitness},
};
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    safe_types::{SafeBytes32, SafeTypeChip, VarLenBytesVec},
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;

use self::types::{
    MappingTrace, MappingWitness, NestedMappingWitness, SolidityType, VarMappingWitness,
};

#[cfg(all(test, feature = "providers"))]
pub mod tests;
pub mod types;

/// Trait which implements functions to prove statements about Solidity operations over Ethereum storage.
///
/// Supports constraining:
/// * Mappings for keys of fixed length (Value) solidity types:
///     * `keccak256(left_pad_32(key) . mapping_slot)`
/// * Mappings for keys of variable length (NonValue) solidity types:
///     * `keccak256(key . mapping_slot)`
/// * Nested Mappings
///     * Spec for double nested mapping:
///         * Fixed Length:
///             * `keccak256(left_pad_32(key_2) . keccak256(left_pad_32(key_1) . mapping_slot))`
///         * Variable Length:
///             * `keccak256(key_2 . keccak256(key_1 . mapping_slot))`
/// * Proving the inclusion of a value at the storage slot of the constrained mapping or nested mapping.
pub struct SolidityChip<'chip, F: Field> {
    pub mpt: &'chip MPTChip<'chip, F>,
    pub max_nesting: usize,
    pub max_key_byte_len: usize, // currently not used
}

impl<'chip, F: Field> SolidityChip<'chip, F> {
    pub fn new(mpt: &'chip MPTChip<'chip, F>, max_nesting: usize, max_key_byte_len: usize) -> Self {
        Self { mpt, max_nesting, max_key_byte_len }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.mpt.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.mpt.range()
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.mpt.rlc()
    }

    pub fn rlp(&self) -> RlpChip<F> {
        self.mpt.rlp()
    }

    pub fn keccak(&self) -> &KeccakChip<F> {
        self.mpt.keccak()
    }

    /// Computes the storage slot of a solidity mapping at a fixed length (Value type) key by:
    /// ```ignore
    /// keccak256(left_pad_32(key) . mapping_slot)
    /// ```
    ///
    /// Inputs:
    /// - `mapping_slot`: [SafeBytes32]<F> representing the slot of the Solidity mapping itself.
    /// - `key`: [SafeBytes32] representing the key of the Solidity mapping.
    ///
    /// Returns:
    /// * The storage slot of the mapping key in question
    pub fn slot_for_mapping_value_key(
        &self,
        ctx: &mut Context<F>,
        mapping_slot: &SafeBytes32<F>,
        key: &SafeBytes32<F>,
    ) -> SafeBytes32<F> {
        let key_slot_concat = [key.value(), mapping_slot.value()].concat();
        debug_assert_eq!(key_slot_concat.len(), 64);

        let hash_query = self.keccak().keccak_fixed_len(ctx, key_slot_concat);
        hash_query.output_bytes
    }

    /// Performs witness generation within phase0 to compute the storage slot of a Solidity mapping at a variable length (non-value type) key.
    /// The storage slot corresponding to `key` is computed according to https://docs.soliditylang.org/en/v0.8.19/internals/layout_in_storage.html#mappings-and-dynamic-arrays
    /// ```ignore
    /// keccak256(key . mapping_slot)
    /// ```
    /// This is a variable length concatenation, so we need to use RLC in two phases.
    ///  
    /// Inputs:
    /// - `mapping_slot`: [SafeBytes32]<F> representing the evm storage slot of the mapping.
    /// - `key`: [VarLenBytesVec]<F> representing the key of the mapping.
    ///
    /// Returns:
    /// - [VarMappingWitness]<F> representing the witness of the computation of the Solidity mapping.
    pub fn slot_for_mapping_nonvalue_key_phase0(
        &self,
        ctx: &mut Context<F>,
        mapping_slot: SafeBytes32<F>,
        key: VarLenBytesVec<F>,
    ) -> VarMappingWitness<F> {
        let key_values = key.bytes().iter().map(|b| *b.as_ref()).collect();
        let prefix = AssignedVarLenVec { values: key_values, len: *key.len() };
        let suffix = mapping_slot.value().to_vec();
        let concat_witness = concat_var_fixed_array_phase0(ctx, self.gate(), prefix, suffix);
        let concat_values = concat_witness.concat.values;
        let concat_len = concat_witness.concat.len;

        let hash_query = self.keccak().keccak_var_len(ctx, concat_values, concat_len, 32);
        VarMappingWitness { mapping_slot, key, hash_query }
    }

    /// Performs rlc concatenation within phase1 to constrain the computation of a Solidity `mapping(key => value)`.
    ///
    /// * `ctx`: Circuit [Context]<F> to assign witnesses to.
    /// * `witness`: [VarMappingWitness]<F> representing the witness of the computation of the Solidity mapping.
    ///
    /// Returns:
    /// * [VarMappingTrace]<F> trace of the rlc computation to constrain the computation of the Solidity mapping.
    pub fn slot_for_mapping_nonvalue_key_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: VarMappingWitness<F>,
    ) -> VarMappingTrace<F> {
        let VarMappingWitness { mapping_slot, key, hash_query } = witness;
        // constrain the concatenation
        let key_values = key.bytes().iter().map(|b| *b.as_ref()).collect();
        let prefix = AssignedVarLenVec { values: key_values, len: *key.len() };
        let suffix = mapping_slot.value().to_vec();
        let concat =
            AssignedVarLenVec { values: hash_query.input_assigned.clone(), len: hash_query.length };
        let witness = ConcatVarFixedArrayWitness { prefix, suffix, concat };

        concat_var_fixed_array_phase1((ctx_gate, ctx_rlc), self.gate(), self.rlc(), witness)
    }

    /// Performs witness generation within phase0 to compute the storage slot of a Solidity mapping at a key of either value or non-value type.
    /// The storage slot corresponding to `key` is computed according to https://docs.soliditylang.org/en/v0.8.19/internals/layout_in_storage.html#mappings-and-dynamic-arrays
    ///
    /// # Assumptions
    /// - The type of the key is known at compile time
    pub fn slot_for_mapping_key_phase0(
        &self,
        ctx: &mut Context<F>,
        mapping_slot: SafeBytes32<F>,
        key: SolidityType<F>,
    ) -> MappingWitness<F> {
        match key {
            SolidityType::Value(key) => {
                MappingWitness::Value(self.slot_for_mapping_value_key(ctx, &mapping_slot, &key))
            }
            SolidityType::NonValue(key) => MappingWitness::NonValue(
                self.slot_for_mapping_nonvalue_key_phase0(ctx, mapping_slot, key),
            ),
        }
    }

    /// Performs rlc concatenation within phase1 to constrain the computation of a Solidity `mapping(key => value)`.
    /// Does nothing if mapping key was of Value type.
    ///
    /// * `ctx`: Circuit [Context]<F> to assign witnesses to.
    /// * `witness`: [MappingWitness]<F> representing the witness of the computation of the Solidity mapping.
    ///
    /// Returns:
    /// * [MappingTrace]<F> trace of the rlc computation to constrain the computation of the Solidity mapping.
    pub fn slot_for_mapping_key_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: MappingWitness<F>,
    ) -> MappingTrace<F> {
        match witness {
            MappingWitness::Value(_) => None,
            MappingWitness::NonValue(witness) => {
                Some(self.slot_for_mapping_nonvalue_key_phase1((ctx_gate, ctx_rlc), witness))
            }
        }
    }

    /// Performs witness generation within phase0 to constrain the computation of a nested Solidity mapping.
    /// Supports variable number of nestings, up to `MAX_NESTING`.
    ///
    /// Inputs:
    /// - `keccak`: [KeccakChip]<F> to constrain the computation of the Solidity mapping.
    /// - `mappings`: (Vec<[SolidityType]<F>>, [SafeType]<F, 1, 256>) representing the successive keys of the nested mapping in order paired with the mapping slot.
    /// - `nestings`: Specifies the amount of nesting (as this function supports variable nesting).
    ///
    /// Returns:
    /// - [NestedMappingWitness]<F> representing the witnesses to constrain the computation of the nested mapping, the desired mapping_slot, and the number of nestings.
    /// - Will return `bytes32(0)` if `nestings` is 0.
    ///
    /// # Assumptions
    /// - The type (Value vs Non-Value) of each key is known at compile time.
    /// - `keys` is padded to `MAX_NESTING` length
    pub fn slot_for_nested_mapping_phase0<const MAX_NESTING: usize>(
        &self,
        ctx: &mut Context<F>,
        mapping_slot: SafeBytes32<F>,
        keys: [SolidityType<F>; MAX_NESTING],
        nestings: AssignedValue<F>,
    ) -> NestedMappingWitness<F> {
        self.range().check_less_than_safe(ctx, nestings, MAX_NESTING as u64 + 1);
        let mut witness = Vec::with_capacity(MAX_NESTING);
        // slots[i] is the storage slot corresponding to keys[i]
        let mut slots = Vec::with_capacity(MAX_NESTING);
        for key in keys {
            let m_slot = slots.last().unwrap_or(&mapping_slot).clone();
            let w = self.slot_for_mapping_key_phase0(ctx, m_slot.clone(), key);
            slots.push(w.slot());
            witness.push(w);
        }
        let slot = if MAX_NESTING == 1 {
            // if only 1 nesting, we ignore `nestings` and just return the slot assuming `nestings` is 1
            slots.pop().unwrap()
        } else {
            let nestings_minus_one = self.gate().sub(ctx, nestings, Constant(F::ONE));
            let indicator = self.gate().idx_to_indicator(ctx, nestings_minus_one, MAX_NESTING);
            let slot = self.gate().select_array_by_indicator(ctx, &slots, &indicator);
            SafeTypeChip::unsafe_to_safe_type(slot)
        };
        NestedMappingWitness { witness, slot, nestings }
    }

    /// Performs rlc concatenation within phase1 to constrain the computation of a Solidity nested mapping.
    ///
    /// * `ctx`: Circuit [Context]<F> to assign witnesses to.
    /// * `witnesses`: Vec<[MappingWitness]<F>> representing the witnesses of the computation of the Solidity mapping that will be constrained.
    ///
    /// Returns:
    /// * `Vec<[MappingTrace]<F>>` containing the traces of the rlc computation to constrain the computation of the Solidity mapping.
    pub fn slot_for_nested_mapping_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: NestedMappingWitness<F>,
    ) -> Vec<MappingTrace<F>> {
        witness
            .witness
            .into_iter()
            .map(|w| self.slot_for_mapping_key_phase1((ctx_gate, ctx_rlc), w))
            .collect_vec()
    }

    /// Combines `EthStorageChip::parse_storage_proof_phase0` with `slot_for_nested_mapping_phase0` to compute the storage slot of a nested Solidity mapping and a storage proof of its inclusion within the storage trie.
    ///
    /// Inputs:
    /// - `proof` should be the MPT for the storage slot of the nested mapping, which must match the output of `slot_for_nested_mapping_phase0`.
    pub fn verify_mapping_storage_phase0<const MAX_NESTING: usize>(
        &self,
        ctx: &mut Context<F>,
        mapping_slot: SafeBytes32<F>,
        keys: [SolidityType<F>; MAX_NESTING],
        nestings: AssignedValue<F>,
        proof: MPTProof<F>,
    ) -> (NestedMappingWitness<F>, EthStorageWitness<F>) {
        let mapping_witness =
            self.slot_for_nested_mapping_phase0(ctx, mapping_slot, keys, nestings);
        let storage_witness = {
            let storage_chip = EthStorageChip::new(self.mpt, None);
            storage_chip.parse_storage_proof_phase0(ctx, mapping_witness.slot.clone(), proof)
        };
        (mapping_witness, storage_witness)
    }

    /// Combines `EthStorageChip::parse_storage_proof_phase1` with `slot_for_nested_mapping_phase1` to compute the slot of a nested Solidity mapping and a storage proof of its inclusion within the storage trie.
    pub fn verify_mapping_storage_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        mapping_witness: NestedMappingWitness<F>,
        storage_witness: EthStorageWitness<F>,
    ) -> (Vec<MappingTrace<F>>, EthStorageTrace<F>) {
        let mapping_trace =
            self.slot_for_nested_mapping_phase1((ctx_gate, ctx_rlc), mapping_witness);
        let storage_trace = {
            let storage_chip = EthStorageChip::new(self.mpt, None);
            storage_chip.parse_storage_proof_phase1((ctx_gate, ctx_rlc), storage_witness)
        };
        (mapping_trace, storage_trace)
    }
}
