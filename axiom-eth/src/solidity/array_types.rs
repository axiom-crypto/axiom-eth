use halo2_base::{safe_types::SafeBytes32, AssignedValue, Context};

use crate::Field;

use super::{add_to_slot, types::SolidityStoragePosition, SolidityChip};

// Note: storage arrays could be larger than this
pub const MAX_ARRAY_LEN_LOG2: u32 = 64;
pub const MAX_ARRAY_LEN: u128 = 2u128.pow(MAX_ARRAY_LEN_LOG2);

impl<'chip, F: Field> SolidityChip<'chip, F> {
    /// Performs witness generation within phase0 to constrain the computation of a Solidity array beginning at evm storage slot `beginning_slot`.
    ///
    /// * `ctx`: Circuit [Context]<F> to assign witnesses to.
    /// * `range: [RangeChip]<F> to constrain the division and modulo operations.
    /// * `item_bit_size`: [AssignedValue<F>] representing the size of the array items in bits.
    /// * `idx`: [AssignedValue]<F> representing the index within the array.
    /// * `beginning_slot`: [SafeBytes32]<F> representing the beginning of the evm storage slot of the array.
    ///
    /// Returns:
    /// * [SolidityStoragePosition] that is the slot where our desired item begins and the byte offset.
    pub fn slot_for_array_idx(
        &self,
        ctx: &mut Context<F>,
        idx: AssignedValue<F>,
        item_byte_size: AssignedValue<F>,
        beginning_slot: &SafeBytes32<F>,
    ) -> SolidityStoragePosition<F> {
        let (offset, pos) = self.slot_and_offset(ctx, idx, item_byte_size);

        let res_bytes = add_to_slot(ctx, self.range(), beginning_slot, offset);
        SolidityStoragePosition { slot: res_bytes, byte_offset: pos, item_byte_len: item_byte_size }
    }

    /// Performs witness generation within phase0 to constrain the computation of a Solidity dynamic array located at evm storage slot `array_slot`.
    /// DOES NOT CHECK IF IDX IS OUT OF BOUNDS.
    ///
    /// * `ctx`: Circuit [Context]<F> to assign witnesses to.
    /// * `range: [RangeChip]<F> to constrain the division and modulo operations.
    /// * `keccak`: [KeccakChip]<F> to constrain the computation of the Solidity dynamic array.
    /// * `array_slot`: [SafeBytes32]<F> representing the evm storage slot of the dynamic array.
    /// * `item_bit_size`: [AssignedValue<F>] representing the size of the array items in bits.
    /// * `idx`: [AssignedValue]<F> representing the index within the array.
    ///
    /// Returns:
    /// * (Vec<[AssignedValue]<F>>, [AssignedValue]<F>) that is the slot where our desired item begins with the byte offset of the struct.
    pub fn slot_for_dynamic_array_idx_unchecked(
        &self,
        ctx: &mut Context<F>,
        array_slot: &SafeBytes32<F>,
        item_byte_size: AssignedValue<F>,
        idx: AssignedValue<F>,
    ) -> SolidityStoragePosition<F> {
        // Find slot where data begins
        let hash_query = self.keccak().keccak_fixed_len(ctx, array_slot.value().to_vec());
        // Find slot for the idx
        self.slot_for_array_idx(ctx, idx, item_byte_size, &hash_query.output_bytes)
    }
}
