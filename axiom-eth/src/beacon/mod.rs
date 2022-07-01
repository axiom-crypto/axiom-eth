//! Merkle Patricia Trie (MPT) inclusion & exclusion proofs in ZK.
//!
//! See https://hackmd.io/@axiom/ry35GZ4l3 for a technical walkthrough of circuit structure and logic
use crate::Field;
use crate::{
    rlc::chip::RlcChip,
    ssz::{self, types::SszStruct, SSZInclusionWitness, SszChip},
};
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;

use self::ssz::SSZInputAssigned;
use self::{ssz::types::Chunk, types::ValidatorInfo};

use self::types::{Gwei, Validator};

pub mod data_gen;
#[cfg(test)]
pub mod tests;
pub mod types;

pub const BEACON_STATE_FIELDS: usize = 25;
pub const VALIDATOR_LIST_IDX: usize = 11;
pub const BALANCE_LIST_IDX: usize = 12;
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 1_099_511_627_776;
pub const VALIDATOR_REGISTRY_LIMIT_BITS: usize = 40;
pub const INFO_ADDITIONAL_BITS: usize = 2;
pub const VALIDATOR_LIST_PATH_BITS: usize = 5;
pub const VALIDATOR_LIST_PATH: [usize; 5] = [0, 1, 0, 1, 1];
pub const BALANCE_LIST_PATH: [usize; 5] = [0, 1, 1, 0, 0];
pub const VALIDATOR_DEPTH: usize = 46;
pub const BALANCE_DEPTH: usize = 44;

#[derive(Clone, Debug)]
pub struct BeaconChip<'range, F: Field> {
    pub ssz: &'range SszChip<'range, F>,
}

impl<'range, F: Field> BeaconChip<'range, F> {
    pub fn new(ssz: &'range SszChip<F>) -> Self {
        Self { ssz }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.ssz.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.ssz.range
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.ssz.rlc.as_ref().expect("RlcChip should be constructed and used only in SecondPhase")
    }

    pub fn validator_hash_root(self, ctx: &mut Context<F>, validator: Validator<F>) -> Chunk<F> {
        validator.hash_root(ctx, self.ssz)
    }

    pub fn verify_validator_inclusion(
        self,
        ctx: &mut Context<F>,
        validator: &Validator<F>,
        proof: SSZInputAssigned<F>,
    ) -> SSZInclusionWitness<F> {
        // let validator_hash = validator.hash_root(ctx, self.ssz, sha);
        // let witness = self.ssz.verify_inclusion_proof(ctx, sha, proof);
        // for (hash_byte, val_byte) in validator_hash.iter().zip(witness.val.iter()) {
        //     ctx.constrain_equal(hash_byte, val_byte);
        // }
        self.ssz.verify_struct_inclusion(ctx, proof, validator)
    }

    pub fn verify_validator_info_from_validator(
        self,
        ctx: &mut Context<F>,
        proof: SSZInputAssigned<F>,
        info: &ValidatorInfo<F>,
    ) -> SSZInclusionWitness<F> {
        let zero = ctx.load_zero();
        let witness = self.ssz.verify_struct_field_inclusion(ctx, zero, 4, proof, info);
        witness
    }

    pub fn verify_validator_info_from_beacon_block_root(
        self,
        ctx: &mut Context<F>,
        idx: AssignedValue<F>,
        info: &ValidatorInfo<F>,
        proof: SSZInputAssigned<F>,
    ) -> (AssignedValue<F>, SSZInclusionWitness<F>) {
        let zero = ctx.load_zero();
        let new_idx = self.gate().mul(ctx, Constant(F::from(4)), idx);
        let (list_len, witness) = self.verify_struct_from_beacon_block_root(
            ctx,
            new_idx,
            info,
            proof,
            VALIDATOR_LIST_PATH.to_vec(),
            Some(VALIDATOR_DEPTH + INFO_ADDITIONAL_BITS),
        );
        ctx.constrain_equal(&witness.directions[VALIDATOR_DEPTH], &zero);
        ctx.constrain_equal(&witness.directions[VALIDATOR_DEPTH + 1], &zero);
        self.range().check_less_than(ctx, idx, list_len, VALIDATOR_REGISTRY_LIMIT_BITS + 1);
        (list_len, witness)
    }

    pub fn verify_validator_field_hash_root(
        self,
        ctx: &mut Context<F>,
        field_num: AssignedValue<F>,
        proof: SSZInputAssigned<F>,
    ) -> (AssignedValue<F>, SSZInclusionWitness<F>) {
        let witness = self.ssz.verify_field_hash(ctx, field_num, 8, proof);
        (field_num, witness)
    }
    /// The root of the proof is beacon_root, maybe this isn't even necessary(?).
    /// verify_validator_inclusion seems to be sufficient due to cryptography or something
    pub fn verify_validator_from_beacon_block_root(
        self,
        ctx: &mut Context<F>,
        idx: AssignedValue<F>,
        validator: &Validator<F>,
        proof: SSZInputAssigned<F>,
    ) -> (AssignedValue<F>, SSZInclusionWitness<F>) {
        let (list_len, witness) = self.verify_struct_from_beacon_block_root(
            ctx,
            idx,
            validator,
            proof,
            VALIDATOR_LIST_PATH.to_vec(),
            Some(VALIDATOR_DEPTH),
        );
        self.range().check_less_than(ctx, idx, list_len, VALIDATOR_REGISTRY_LIMIT_BITS + 1);
        (list_len, witness)
    }

    /// /// The root of the proof is beacon_root, maybe this isn't even necessary(?).
    /// verify_validator_inclusion seems to be sufficient due to cryptography or something
    pub fn verify_validator_hash_from_beacon_block_root(
        &self,
        ctx: &mut Context<F>,
        idx: AssignedValue<F>,
        proof: SSZInputAssigned<F>,
    ) -> (AssignedValue<F>, SSZInclusionWitness<F>) {
        let (list_len, witness) = self.verify_hash_from_beacon_block_root(
            ctx,
            idx,
            proof,
            VALIDATOR_LIST_PATH.to_vec(),
            Some(VALIDATOR_DEPTH),
        );
        self.range().check_less_than(ctx, idx, list_len, VALIDATOR_REGISTRY_LIMIT_BITS + 1);
        (list_len, witness)
    }

    /// The root of the proof is beacon_root, maybe this isn't even necessary(?).
    /// verify_validator_inclusion seems to be sufficient due to cryptography or something
    /// There is a bit of redundancy here not gonna lie
    pub fn verify_balance_from_beacon_block_root(
        &self,
        ctx: &mut Context<F>,
        idx: AssignedValue<F>,
        idx_div_4: AssignedValue<F>,
        idx_mod_4: AssignedValue<F>,
        balance: &Gwei<F>,
        proof: SSZInputAssigned<F>,
    ) -> (AssignedValue<F>, AssignedValue<F>, SSZInclusionWitness<F>) {
        self.range().check_less_than_safe(ctx, idx_mod_4, 4);
        let (len, witness) = self.verify_hash_from_beacon_block_root(
            ctx,
            idx_div_4,
            proof,
            BALANCE_LIST_PATH.to_vec(),
            Some(BALANCE_DEPTH),
        );
        let balance_val = balance.val().value();
        let chunks = witness.val.chunks(8);
        let balances = chunks.map(|v| v.to_vec()).collect_vec();
        let indicator = self.gate().idx_to_indicator(ctx, idx_mod_4, 4);
        for i in 0..8 {
            let mut bytes = Vec::new();
            for j in 0..4 {
                bytes.push(balances[j][i]);
            }
            let chosen_byte = self.gate().select_by_indicator(ctx, bytes, indicator.clone());
            ctx.constrain_equal(&balance_val[i], &chosen_byte);
        }
        let mut match_idx = self.gate().mul(ctx, idx_div_4, Constant(F::from(4)));
        match_idx = self.gate().add(ctx, match_idx, idx_mod_4);
        ctx.constrain_equal(&idx, &match_idx);
        self.range().check_less_than(ctx, idx_div_4, len, VALIDATOR_REGISTRY_LIMIT_BITS + 1);
        self.range().check_less_than(ctx, idx, len, VALIDATOR_REGISTRY_LIMIT_BITS + 1);
        (idx, len, witness)
    }

    /// Passes back len in case struct is a weird basic type (which means its vals are packed).
    /// Verifies any struct in a list within the block_root.
    /// If the values get packed together (a list of basic types), then extra post processing must be done.
    /// See the balance function above
    pub fn verify_struct_from_beacon_block_root(
        &self,
        ctx: &mut Context<F>,
        idx: AssignedValue<F>,
        ssz_struct: &dyn SszStruct<F>,
        proof: SSZInputAssigned<F>,
        list_path: Vec<usize>,
        desired_depth: Option<usize>,
    ) -> (AssignedValue<F>, SSZInclusionWitness<F>) {
        let (list_len, witness) =
            self.verify_hash_from_beacon_block_root(ctx, idx, proof, list_path, desired_depth);
        let struct_root = ssz_struct.hash_root(ctx, self.ssz);
        for i in 0..32 {
            ctx.constrain_equal(&witness.val[i], &struct_root[i]);
        }
        (list_len, witness)
    }

    /// MUST CONSTRAIN THE IDX IS VALID AFTERWARDS, HENCE WHY LIST_LEN IS RETURNED
    pub fn verify_hash_from_beacon_block_root(
        &self,
        ctx: &mut Context<F>,
        idx: AssignedValue<F>,
        proof: SSZInputAssigned<F>,
        list_path: Vec<usize>,
        desired_depth: Option<usize>,
    ) -> (AssignedValue<F>, SSZInclusionWitness<F>) {
        let list_path_bits = list_path.len();
        let max_depth = proof.proof.len();
        // list_depth describes the number of nodes past the the fixed directions
        let list_depth = max_depth - list_path_bits - 1;
        let zero = ctx.load_zero();
        let depth = proof.depth;
        if let Some(_depth) = desired_depth {
            let good_depth = ctx.load_constant(F::from(_depth as u64));
            ctx.constrain_equal(&good_depth, &depth);
        }
        // proof needs at least list_path + 1 nodes in order to be valid
        let bad_depth = self.range().is_less_than_safe(ctx, depth, (list_path_bits + 1) as u64);
        ctx.constrain_equal(&bad_depth, &zero);
        // Constrain that we are actually looking in the correct list
        for i in 0..list_path_bits {
            let list_bit = ctx.load_constant(F::from(list_path[i] as u64));
            ctx.constrain_equal(&proof.directions[i], &list_bit);
        }
        // Constrain that we are going down the list values path
        ctx.constrain_equal(&proof.directions[list_path_bits], &zero);
        // Verify ssz_struct
        let witness = self.ssz.verify_inclusion_proof(ctx, proof);
        let fixed_bits_witness_plus_one = ctx.load_constant(F::from((list_path_bits + 2) as u64));
        let depth_adjusted = self.gate().sub(ctx, depth, fixed_bits_witness_plus_one);
        let depth_adjusted_indicator =
            self.gate().idx_to_indicator(ctx, depth_adjusted, list_depth);
        // creates an indicator for all slots less than depth
        let mut pre_depth = vec![zero; list_depth];
        pre_depth[list_depth - 1] = depth_adjusted_indicator[list_depth - 1];
        for i in 1..list_depth {
            pre_depth[list_depth - 1 - i] = self.gate().add(
                ctx,
                pre_depth[list_depth - i],
                depth_adjusted_indicator[list_depth - 1 - i],
            );
        }
        // constrains that the validator in question is at the claimed index within the list
        let mut cum_idx = zero;
        for i in 0..list_depth {
            let mut new_val =
                self.gate().add(ctx, witness.directions[i + list_path_bits + 1], cum_idx);
            new_val = self.gate().mul(ctx, new_val, pre_depth[i]);
            cum_idx = self.gate().add(ctx, new_val, cum_idx);
        }
        ctx.constrain_equal(&cum_idx, &idx);
        // recall that the `list_path_bits`th node in the proof contains the length of the list
        let mut list_len = zero;
        let base = ctx.load_constant(F::from(256));
        for i in 0..32 {
            list_len = self.gate().mul(ctx, list_len, base);
            list_len = self.gate().add(ctx, list_len, witness.proof[list_path_bits][31 - i]);
        }
        (list_len, witness)
    }
}
