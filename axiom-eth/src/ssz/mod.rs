use crate::Field;
use crate::{
    rlc::{
        chip::RlcChip,
        circuit::{builder::RlcCircuitBuilder, instructions::RlcCircuitInstructions},
    },
    sha256::Sha256Chip,
    utils::{assign_vec, uint_to_bytes_be},
};
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    utils::bit_length,
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use self::types::{Chunk, SszBasicType, SszBasicTypeList, SszBasicTypeVector, SszStruct};

#[cfg(test)]
pub mod tests;
pub mod types;

pub const NUM_BASIC_TYPES: usize = 7;
pub const BASIC_TYPE_BIT_SIZES: [usize; NUM_BASIC_TYPES] = [1, 8, 16, 32, 64, 128, 256];

#[derive(Clone, Debug)]
pub struct SszChip<'r, F: Field> {
    pub rlc: Option<&'r RlcChip<F>>, // We use this chip in FirstPhase when there is no RlcChip
    pub range: &'r RangeChip<F>,
    pub sha256: Sha256Chip<'r, F>,
}

pub fn next_pow2(n: usize) -> usize {
    let mut pow2 = 1;
    loop {
        if pow2 >= n {
            return pow2;
        }
        pow2 *= 2;
    }
}

impl<'r, F: Field> SszChip<'r, F> {
    pub fn new(
        rlc: Option<&'r RlcChip<F>>,
        range: &'r RangeChip<F>,
        sha256: Sha256Chip<'r, F>,
    ) -> Self {
        Self { rlc, range, sha256 }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.range.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.range
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.rlc.as_ref().expect("RlcChip should be constructed and used only in SecondPhase")
    }

    pub fn sha256(&self) -> &Sha256Chip<F> {
        &self.sha256
    }

    pub fn pack_basic_type(&self, ctx: &mut Context<F>, value: &SszBasicType<F>) -> Chunk<F> {
        let mut val = value.value().clone();
        let zero = ctx.load_zero();
        val.resize(32, zero);
        val
    }

    pub fn pack_basic_type_vector(
        &self,
        ctx: &mut Context<F>,
        value: &SszBasicTypeVector<F>,
    ) -> Vec<Chunk<F>> {
        let int_bit_size = value.int_bit_size();
        let int_byte_size = (int_bit_size + 7) / 8;
        let values = value.values();
        let mut total_bytes_len = next_pow2(int_byte_size * values.len());
        total_bytes_len = 32 * ((total_bytes_len + 31) / 32);
        let mut packed_bytes = Vec::new();
        for i in 0..values.len() {
            let int = values[i].value();
            for j in 0..int_byte_size {
                packed_bytes.push(int[j]);
            }
        }
        let zero = ctx.load_zero();
        packed_bytes.resize(total_bytes_len, zero);
        let packed_bytes = packed_bytes.chunks(32);
        packed_bytes.map(|v| v.to_vec()).collect_vec()
    }

    pub fn pack_basic_type_list(
        &self,
        ctx: &mut Context<F>,
        value: &SszBasicTypeList<F>,
    ) -> Vec<Chunk<F>> {
        let int_bit_size = value.int_bit_size();
        let int_byte_size = (int_bit_size + 7) / 8;
        let values = value.values();
        let mut total_bytes_len = next_pow2(int_byte_size * values.len());
        total_bytes_len = 32 * ((total_bytes_len + 31) / 32);
        let mut packed_bytes = Vec::new();
        for i in 0..values.len() {
            let int = values[i].value();
            for j in 0..int_byte_size {
                packed_bytes.push(int[j]);
            }
        }
        let zero = ctx.load_zero();
        packed_bytes.resize(total_bytes_len, zero);
        let packed_bytes = packed_bytes.chunks(32);
        packed_bytes.map(|v| v.to_vec()).collect_vec()
    }

    pub fn merkleize(&self, ctx: &mut Context<F>, chunks: Vec<Chunk<F>>) -> Chunk<F> {
        assert!(chunks.len().is_power_of_two());
        let len = chunks.len();
        if len == 1 {
            return chunks[0].clone();
        }
        let mut new_chunks = Vec::new();
        for i in 0..(len / 2) {
            let mut chunk0 = chunks[2 * i].clone();
            let mut chunk1 = chunks[2 * i + 1].clone();
            chunk0.append(&mut chunk1);
            let hash_query = self.sha256.sha256_fixed_len(ctx, chunk0);
            new_chunks.push(hash_query.output_assigned.clone());
        }
        return self.merkleize(ctx, new_chunks);
    }

    pub fn basic_type_hash_tree_root(
        &self,
        ctx: &mut Context<F>,
        value: &SszBasicType<F>,
    ) -> Chunk<F> {
        // let val_bytes = self.pack_basic_type(ctx, value);
        // self.merkleize(ctx, sha, vec![val_bytes])
        self.pack_basic_type(ctx, value)
    }

    pub fn basic_type_vector_hash_tree_root(
        &self,
        ctx: &mut Context<F>,
        vec: &SszBasicTypeVector<F>,
    ) -> Chunk<F> {
        let chunks = self.pack_basic_type_vector(ctx, &vec);
        self.merkleize(ctx, chunks)
    }

    pub fn basic_type_list_hash_tree_root(
        &self,
        ctx: &mut Context<F>,
        list: &SszBasicTypeList<F>,
    ) -> Chunk<F> {
        let len_bytes = uint_to_bytes_be(ctx, self.range, &list.len(), 32);
        let len_bytes = len_bytes.into_iter().map(|b| b.into()).rev().collect();
        let chunks = self.pack_basic_type_list(ctx, &list);
        let root = self.merkleize(ctx, chunks);
        self.merkleize(ctx, vec![root, len_bytes])
    }

    pub fn verify_inclusion_proof(
        &self,
        ctx: &mut Context<F>,
        input: SSZInputAssigned<F>,
    ) -> SSZInclusionWitness<F> {
        let val = &input.val;
        let root_bytes = &input.root_bytes;
        let proof = &input.proof;
        let directions = &input.directions;
        let depth = input.depth;
        // Check that depth is nonzero
        let depth_is_zero = self.gate().is_zero(ctx, depth);
        self.gate().assert_is_const(ctx, &depth_is_zero, &F::ZERO);
        let max_depth = proof.len();
        self.range.check_less_than_safe(ctx, depth, (max_depth + 1) as u64);
        assert!(proof.len() == directions.len());
        assert!(proof.len() == max_depth);
        for i in 0..max_depth {
            self.range.check_less_than_safe(ctx, directions[i], 2);
        }
        let zero = ctx.load_zero();
        let zero_chunk = vec![zero; 32];
        let mut roots = vec![zero_chunk];
        let depth_minus_one = self.gate().dec(ctx, depth);
        let depth_minus_one_indicator =
            self.gate().idx_to_indicator(ctx, depth_minus_one, max_depth);
        for i in 0..max_depth {
            let idx = max_depth - 1 - i;
            let mut child = Vec::new();
            for j in 0..32 {
                let child_byte =
                    self.gate().select(ctx, val[j], roots[i][j], depth_minus_one_indicator[idx]);
                child.push(child_byte);
            }
            let other_child = proof[idx].clone();
            let left_root = self.merkleize(ctx, vec![child.clone(), other_child.clone()]);
            let right_root = self.merkleize(ctx, vec![other_child, child]);
            let mut root = Vec::new();
            for j in 0..32 {
                let root_byte =
                    self.gate().select(ctx, right_root[j], left_root[j], directions[idx]);
                root.push(root_byte);
            }
            roots.push(root);
        }
        for j in 0..32 {
            ctx.constrain_equal(&roots[max_depth][j], &root_bytes[j]);
        }
        input
    }

    pub fn verify_field_hash(
        &self,
        ctx: &mut Context<F>,
        field_num: AssignedValue<F>,
        max_fields: usize,
        proof: SSZInputAssigned<F>,
    ) -> SSZInclusionWitness<F> {
        assert!(max_fields > 0);
        let log_max_fields = bit_length(max_fields as u64);
        self.range().check_less_than_safe(ctx, field_num, max_fields as u64);
        let field_num_bits = self.gate().num_to_bits(ctx, field_num, log_max_fields);
        let witness = self.verify_inclusion_proof(ctx, proof);
        let bad_depth = self.range().is_less_than_safe(ctx, witness.depth, log_max_fields as u64);
        self.gate().assert_is_const(ctx, &bad_depth, &F::from(0));
        for i in 1..(log_max_fields + 1) {
            let index = self.gate().sub(ctx, witness.depth, Constant(F::from(i as u64)));
            let dir_bit = self.gate().select_from_idx(ctx, witness.directions.clone(), index);
            ctx.constrain_equal(&dir_bit, field_num_bits[log_max_fields - i].as_ref());
        }
        witness
    }

    pub fn verify_struct_inclusion(
        &self,
        ctx: &mut Context<F>,
        proof: SSZInputAssigned<F>,
        ssz_struct: &impl SszStruct<F>,
    ) -> SSZInclusionWitness<F> {
        let witness = self.verify_inclusion_proof(ctx, proof);
        let struct_root = ssz_struct.hash_root(ctx, self);
        let zipped_vals: Vec<(&AssignedValue<F>, &AssignedValue<F>)> =
            witness.val.iter().zip(struct_root.iter()).collect();
        for (root_byte, hash_byte) in zipped_vals {
            ctx.constrain_equal(root_byte, hash_byte);
        }
        witness
    }

    pub fn verify_struct_field_inclusion(
        &self,
        ctx: &mut Context<F>,
        field_num: AssignedValue<F>,
        max_fields: usize,
        proof: SSZInputAssigned<F>,
        ssz_struct: &impl SszStruct<F>,
    ) -> SSZInclusionWitness<F> {
        let witness = self.verify_field_hash(ctx, field_num, max_fields, proof);
        let struct_root = ssz_struct.hash_root(ctx, self);
        let zipped_vals: Vec<(&AssignedValue<F>, &AssignedValue<F>)> =
            witness.val.iter().zip(struct_root.iter()).collect();
        for (root_byte, hash_byte) in zipped_vals {
            ctx.constrain_equal(root_byte, hash_byte);
        }
        witness
    }
}

pub type SSZInclusionWitness<F> = SSZInputAssigned<F>;

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]

pub struct SSZInput {
    pub val: Vec<u8>,
    pub root_bytes: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub directions: Vec<u8>,
    pub depth: usize,
    pub max_depth: usize,
}

impl SSZInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> SSZInputAssigned<F> {
        assert!(self.val.len() == 32);
        assert!(self.root_bytes.len() == 32);
        for i in 0..self.proof.len() {
            assert!(self.proof[i].len() == 32);
        }
        assert!(self.directions.len() == self.proof.len());
        assert!(self.depth <= self.max_depth);
        assert!(self.depth == self.proof.len());
        let val = assign_vec(ctx, self.val, 32);
        let root_bytes = assign_vec(ctx, self.root_bytes, 32);
        let zeros: Vec<u8> = [0; 32].to_vec();
        let mut padded_proof = self.proof.clone();
        padded_proof.resize(self.max_depth, zeros);
        let proof = padded_proof.into_iter().map(|node| assign_vec(ctx, node, 32)).collect_vec();
        let directions = assign_vec(ctx, self.directions, self.max_depth);
        let depth = ctx.load_witness(F::from(self.depth as u64));
        SSZInputAssigned { val, root_bytes, proof, directions, depth }
    }
}

#[derive(Clone, Debug)]
pub struct SSZInputAssigned<F: Field> {
    pub val: Chunk<F>,
    pub root_bytes: Chunk<F>,
    pub proof: Vec<Chunk<F>>,
    pub directions: Vec<AssignedValue<F>>,
    pub depth: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct SSZInclusionCircuit<F: Field> {
    pub input: SSZInput, // public and private inputs
    pub max_depth: usize,
    pub _marker: PhantomData<F>,
}

impl<F: Field> SSZInclusionCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_input(input: SSZInput) -> Self {
        let max_depth = input.max_depth;
        Self { input, max_depth, _marker: PhantomData }
    }
}

// TEMPORARY: We'll need an EthBeaconCircuitBuilder or something similar. Need to think about how to reduce code duplication.
impl<F: Field> RlcCircuitInstructions<F> for SSZInclusionCircuit<F> {
    type FirstPhasePayload = ();
    fn generate_witnesses_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let sha = Sha256Chip::new(range);
        let ctx = builder.base.main(0);
        let input = self.input.clone().assign(ctx);
        let ssz = SszChip::new(None, &range, sha);
        let _witness = ssz.verify_inclusion_proof(ctx, input);
    }
    fn generate_witnesses_phase1(
        _builder: &mut RlcCircuitBuilder<F>,
        _range: &RangeChip<F>,
        _rlc: &RlcChip<F>,
        _payload: Self::FirstPhasePayload,
    ) {
    }
}
