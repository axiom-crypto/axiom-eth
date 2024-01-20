//! Merkle Patricia Trie (MPT) inclusion & exclusion proofs in ZK.
//!
//! See https://hackmd.io/@axiom/ry35GZ4l3 for a technical walkthrough of circuit structure and logic
//!
//! # Assumptions
//! - We have tuned our circuit constants (see [`MAX_BRANCH_ITEM_LENS`]) for the case where the MPT value never ends as the 17th item in a branch.
//! - This only happens if a key in the trie is the prefix of another key in the trie.
//! - This never happens for Ethereum tries:
//!     - Either the trie has fixed key length (state, storage)
//!     - The key is of the form `rlp(idx)` and bytes are converted to even number of hexes (transaction, receipt).
//!       If two `i, j` had `rlp(i)` prefix of `rlp(j)`, that means there would have been no way to RLP decode `rlp(j)` (since you would decode it at first as if it were `rlp(i)`).
//! - If one needed to handle this case, one can add some additional handling using a different `MAX_BRANCH_ITEM_LENS` when parsing the terminal node.
use crate::Field;
use crate::{
    keccak::{types::KeccakVarLenQuery, KeccakChip},
    rlc::{
        chip::{rlc_is_equal, rlc_select, rlc_select_by_indicator, rlc_select_from_idx, RlcChip},
        circuit::builder::RlcContextPair,
        types::{RlcFixedTrace, RlcTrace, RlcVar},
    },
    rlp::{max_rlp_encoding_len, types::RlpFieldTrace, RlpChip},
};
use ethers_core::{types::H256, utils::hex::FromHex};
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    utils::{bit_length, log2_ceil, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use lazy_static::lazy_static;
use rlp::Rlp;
use serde::{Deserialize, Serialize};
use std::{
    cmp::max,
    iter::{self},
};

#[cfg(test)]
mod tests;
mod types;

pub use types::*;

pub const BRANCH_NUM_ITEMS: usize = 17;
pub const MAX_BRANCH_ITEM_LENS: [usize; BRANCH_NUM_ITEMS] = max_branch_lens(1).0; // max_vt_bytes = 0 is likely also ok; for our use cases, the value in a branch is always empty
pub const MAX_BRANCH_ENCODING_BYTES: usize = max_branch_lens(1).1;

lazy_static! {
    static ref DUMMY_BRANCH: Vec<u8> = Vec::from_hex("d18080808080808080808080808080808080").unwrap();
    static ref DUMMY_EXT: Vec<u8> = Vec::from_hex(
            "e21ba00000000000000000000000000000000000000000000000000000000000000000").unwrap();
    /// rlp(["", 0x0])
    static ref NULL_LEAF: Vec<u8> = Vec::from_hex(
            "c3818000").unwrap();
    /// keccak(rlp("")) = keccak(0x80)
    pub static ref KECCAK_RLP_EMPTY_STRING: Vec<u8> = Vec::from_hex(
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
    static ref RLP_EMPTY_STRING: Vec<u8> = Vec::from_hex(
            "80").unwrap();
}

pub const fn max_leaf_lens(max_key_bytes: usize, max_value_bytes: usize) -> ([usize; 2], usize) {
    let max_encoded_path_bytes = max_key_bytes + 1;
    let max_encoded_path_rlp_bytes = max_rlp_encoding_len(max_encoded_path_bytes);
    let max_value_rlp_bytes = max_rlp_encoding_len(max_value_bytes);
    let max_field_bytes = [max_encoded_path_rlp_bytes, max_value_rlp_bytes];
    let max_leaf_bytes = max_rlp_encoding_len(max_encoded_path_rlp_bytes + max_value_rlp_bytes);
    (max_field_bytes, max_leaf_bytes)
}

pub const fn max_ext_lens(max_key_bytes: usize) -> ([usize; 2], usize) {
    let max_node_ref_bytes = 32;
    let max_encoded_path_bytes = max_key_bytes + 1;
    let max_encoded_path_rlp_bytes = max_rlp_encoding_len(max_encoded_path_bytes);
    let max_node_ref_rlp_bytes = max_rlp_encoding_len(max_node_ref_bytes);
    let max_field_bytes = [max_encoded_path_rlp_bytes, max_node_ref_rlp_bytes];
    let max_ext_bytes = max_rlp_encoding_len(max_encoded_path_rlp_bytes + max_node_ref_rlp_bytes);
    (max_field_bytes, max_ext_bytes)
}

pub const fn max_branch_lens(max_vt_bytes: usize) -> ([usize; BRANCH_NUM_ITEMS], usize) {
    let max_node_ref_bytes = 32;
    let max_node_ref_rlp_bytes = max_rlp_encoding_len(max_node_ref_bytes);
    let mut max_field_bytes = [max_node_ref_rlp_bytes; BRANCH_NUM_ITEMS];
    max_field_bytes[BRANCH_NUM_ITEMS - 1] = max_rlp_encoding_len(max_vt_bytes);
    let max_field_bytes_sum = 16 * max_node_ref_rlp_bytes + max_field_bytes[BRANCH_NUM_ITEMS - 1];
    let max_branch_bytes = max_rlp_encoding_len(max_field_bytes_sum);
    (max_field_bytes, max_branch_bytes)
}

/// Thread-safe chip for performing Merkle Patricia Trie (MPT) inclusion proofs.
#[derive(Clone, Debug)]
pub struct MPTChip<'r, F: Field> {
    pub rlp: RlpChip<'r, F>,
    pub keccak: &'r KeccakChip<F>,
}

impl<'r, F: Field> MPTChip<'r, F> {
    pub fn new(rlp: RlpChip<'r, F>, keccak: &'r KeccakChip<F>) -> Self {
        Self { rlp, keccak }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.rlp.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.rlp.range
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.rlp.rlc()
    }

    pub fn rlp(&self) -> RlpChip<F> {
        self.rlp
    }

    pub fn keccak(&self) -> &'r KeccakChip<F> {
        self.keccak
    }

    /// When one node is referenced inside another node, what is included is H(rlp.encode(x)), where H(x) = keccak256(x) if len(x) >= 32 else x and rlp.encode is the RLP encoding function.
    ///
    /// Assumes that `bytes` is non-empty.
    pub fn mpt_hash_phase0(
        &self,
        ctx: &mut Context<F>, // ctx_gate in FirstPhase
        bytes: AssignedBytes<F>,
        len: AssignedValue<F>,
    ) -> MPTHashWitness<F> {
        assert!(!bytes.is_empty());
        self.keccak.keccak_var_len(ctx, bytes, len, 0usize)
    }

    /// When one node is referenced inside another node, what is included is H(rlp.encode(x)), where H(x) = keccak256(x) if len(x) >= 32 else x and rlp.encode is the RLP encoding function.
    /// We only return the RLC value of the MPT hash
    pub fn mpt_hash_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>, // ctxs in SecondPhase
        keccak_query: &KeccakVarLenQuery<F>,
    ) -> MPTHashTrace<F> {
        // RLC of keccak(rlp.encode(x))
        let hash_bytes = keccak_query.output_bytes.as_ref().iter().copied();
        let hash_rlc = self.rlc().compute_rlc_fixed_len(ctx_rlc, hash_bytes);
        let len = keccak_query.length;
        let max_len = std::cmp::max(keccak_query.input_assigned.len(), 32);
        let thirty_two = F::from(32);
        let is_short = self.range().is_less_than(
            ctx_gate,
            len,
            Constant(thirty_two),
            bit_length(max_len as u64),
        );
        let mpt_hash_len = self.gate().select(ctx_gate, len, Constant(thirty_two), is_short);
        // input_assigned = rlp.encode(x), we then truncate to at most 32 bytes
        let mut input_trunc = keccak_query.input_assigned.clone();
        input_trunc.truncate(32);
        // Compute RLC(input_trunc) = RLC( (rlp.encode(x))[0..min(input_assigned.len, 32] )
        // We will only use this value if is_short = 1
        let input_rlc =
            self.rlc().compute_rlc((ctx_gate, ctx_rlc), self.gate(), input_trunc, mpt_hash_len);
        let mpt_hash_rlc =
            self.gate().select(ctx_gate, input_rlc.rlc_val, hash_rlc.rlc_val, is_short);
        MPTHashTrace { hash: hash_rlc, mpt_hash: RlcTrace::new(mpt_hash_rlc, mpt_hash_len, 32) }
    }

    /// Parse the RLP encoding of an assumed leaf node.
    /// Computes the keccak hash (or literal, see [`mpt_hash_phase0`]) of the node's RLP encoding.
    ///
    /// This is the same as the first part of [`parse_mpt_inclusion_phase0`]
    /// except that the assumed maximum length of a leaf node
    /// may be different from that of an extension node.
    pub fn parse_terminal_node_phase0(
        &self,
        ctx: &mut Context<F>,
        leaf_bytes: MPTNode<F>,
        max_key_bytes: usize,
        max_value_bytes: usize,
    ) -> TerminalWitness<F> {
        let (_, max_leaf_bytes) = max_leaf_lens(max_key_bytes, max_value_bytes);
        let (_, max_ext_bytes) = max_ext_lens(max_key_bytes);
        let max_ext_bytes = max(max_ext_bytes, MAX_BRANCH_ENCODING_BYTES);
        let max_leaf_bytes = max(max_ext_bytes, max_leaf_bytes);
        assert_eq!(leaf_bytes.rlp_bytes.len(), max_leaf_bytes);

        let [dummy_branch, dummy_ext] =
            [DUMMY_BRANCH.clone(), DUMMY_EXT.clone()].map(|mut dummy| {
                dummy.resize(max_leaf_bytes, 0u8);
                dummy.into_iter().map(|b| Constant(F::from(b as u64))).collect_vec()
            });

        let (ext_in, branch_in): (AssignedBytes<F>, AssignedBytes<F>) = leaf_bytes
            .rlp_bytes
            .into_iter()
            .zip(dummy_ext)
            .zip(dummy_branch)
            .map(|((node_byte, dummy_ext_byte), dummy_branch_byte)| {
                (
                    self.gate().select(ctx, node_byte, dummy_ext_byte, leaf_bytes.node_type),
                    self.gate().select(ctx, dummy_branch_byte, node_byte, leaf_bytes.node_type),
                )
            })
            .unzip();

        let ext_parsed = self.parse_leaf_phase0(ctx, ext_in, max_key_bytes, max_value_bytes);
        let branch_parsed = {
            assert_eq!(branch_in.len(), max_leaf_bytes);

            let rlp =
                self.rlp.decompose_rlp_array_phase0(ctx, branch_in, &MAX_BRANCH_ITEM_LENS, false);
            let hash_query = self.mpt_hash_phase0(ctx, rlp.rlp_array.clone(), rlp.rlp_len);
            BranchWitness { rlp, hash_query }
        };
        TerminalWitness { node_type: leaf_bytes.node_type, ext: ext_parsed, branch: branch_parsed }
    }

    pub fn parse_terminal_node_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: TerminalWitness<F>,
    ) -> TerminalTrace<F> {
        let ext = self.parse_leaf_phase1((ctx_gate, ctx_rlc), witness.ext);
        // phase 1 parsing is the same for terminal or non-terminal branches, since the max length is already determined
        let branch = self.parse_nonterminal_branch_phase1((ctx_gate, ctx_rlc), witness.branch);
        TerminalTrace { node_type: witness.node_type, ext, branch }
    }

    pub fn parse_leaf_phase0(
        &self,
        ctx: &mut Context<F>,
        leaf_bytes: AssignedBytes<F>,
        max_key_bytes: usize,
        max_value_bytes: usize,
    ) -> LeafWitness<F> {
        let (max_field_bytes, max_leaf_bytes) = max_leaf_lens(max_key_bytes, max_value_bytes);
        // for small values, max_ext_bytes may be larger than max_leaf_bytes
        let (max_ext_field_bytes, max_ext_bytes) = max_ext_lens(max_key_bytes);
        let max_ext_bytes = max(max_ext_bytes, MAX_BRANCH_ENCODING_BYTES);
        let max_leaf_bytes = max(max_ext_bytes, max_leaf_bytes);
        let max_field_bytes = [max_field_bytes[0], max(max_field_bytes[1], max_ext_field_bytes[1])];
        assert_eq!(leaf_bytes.len(), max_leaf_bytes);
        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, leaf_bytes, &max_field_bytes, false);
        // TODO: remove unnecessary clones somehow?
        let hash_query =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len);
        LeafWitness { rlp: rlp_witness, hash_query }
    }

    /// Parse the RLP encoding of an assumed leaf node.
    /// Computes the keccak hash (or literal, see [`mpt_hash_phase1`]) of the node's RLP encoding.
    pub fn parse_leaf_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: LeafWitness<F>,
    ) -> LeafTrace<F> {
        let rlp_trace =
            self.rlp.decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.rlp, false);
        let [key_path, value]: [RlpFieldTrace<F>; 2] = rlp_trace.field_trace.try_into().unwrap();
        let rlcs = self.mpt_hash_phase1((ctx_gate, ctx_rlc), &witness.hash_query);
        LeafTrace { key_path, value, rlcs }
    }

    /// Parse the RLP encoding of an assumed extension node.
    /// Computes the keccak hash (or literal, see [`mpt_hash_phase0`]) of the node's RLP encoding.
    pub fn parse_ext_phase0(
        &self,
        ctx: &mut Context<F>,
        ext_bytes: AssignedBytes<F>,
        max_key_bytes: usize,
    ) -> ExtensionWitness<F> {
        let (max_field_bytes, max_ext_bytes) = max_ext_lens(max_key_bytes);
        let max_ext_bytes = max(max_ext_bytes, MAX_BRANCH_ENCODING_BYTES);
        assert_eq!(ext_bytes.len(), max_ext_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, ext_bytes, &max_field_bytes, false);
        let hash_query =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len);
        ExtensionWitness { rlp: rlp_witness, hash_query }
    }

    /// Parse the RLP encoding of an assumed extension node.
    /// Computes the keccak hash (or literal, see [`mpt_hash_phase1`]) of the node's RLP encoding.
    pub fn parse_ext_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: ExtensionWitness<F>,
    ) -> ExtensionTrace<F> {
        let rlp_trace =
            self.rlp.decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.rlp, false);
        let [key_path, node_ref]: [RlpFieldTrace<F>; 2] = rlp_trace.field_trace.try_into().unwrap();
        let rlcs = self.mpt_hash_phase1((ctx_gate, ctx_rlc), &witness.hash_query);
        ExtensionTrace { key_path, node_ref, rlcs }
    }

    /// Parse the RLP encoding of an assumed branch node.
    /// Computes the keccak hash (or literal, see [`mpt_hash_phase0`]) of the node's RLP encoding.
    pub fn parse_nonterminal_branch_phase0(
        &self,
        ctx: &mut Context<F>,
        branch_bytes: AssignedBytes<F>,
        max_key_bytes: usize,
    ) -> BranchWitness<F> {
        let (_, max_ext_bytes) = max_ext_lens(max_key_bytes);
        let max_branch_bytes = max(max_ext_bytes, MAX_BRANCH_ENCODING_BYTES);
        assert_eq!(branch_bytes.len(), max_branch_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, branch_bytes, &MAX_BRANCH_ITEM_LENS, false);
        let hash_query =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len);
        BranchWitness { rlp: rlp_witness, hash_query }
    }

    pub fn parse_nonterminal_branch_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: BranchWitness<F>,
    ) -> BranchTrace<F> {
        let rlp_trace =
            self.rlp.decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.rlp, false);
        let node_refs: [RlpFieldTrace<F>; 17] = rlp_trace.field_trace.try_into().unwrap();
        let rlcs = self.mpt_hash_phase1((ctx_gate, ctx_rlc), &witness.hash_query);
        BranchTrace { node_refs, rlcs }
    }

    pub fn compute_rlc_trace(
        &self,
        ctx: RlcContextPair<F>,
        inputs: Vec<AssignedValue<F>>,
        len: AssignedValue<F>,
    ) -> RlcTrace<F> {
        self.rlc().compute_rlc(ctx, self.gate(), inputs, len)
    }

    /* Inputs must follow the following unchecked constraints:
     * keys must have positive length
     * values must have length at least 32
     * trie has to be nonempty (root is not KECCAK_RLP_EMPTY_STRING)
     */
    /// Loads input witnesses into the circuit and parses the RLP encoding of nodes and leaves
    pub fn parse_mpt_inclusion_phase0(
        &self,
        ctx: &mut Context<F>,
        proof: MPTProof<F>,
    ) -> MPTProofWitness<F> {
        let max_key_byte_len = proof.max_key_byte_len;
        let value_max_byte_len = proof.value_bytes.len();
        let max_depth = proof.max_depth;
        assert_eq!(proof.nodes.len(), max_depth - 1);
        assert_eq!(proof.root_hash_bytes.len(), 32);
        assert_eq!(proof.key_bytes.len(), max_key_byte_len);
        let (_, ext_max_byte_len) = max_ext_lens(max_key_byte_len);
        let node_max_byte_len = max(ext_max_byte_len, MAX_BRANCH_ENCODING_BYTES);

        let [dummy_branch, dummy_ext] =
            [DUMMY_BRANCH.clone(), DUMMY_EXT.clone()].map(|mut dummy| {
                dummy.resize(node_max_byte_len, 0u8);
                dummy.into_iter().map(|b| Constant(F::from(b as u64))).collect_vec()
            });

        /* Validate inputs, check that:
         * all inputs are bytes
         * node_types[idx] in {0, 1}
         * key_frag_is_odd[idx] in {0, 1}
         * slot_is_empty in {0, 1}
         * key_frag_hexes are hexs
         * 0 <= depth <= max_depth
         * 0 <= value_byte_len <= value_max_byte_len
         * 0 <= key_frag_byte_len[idx] <= key_byte_len + 1
         */
        for byte in iter::empty()
            .chain(proof.key_bytes.iter())
            .chain(proof.value_bytes.iter())
            .chain(proof.root_hash_bytes.iter())
            .chain(proof.leaf.rlp_bytes.iter())
            .chain(proof.nodes.iter().flat_map(|node| node.rlp_bytes.iter()))
        {
            self.range().range_check(ctx, *byte, 8);
        }
        for bit in iter::once(&proof.slot_is_empty)
            .chain(iter::once(&proof.leaf.node_type))
            .chain(proof.nodes.iter().map(|node| &node.node_type))
            .chain(proof.key_frag.iter().map(|frag| &frag.is_odd))
        {
            self.gate().assert_bit(ctx, *bit);
        }
        for nibble in proof.key_frag.iter().flat_map(|frag| frag.nibbles.iter()) {
            self.range().range_check(ctx, *nibble, 4);
        }
        self.range().check_less_than_safe(ctx, proof.depth, max_depth as u64 + 1);
        self.range().check_less_than_safe(ctx, proof.value_byte_len, value_max_byte_len as u64 + 1);
        if let Some(key_byte_len) = proof.key_byte_len {
            self.range().check_less_than_safe(ctx, key_byte_len, max_key_byte_len as u64 + 1);
            let two = ctx.load_constant(F::from(2u64));
            let frag_ub = self.gate().add(ctx, two, key_byte_len);
            for frag_len in proof.key_frag.iter().map(|frag| frag.byte_len) {
                self.range().check_less_than(
                    ctx,
                    frag_len,
                    frag_ub,
                    log2_ceil(max_key_byte_len as u64) + 2,
                );
            }
        } else {
            for frag_len in proof.key_frag.iter().map(|frag| frag.byte_len) {
                self.range().check_less_than_safe(ctx, frag_len, max_key_byte_len as u64 + 2);
            }
        }
        /* Parse RLP
         * RLP Terminal  for leaf
         * RLP Extension for select(dummy_extension[idx], nodes[idx], node_types[idx])
         * RLP Branch    for select(nodes[idx], dummy_branch[idx], node_types[idx])
         */
        let terminal_node =
            self.parse_terminal_node_phase0(ctx, proof.leaf, max_key_byte_len, value_max_byte_len);
        let nodes: Vec<_> = proof
            .nodes
            .into_iter()
            .map(|node| {
                assert_eq!(node.rlp_bytes.len(), node_max_byte_len);
                let (ext_in, branch_in): (AssignedBytes<F>, AssignedBytes<F>) = node
                    .rlp_bytes
                    .iter()
                    .zip(dummy_ext.iter())
                    .zip(dummy_branch.iter())
                    .map(|((&node_byte, &dummy_ext_byte), &dummy_branch_byte)| {
                        (
                            self.gate().select(ctx, node_byte, dummy_ext_byte, node.node_type),
                            self.gate().select(ctx, dummy_branch_byte, node_byte, node.node_type),
                        )
                    })
                    .unzip();

                let ext_parsed = self.parse_ext_phase0(ctx, ext_in, max_key_byte_len);
                let branch_parsed =
                    self.parse_nonterminal_branch_phase0(ctx, branch_in, max_key_byte_len);
                MPTNodeWitness { node_type: node.node_type, ext: ext_parsed, branch: branch_parsed }
            })
            .collect();
        // Check key fragment and prefix consistency
        let mut key_frag_ext_bytes = Vec::with_capacity(max_depth - 1);
        let mut key_frag_leaf_bytes = Vec::with_capacity(max_depth);
        let mut frag_lens = Vec::with_capacity(max_depth);
        // assert to avoid capacity checks?
        assert_eq!(proof.key_frag.len(), max_depth);

        for (idx, key_frag) in proof.key_frag.iter().enumerate() {
            assert_eq!(key_frag.nibbles.len(), 2 * max_key_byte_len);
            let leaf_path_bytes = hex_prefix_encode(
                ctx,
                self.gate(),
                &key_frag.nibbles,
                key_frag.is_odd,
                max_key_byte_len,
                false,
            );
            if idx < max_depth - 1 {
                // all except first byte are same as `leaf_path_bytes`
                let ext_path_byte_first = hex_prefix_encode_first(
                    ctx,
                    self.gate(),
                    key_frag.nibbles[0],
                    key_frag.is_odd,
                    true,
                );
                let ext_path_bytes = [&[ext_path_byte_first], &leaf_path_bytes[1..]].concat();
                key_frag_ext_bytes.push(ext_path_bytes);
            }
            key_frag_leaf_bytes.push(leaf_path_bytes);

            let frag_len = hex_prefix_len(ctx, self.gate(), key_frag.byte_len, key_frag.is_odd);
            frag_lens.push(frag_len);
        }

        let mut key_hexs = Vec::with_capacity(2 * max_key_byte_len);
        for byte in proof.key_bytes.into_iter() {
            let bits = self.gate().num_to_bits(ctx, byte, 8);
            let hexs = [4, 0].map(|i| {
                self.gate().inner_product(
                    ctx,
                    bits[i..i + 4].iter().copied(),
                    (0..4).map(|x| Constant(self.gate().pow_of_two()[x])),
                )
            });
            key_hexs.extend(hexs);
        }
        MPTProofWitness {
            value_bytes: proof.value_bytes,
            value_byte_len: proof.value_byte_len,
            root_hash_bytes: proof.root_hash_bytes,
            key_byte_len: proof.key_byte_len,
            depth: proof.depth,
            nodes,
            terminal_node,
            slot_is_empty: proof.slot_is_empty,
            max_key_byte_len,
            max_depth,
            key_frag: proof.key_frag,
            key_frag_ext_bytes,
            key_frag_leaf_bytes,
            frag_lens,
            key_hexs,
        }
    }

    /// Checks constraints after the proof is parsed in phase 0
    pub fn parse_mpt_inclusion_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        mut witness: MPTProofWitness<F>,
    ) {
        let gate = self.gate();
        let max_depth = witness.max_depth;
        let terminal_node =
            self.parse_terminal_node_phase1((ctx_gate, ctx_rlc), witness.terminal_node.clone());
        let nodes: Vec<MPTNodeTrace<F>> = witness
            .nodes
            .into_iter()
            .map(|node| {
                let ext_parsed = self.parse_ext_phase1((ctx_gate, ctx_rlc), node.ext);
                let branch_parsed =
                    self.parse_nonterminal_branch_phase1((ctx_gate, ctx_rlc), node.branch);
                MPTNodeTrace { node_type: node.node_type, ext: ext_parsed, branch: branch_parsed }
            })
            .collect();
        let key_frag_ext_rlcs: Vec<_> = witness
            .key_frag_ext_bytes
            .into_iter()
            .zip(witness.key_frag.iter())
            .map(|(bytes, frag)| self.compute_rlc_trace((ctx_gate, ctx_rlc), bytes, frag.byte_len))
            .collect();
        let key_frag_leaf_rlcs: Vec<_> = witness
            .key_frag_leaf_bytes
            .into_iter()
            .zip(witness.key_frag.iter())
            .map(|(bytes, frag)| self.compute_rlc_trace((ctx_gate, ctx_rlc), bytes, frag.byte_len))
            .collect();
        let key_hexs = witness.key_hexs;
        let slot_is_empty = witness.slot_is_empty;
        let slot_is_occupied = self.gate().not(ctx_gate, slot_is_empty);
        let mut proof_is_empty = self.gate().is_zero(ctx_gate, witness.depth);
        proof_is_empty = self.gate().and(ctx_gate, proof_is_empty, slot_is_empty);
        // set `depth = 1` if proof is empty
        let pseudo_depth = self.gate().add(ctx_gate, witness.depth, proof_is_empty);
        let pseudo_depth_minus_one = self.gate().sub(ctx_gate, pseudo_depth, Constant(F::ONE));
        // pseudo_depth_minus_one_indicator[idx] = (idx == pseudo_depth - 1); this is used many times below
        let pseudo_depth_minus_one_indicator =
            self.gate().idx_to_indicator(ctx_gate, pseudo_depth_minus_one, max_depth);

        // Match fragments to node key
        for (((key_frag_ext_rlc, node), is_last), frag_len) in key_frag_ext_rlcs
            .into_iter()
            .zip(nodes.iter())
            .zip(pseudo_depth_minus_one_indicator.iter())
            .zip(witness.frag_lens.iter_mut())
        {
            // When node is extension, check node key RLC equals key frag RLC
            let node_key_path_rlc = rlc_select(
                ctx_gate,
                gate,
                terminal_node.ext.key_path.field_trace,
                node.ext.key_path.field_trace,
                *is_last,
            );
            let node_type =
                self.gate().select(ctx_gate, terminal_node.node_type, node.node_type, *is_last);
            let mut node_key_is_equal =
                rlc_is_equal(ctx_gate, self.gate(), node_key_path_rlc, key_frag_ext_rlc);
            // The key fragments must be equal unless either:
            // * node is not extension
            // * slot_is_empty and this is the last node
            // If slot_is_empty && this is the last node && node is extension, then node key fragment must NOT equal key fragment (which is the last key fragment)
            // Reminder: node_type = 1 if extension, 0 if branch
            let is_ext = node_type;
            let is_branch = self.gate().not(ctx_gate, node_type);
            // is_ext ? node_key_is_equal : 1
            node_key_is_equal = self.gate().mul_add(ctx_gate, node_key_is_equal, is_ext, is_branch);
            // !is_last || !is_ext = !(is_last && is_ext) = 1 - is_last * is_ext
            let mut expected = self.gate().sub_mul(ctx_gate, Constant(F::ONE), *is_last, is_ext);
            // (slot_is_empty ? !(is_last && is_ext) : 1), we cache slot_is_occupied as an optimization
            let is_not_last = self.gate().not(ctx_gate, *is_last);
            let slot_is_occupied_expected =
                self.gate().and(ctx_gate, slot_is_occupied, is_not_last);
            expected =
                self.gate().mul_add(ctx_gate, expected, slot_is_empty, slot_is_occupied_expected);
            // assuming node type is not extension if idx > pf.len() [we don't care what happens for these idx]
            ctx_gate.constrain_equal(&node_key_is_equal, &expected);

            // We enforce that the frag_len is 1 if the node is a branch, unless it is the last node (idx = depth - 1)
            // This check is only necessary if slot_is_empty; otherwise, the key length and overall concatenation check will enforce this
            let is_branch_and_not_last = self.gate().mul_not(ctx_gate, *is_last, is_branch);
            *frag_len =
                self.gate().select(ctx_gate, Constant(F::ONE), *frag_len, is_branch_and_not_last);
        }
        // match hex-prefix encoding of leaf path (gotten from witness.key_frag) to the parsed leaf encoded path
        // ignore leaf if slot_is_empty
        {
            let leaf_encoded_path_rlc = rlc_select_by_indicator(
                ctx_gate,
                self.gate(),
                key_frag_leaf_rlcs,
                pseudo_depth_minus_one_indicator.clone(),
            );
            let mut check = rlc_is_equal(
                ctx_gate,
                self.gate(),
                leaf_encoded_path_rlc,
                terminal_node.ext.key_path.field_trace,
            );
            check = self.gate().or(ctx_gate, check, slot_is_empty);
            self.gate().assert_is_const(ctx_gate, &check, &F::ONE);
        }

        // Check key fragments concatenate to key using hex RLC
        // We supply witness key fragments so this check passes even if the slot is empty
        let fragment_first_nibbles = {
            let key_hex_rlc = if let Some(key_byte_len) = witness.key_byte_len {
                // key_hex_len = 2 * key_byte_len
                let key_hex_len = self.gate().add(ctx_gate, key_byte_len, key_byte_len);
                self.rlc().compute_rlc((ctx_gate, ctx_rlc), self.gate(), key_hexs, key_hex_len)
            } else {
                let RlcFixedTrace { rlc_val, len: max_len } =
                    self.rlc().compute_rlc_fixed_len(ctx_rlc, key_hexs);
                let len = ctx_gate.load_constant(F::from(max_len as u64));
                RlcTrace { rlc_val, len, max_len }
            };
            let (fragment_rlcs, fragment_first_nibbles): (Vec<_>, Vec<_>) = witness
                .key_frag
                .into_iter()
                .zip(witness.frag_lens)
                .map(|(key_frag, frag_len)| {
                    let first_nibble = key_frag.nibbles[0];
                    (
                        self.rlc().compute_rlc(
                            (ctx_gate, ctx_rlc),
                            self.gate(),
                            key_frag.nibbles,
                            frag_len,
                        ),
                        first_nibble,
                    )
                })
                .unzip();
            self.rlc().load_rlc_cache(
                (ctx_gate, ctx_rlc),
                self.gate(),
                bit_length(2 * witness.max_key_byte_len as u64),
            );
            self.rlc().constrain_rlc_concat(
                ctx_gate,
                self.gate(),
                fragment_rlcs,
                &key_hex_rlc,
                Some(pseudo_depth),
            );
            fragment_first_nibbles
        };
        /* Check value matches. Currently value_bytes is RLC encoded
         * and value_byte_len is the RLC encoding's length
         */
        {
            let value_rlc_trace = self.rlp.rlc().compute_rlc(
                (ctx_gate, ctx_rlc),
                self.gate(),
                witness.value_bytes.clone(),
                witness.value_byte_len,
            );
            // value doesn't matter if slot is empty; by default we will make leaf.value = 0 in that case
            let branch_value_trace = terminal_node.branch.node_refs[16].field_trace;
            let value_trace = rlc_select(
                ctx_gate,
                self.gate(),
                terminal_node.ext.value.field_trace,
                branch_value_trace,
                terminal_node.node_type,
            );
            let value_equals_leaf =
                rlc_is_equal(ctx_gate, self.gate(), value_rlc_trace, value_trace);
            let value_check = self.gate().or(ctx_gate, value_equals_leaf, slot_is_empty);
            self.gate().assert_is_const(ctx_gate, &value_check, &F::ONE);
        }
        /*
        Check hash chains:
        Recall that nodes.len() = slot_is_empty ? depth : depth - 1

        * hash(nodes[0]) == root_hash IF !proof_is_empty
        * hash(nodes[idx + 1]) is in nodes[idx] for idx in 0..depth - 2
        * hash(slot_is_empty ? nodes[depth - 1] : leaf_bytes) is in nodes[depth - 2]

        if slot_is_empty:
            we assume that depth < max_depth: if depth == max_depth, then we set hash(nodes[depth - 1]) := 0. The circuit will try to prove 0 in nodes[max_depth - 2], which will either fail or (succeed => still shows MPT does not include `key`)
        if proof_is_empty:
            then root_hash = keccak(rlp("")) = keccak(0x80) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        */
        // if proof_is_empty, then root_hash = keccak(rlp("")) = keccak(0x80) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        let root_hash_rlc = self.rlc().compute_rlc_fixed_len(ctx_rlc, witness.root_hash_bytes);

        let null_root_rlc = {
            let keccak_rlp_null = KECCAK_RLP_EMPTY_STRING
                .iter()
                .map(|b| ctx_gate.load_constant(F::from(*b as u64)))
                .collect::<Vec<_>>();
            self.rlc().compute_rlc_fixed_len(ctx_rlc, keccak_rlp_null)
        };
        let root_is_null =
            self.gate().is_equal(ctx_gate, root_hash_rlc.rlc_val, null_root_rlc.rlc_val);

        let mut matches = Vec::with_capacity(max_depth);
        let mut branch_refs_are_null = Vec::with_capacity(max_depth);
        // assert so later array indexing doesn't do bound check
        assert_eq!(nodes.len(), max_depth - 1);

        // makes match_sums[idx] = idx later on
        matches.push(ctx_gate.load_constant(F::ZERO));

        let pseudo_depth_indicator =
            self.gate().idx_to_indicator(ctx_gate, pseudo_depth, max_depth);

        let leaf_hash_rlc = terminal_node.mpt_hash_rlc(ctx_gate, self.gate());
        // TODO: maybe use rust iterators instead here, would make it harder to read though

        for idx in 0..max_depth {
            if idx == 0 {
                // if !proof_is_empty:
                //     check hash(nodes[0]) == root_hash
                // else:
                //     check root_hash == keccak(rlp(""))

                // The root_hash is always the keccak hash of the root node.
                // However `node_hash_rlc` above is the `mpt_hash` of the node, which could be
                // just the RLP of the node itself is its length is less than 32 bytes.
                // Therefore we have to specially extract the actual hash (denoted _hash32) in this case below
                let leaf_hash32_rlc = terminal_node.keccak_rlc(ctx_gate, self.gate());
                let node_hash32_rlc = if idx < max_depth - 1 {
                    let node_hash32_rlc = nodes[idx].keccak_rlc(ctx_gate, self.gate());
                    // is_last = (idx == pseudo_depth - 1)
                    let is_last = pseudo_depth_minus_one_indicator[idx];
                    //self.gate().mul_not(ctx_gate, slot_is_empty, is_last);
                    self.gate().select(ctx_gate, leaf_hash32_rlc, node_hash32_rlc, is_last)
                } else {
                    leaf_hash32_rlc
                };
                let mut root_check =
                    self.gate().is_equal(ctx_gate, node_hash32_rlc, root_hash_rlc.rlc_val);
                root_check = self.gate().select(ctx_gate, root_is_null, root_check, proof_is_empty);
                self.gate().assert_is_const(ctx_gate, &root_check, &F::ONE);
            } else {
                // we check that the mpt hash of a node matches its reference in a previous node
                // since `terminal_node` is stored separately, we always need extra handling for it, with a select
                let mut node_hash_rlc = leaf_hash_rlc;
                if idx < nodes.len() {
                    node_hash_rlc = nodes[idx].mpt_hash_rlc(ctx_gate, self.gate());
                    // is_last = (idx == pseudo_depth - 1)
                    let is_last = pseudo_depth_minus_one_indicator[idx];
                    node_hash_rlc =
                        rlc_select(ctx_gate, self.gate(), leaf_hash_rlc, node_hash_rlc, is_last);
                }
                let prev_is_last = pseudo_depth_indicator[idx];
                // Get the previous node. there are three types to consider:
                // - extension
                // - branch
                // - terminal branch
                // - terminal branch should be used instead of branch if `prev_is_last == true`
                // In each case, if the current node is extension/leaf AND the value of the current node is small enough,
                // then the previous node contains the RLP of the current node as a 2-item list, and not as a hash (byte string).
                // We therefore need to parse the node reference in two ways to account for this.
                // This condition is equivalent to when `node_hash_rlc` is actually not the keccak of the node, but the RLP of the node itself.
                let ext_ref_rlc = nodes[idx - 1].ext.node_ref.field_trace;
                let ext_ref_rlp_rlc = nodes[idx - 1].ext.node_ref.rlp_trace;
                let nibble = fragment_first_nibbles[idx - 1];
                let [(branch_ref_rlc, branch_ref_rlp_rlc), (terminal_branch_ref_rlc, terminal_branch_ref_rlp_rlc)] =
                    [&nodes[idx - 1].branch.node_refs, &terminal_node.branch.node_refs].map(
                        |node_refs| {
                            // the RLC of the decoded node reference, assuming it's a byte string
                            let ref_rlc = rlc_select_from_idx(
                                ctx_gate,
                                self.gate(),
                                node_refs.iter().map(|node| node.field_trace),
                                nibble,
                            );
                            // the RLC of the RLP encoding of the node reference
                            let ref_rlp_rlc = rlc_select_from_idx(
                                ctx_gate,
                                self.gate(),
                                node_refs.iter().map(|node| node.rlp_trace),
                                nibble,
                            );
                            (ref_rlc, ref_rlp_rlc)
                        },
                    );
                let mut get_maybe_short_ref_rlc =
                    |ref_rlc: RlcVar<F>, ref_rlp_rlc: RlcVar<F>| -> RlcVar<F> {
                        let is_short = self.range().is_less_than_safe(ctx_gate, ref_rlc.len, 32);
                        let is_null = self.range().is_less_than_safe(ctx_gate, ref_rlc.len, 2);
                        let is_not_hash = self.gate().mul_not(ctx_gate, is_null, is_short);
                        rlc_select(ctx_gate, self.gate(), ref_rlp_rlc, ref_rlc, is_not_hash)
                    };
                let mut branch_ref_rlc =
                    get_maybe_short_ref_rlc(branch_ref_rlc, branch_ref_rlp_rlc);
                let ext_ref_rlc =
                    get_maybe_short_ref_rlc(ext_ref_rlc.into(), ext_ref_rlp_rlc.into());
                let terminal_branch_ref_rlc =
                    get_maybe_short_ref_rlc(terminal_branch_ref_rlc, terminal_branch_ref_rlp_rlc);
                branch_ref_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    terminal_branch_ref_rlc,
                    branch_ref_rlc,
                    prev_is_last,
                );
                let branch_ref_rlp_rlc = rlc_select_from_idx(
                    ctx_gate,
                    self.gate(),
                    nodes[idx - 1].branch.node_refs.iter().map(|node| node.rlp_trace),
                    fragment_first_nibbles[idx - 1],
                );
                let mut terminal_branch_ref_rlc = rlc_select_from_idx(
                    ctx_gate,
                    self.gate(),
                    terminal_node.branch.node_refs.iter().map(|node| node.field_trace),
                    fragment_first_nibbles[idx - 1],
                );
                let terminal_branch_ref_rlp_rlc = rlc_select_from_idx(
                    ctx_gate,
                    self.gate(),
                    terminal_node.branch.node_refs.iter().map(|node| node.rlp_trace),
                    fragment_first_nibbles[idx - 1],
                );
                let is_short = self.range().is_less_than_safe(ctx_gate, branch_ref_rlc.len, 32);
                let is_null = self.range().is_less_than_safe(ctx_gate, branch_ref_rlc.len, 2);
                let is_not_null = self.gate().not(ctx_gate, is_null);
                let is_not_hash = self.gate().and(ctx_gate, is_short, is_not_null);
                branch_ref_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    branch_ref_rlp_rlc,
                    branch_ref_rlc,
                    is_not_hash,
                );
                let is_short = self.range().is_less_than_safe(ctx_gate, ext_ref_rlc.len, 32);
                let is_null = self.range().is_less_than_safe(ctx_gate, ext_ref_rlc.len, 2);
                let is_not_null = self.gate().not(ctx_gate, is_null);
                let is_not_hash = self.gate().and(ctx_gate, is_short, is_not_null);
                let ext_ref_rlc =
                    rlc_select(ctx_gate, self.gate(), ext_ref_rlp_rlc, ext_ref_rlc, is_not_hash);
                let is_short =
                    self.range().is_less_than_safe(ctx_gate, terminal_branch_ref_rlc.len, 32);
                let is_null =
                    self.range().is_less_than_safe(ctx_gate, terminal_branch_ref_rlc.len, 2);
                let is_not_null = self.gate().not(ctx_gate, is_null);
                let is_not_hash = self.gate().and(ctx_gate, is_short, is_not_null);
                terminal_branch_ref_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    terminal_branch_ref_rlp_rlc,
                    terminal_branch_ref_rlc,
                    is_not_hash,
                );
                branch_ref_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    terminal_branch_ref_rlc,
                    branch_ref_rlc,
                    prev_is_last,
                );
                // branch_ref_rlc should equal NULL = "" (empty string) if slot_is_empty and idx == depth and nodes[idx - 1] is a branch node; we save these checks for all idx and `select` for `depth` later
                let branch_ref_is_null = self.gate().is_zero(ctx_gate, branch_ref_rlc.len);
                branch_refs_are_null.push(branch_ref_is_null);

                // the node that nodes[idx - 1] actually points to
                let match_hash_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    ext_ref_rlc,
                    branch_ref_rlc,
                    nodes[idx - 1].node_type, // does not need terminal_node.node_type because match_cnt ignores idx >= depth
                );
                if idx == max_depth - 1 {
                    // if slot_is_empty: we set hash(nodes[max_depth - 1]) := 0 to rule out the case depth == max_depth
                    node_hash_rlc.rlc_val =
                        self.gate().mul_not(ctx_gate, slot_is_empty, node_hash_rlc.rlc_val);
                }
                let is_match = rlc_is_equal(ctx_gate, self.gate(), match_hash_rlc, node_hash_rlc);
                matches.push(is_match);
            }
        }
        // padding by 0 to avoid empty vector
        branch_refs_are_null.push(ctx_gate.load_constant(F::from(0)));
        // constrain hash chain
        {
            let match_sums =
                self.gate().partial_sums(ctx_gate, matches.iter().copied()).collect_vec();
            let match_cnt = self.gate().select_by_indicator(
                ctx_gate,
                match_sums.into_iter().map(Existing),
                pseudo_depth_minus_one_indicator.clone(),
            );
            ctx_gate.constrain_equal(&match_cnt, &pseudo_depth_minus_one);
        }
        // if slot_is_empty: check that nodes[depth - 1] points to null if it is branch node
        {
            let mut branch_ref_check = self.gate().select_by_indicator(
                ctx_gate,
                branch_refs_are_null.into_iter().map(Existing),
                pseudo_depth_minus_one_indicator,
            );
            branch_ref_check = self.gate().or(ctx_gate, branch_ref_check, terminal_node.node_type);
            branch_ref_check =
                self.gate().select(ctx_gate, branch_ref_check, Constant(F::ONE), slot_is_empty);
            // nothing to check if proof is empty
            branch_ref_check = self.gate().or(ctx_gate, branch_ref_check, proof_is_empty);
            self.gate().assert_is_const(ctx_gate, &branch_ref_check, &F::ONE);
        }
    }
}

/// # Assumptions
/// * `is_odd` is either 0 or 1
pub fn hex_prefix_encode_first<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    first_nibble: AssignedValue<F>,
    is_odd: AssignedValue<F>,
    is_ext: bool,
) -> AssignedValue<F> {
    let sixteen = F::from(16);
    let thirty_two = F::from(32);
    if is_ext {
        gate.inner_product(
            ctx,
            [Existing(is_odd), Existing(is_odd)],
            [Constant(sixteen), Existing(first_nibble)],
        )
    } else {
        // (1 - is_odd) * 32 + is_odd * (48 + x_0)
        // | 32 | 16 | is_odd | 32 + 16 * is_odd | is_odd | x_0 | out |
        let tmp = gate.mul_add(ctx, Constant(sixteen), is_odd, Constant(thirty_two));
        gate.mul_add(ctx, is_odd, first_nibble, tmp)
    }
}

/// # Assumptions
/// * `is_odd` is either 0 or 1
pub fn hex_prefix_encode<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    key_frag_hexs: &[AssignedValue<F>],
    is_odd: AssignedValue<F>,
    key_byte_len: usize,
    is_ext: bool,
) -> AssignedBytes<F> {
    let mut path_bytes = Vec::with_capacity(key_byte_len);
    let sixteen = F::from(16);
    for byte_idx in 0..=key_byte_len {
        if byte_idx == 0 {
            let byte = hex_prefix_encode_first(ctx, gate, key_frag_hexs[0], is_odd, is_ext);
            path_bytes.push(byte);
        } else {
            let [odd_byte, even_byte] = [0, 1].map(|is_even| {
                gate.mul_add(
                    ctx,
                    Existing(key_frag_hexs[2 * byte_idx - 1 - is_even]),
                    Constant(sixteen),
                    if is_even == 0 && byte_idx >= key_byte_len {
                        Constant(F::ZERO)
                    } else {
                        Existing(key_frag_hexs[2 * byte_idx - is_even])
                    },
                )
            });
            let byte = gate.select(ctx, odd_byte, even_byte, is_odd);
            path_bytes.push(byte);
        }
    }
    path_bytes
}

pub fn hex_prefix_len<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    key_frag_byte_len: AssignedValue<F>,
    is_odd: AssignedValue<F>,
) -> AssignedValue<F> {
    let two = F::from(2);
    let pre_val = two * key_frag_byte_len.value() + is_odd.value();
    // 2 * key_frag_byte_len + is_odd - 2
    let val = pre_val - two;
    let hex_len = ctx.assign_region_last(
        [
            Existing(is_odd),
            Constant(two),
            Existing(key_frag_byte_len),
            Witness(pre_val),
            Constant(-two),
            Constant(F::ONE),
            Witness(val),
        ],
        [0, 3],
    );
    let byte_len_is_zero = gate.is_zero(ctx, key_frag_byte_len);
    // TODO: should we constrain is_odd to be 0 when is_zero = 1?
    gate.select(ctx, Constant(F::ZERO), hex_len, byte_len_is_zero)
}

#[test]
fn test_dummy_branch() {
    assert_eq!(
        ::rlp::encode_list::<Vec<u8>, Vec<u8>>(&vec![vec![]; 17]).as_ref(),
        &DUMMY_BRANCH[..]
    );
}
