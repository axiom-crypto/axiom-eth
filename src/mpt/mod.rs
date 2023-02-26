use crate::{
    keccak::{self, KeccakChip, SharedKeccakChip},
    rlp::{
        max_rlp_len_len,
        rlc::{
            rlc_constrain_equal, rlc_is_equal, rlc_select, rlc_select_from_idx, RlcContextPair,
            RlcTrace, RlcVar,
        },
        RlpChip, RlpFieldTrace,
    },
    rlp::{rlc::RlcChip, RlpArrayTraceWitness},
    Field,
};
use ethers_core::{types::H256, utils::hex::FromHex};
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use lazy_static::lazy_static;
use rlp::Rlp;
use std::{cmp::max, iter::once, sync::MutexGuard};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct LeafTrace<F: Field> {
    key_path: RlpFieldTrace<F>,
    value: RlpFieldTrace<F>,
    leaf_hash_rlc: RlcVar<F>,
}

#[derive(Clone, Debug)]
pub struct LeafTraceWitness<F: Field> {
    pub rlp: RlpArrayTraceWitness<F>,
    pub leaf_hash_query_idx: usize,
    // pub max_leaf_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ExtensionTrace<F: Field> {
    key_path: RlpFieldTrace<F>,
    node_ref: RlpFieldTrace<F>,
    ext_hash_rlc: RlcVar<F>,
}

#[derive(Clone, Debug)]
pub struct ExtensionTraceWitness<F: Field> {
    pub rlp: RlpArrayTraceWitness<F>,
    pub ext_hash_query_idx: usize,
    // pub max_ext_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct BranchTrace<F: Field> {
    node_refs: [RlpFieldTrace<F>; 17],
    branch_hash_rlc: RlcVar<F>,
}

#[derive(Clone, Debug)]
pub struct BranchTraceWitness<F: Field> {
    pub rlp: RlpArrayTraceWitness<F>,
    pub branch_hash_query_idx: usize,
    // pub max_branch_bytes: usize,
}

// helper types for readability
pub type AssignedBytes<F> = Vec<AssignedValue<F>>;
pub type AssignedNibbles<F> = Vec<AssignedValue<F>>;

#[derive(Clone, Debug)]
pub struct MPTNode<F: Field> {
    pub rlp_bytes: AssignedBytes<F>,
    pub node_type: AssignedValue<F>, // index 0 = root; 0 = branch, 1 = extension
}

#[derive(Clone, Debug)]
/// A fragment of the key (bytes), stored as nibbles before hex-prefix encoding
pub struct MPTKeyFragment<F: Field> {
    pub nibbles: AssignedNibbles<F>,
    pub is_odd: AssignedValue<F>,
    // hex_len = 2 * byte_len + is_odd - 2
    // if nibble for branch: byte_len = is_odd = 1
    /// The byte length of the hex-prefix encoded fragment
    pub byte_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct MPTFixedKeyProof<F: Field> {
    // claim specification: (key, value)
    pub key_bytes: AssignedBytes<F>,
    pub value_bytes: AssignedBytes<F>,
    pub value_byte_len: AssignedValue<F>,
    pub root_hash_bytes: AssignedBytes<F>,

    // proof specification
    pub depth: AssignedValue<F>,
    /// RLP encoding of the final leaf node
    pub leaf_bytes: AssignedBytes<F>,
    pub nodes: Vec<MPTNode<F>>,
    pub key_frag: Vec<MPTKeyFragment<F>>,

    pub key_byte_len: usize,
    pub value_max_byte_len: usize,
    /// `max_depth` should be `>=1`
    pub max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct MPTFixedKeyProofWitness<F: Field> {
    // pub proof: MPTFixedKeyProof<F>,
    // we keep only the parts of the proof necessary:
    pub value_bytes: AssignedBytes<F>,
    pub value_byte_len: AssignedValue<F>,
    pub root_hash_bytes: AssignedBytes<F>,
    pub depth: AssignedValue<F>,
    pub nodes: Vec<MPTNode<F>>,
    pub key_frag: Vec<MPTKeyFragment<F>>,
    pub key_byte_len: usize,
    pub max_depth: usize,

    pub leaf_parsed: LeafTraceWitness<F>,
    pub exts_parsed: Vec<ExtensionTraceWitness<F>>,
    pub branches_parsed: Vec<BranchTraceWitness<F>>,
    /// the hex-prefix encoded path for (potential) extension nodes
    pub key_frag_ext_bytes: Vec<Vec<AssignedValue<F>>>,
    /// the hex-prefix encoded path for (potential) leaf nodes
    pub key_frag_leaf_bytes: Vec<Vec<AssignedValue<F>>>,
    pub frag_lens: Vec<AssignedValue<F>>,
    pub key_hexs: AssignedNibbles<F>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MPTVarKeyProof<F: Field> {
    // claim specification
    key_bytes: AssignedBytes<F>,
    key_byte_len: AssignedValue<F>,
    value_bytes: AssignedBytes<F>,
    value_byte_len: AssignedValue<F>,
    root_hash_bytes: AssignedBytes<F>,

    // proof specification
    leaf_bytes: AssignedBytes<F>,
    proof_nodes: Vec<AssignedBytes<F>>,
    node_types: Vec<AssignedValue<F>>, // index 0 = root; 0 = branch, 1 = extension
    depth: AssignedValue<F>,

    key_frag_hexs: Vec<AssignedNibbles<F>>,
    // hex_len = 2 * byte_len + is_odd - 2
    key_frag_is_odd: Vec<AssignedValue<F>>,
    key_frag_byte_len: Vec<AssignedValue<F>>,

    key_max_byte_len: usize,
    value_max_byte_len: usize,
    max_depth: usize,
}

pub fn max_leaf_lens(max_key_bytes: usize, max_value_bytes: usize) -> (Vec<usize>, usize) {
    let max_encoded_path_bytes = max_key_bytes + 1;
    let max_encoded_path_rlp_bytes =
        1 + max_rlp_len_len(max_encoded_path_bytes) + max_encoded_path_bytes;
    let max_value_rlp_bytes = 1 + max_rlp_len_len(max_value_bytes) + max_value_bytes;
    let max_field_bytes = vec![max_encoded_path_rlp_bytes, max_value_rlp_bytes];
    let max_leaf_bytes: usize =
        1 + max_rlp_len_len(max_field_bytes.iter().sum()) + max_field_bytes.iter().sum::<usize>();
    (max_field_bytes, max_leaf_bytes)
}

pub fn max_ext_lens(max_key_bytes: usize) -> (Vec<usize>, usize) {
    let max_node_ref_bytes = 32;
    let max_encoded_path_bytes = max_key_bytes + 1;
    let max_encoded_path_rlp_bytes =
        1 + max_rlp_len_len(max_encoded_path_bytes) + max_encoded_path_bytes;
    let max_node_ref_rlp_bytes = 1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
    let max_field_bytes = vec![max_encoded_path_rlp_bytes, max_node_ref_rlp_bytes];
    let max_ext_bytes: usize =
        1 + max_rlp_len_len(max_field_bytes.iter().sum()) + max_field_bytes.iter().sum::<usize>();
    (max_field_bytes, max_ext_bytes)
}

pub fn max_branch_lens() -> (Vec<usize>, usize) {
    let max_node_ref_bytes = 32;
    let max_node_ref_rlp_bytes = 1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
    let mut max_field_bytes = vec![max_node_ref_rlp_bytes; 16];
    max_field_bytes.push(2);
    let max_branch_bytes: usize =
        1 + max_rlp_len_len(max_field_bytes.iter().sum()) + max_field_bytes.iter().sum::<usize>();
    (max_field_bytes, max_branch_bytes)
}

lazy_static! {
    pub static ref MAX_BRANCH_LENS: (Vec<usize>, usize) = max_branch_lens();
}

/// Thread-safe chip for performing Merkle Patricia Trie (MPT) inclusion proofs.
#[derive(Clone, Debug)]
pub struct MPTChip<'chip, F: Field> {
    pub rlp: RlpChip<'chip, F>,
    /// `KeccakChip` that can be mutably borrowed with smart pointer saved in this chip mostly for convenience.
    /// This should only be used in `FirstPhase`, and the user should _not_ use it in `SecondPhase`.
    keccak: SharedKeccakChip<F>,
    /// The Keccak RLCs will be available at the start of `SecondPhase`. These must be manually loaded.
    keccak_rlcs: Option<(keccak::FixedLenRLCs<F>, keccak::VarLenRLCs<F>)>,
}

impl<'chip, F: Field> MPTChip<'chip, F> {
    pub fn new(rlp: RlpChip<'chip, F>, keccak: SharedKeccakChip<F>) -> Self {
        Self { rlp, keccak, keccak_rlcs: None }
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

    pub fn rlp(&self) -> &RlpChip<F> {
        &self.rlp
    }

    pub fn keccak(&self) -> MutexGuard<KeccakChip<F>> {
        self.keccak.lock().unwrap()
    }

    pub fn keccak_fixed_len_rlcs(&self) -> &keccak::FixedLenRLCs<F> {
        &self.keccak_rlcs.as_ref().expect("Keccak RLCs have not been loaded").0
    }

    pub fn keccak_var_len_rlcs(&self) -> &keccak::VarLenRLCs<F> {
        &self.keccak_rlcs.as_ref().expect("Keccak RLCs have not been loaded").1
    }

    fn ext_max_byte_len(max_key_bytes: usize) -> usize {
        let max_node_ref_bytes = 32;
        let max_encoded_path_bytes = max_key_bytes + 1;
        let max_encoded_path_rlp_bytes =
            1 + max_rlp_len_len(max_encoded_path_bytes) + max_encoded_path_bytes;
        let max_node_ref_rlp_bytes = 1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
        let max_field_bytes = vec![max_encoded_path_rlp_bytes, max_node_ref_rlp_bytes];
        let max_ext_bytes: usize = 1
            + max_rlp_len_len(max_field_bytes.iter().sum())
            + max_field_bytes.iter().sum::<usize>();
        max_ext_bytes
    }

    fn branch_max_byte_len() -> usize {
        let max_node_ref_bytes = 32;
        let max_node_ref_rlp_bytes = 1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
        let mut max_field_bytes = vec![max_node_ref_rlp_bytes; 16];
        max_field_bytes.push(2);
        let max_branch_bytes: usize = 1
            + max_rlp_len_len(max_field_bytes.iter().sum())
            + max_field_bytes.iter().sum::<usize>();
        max_branch_bytes
    }

    /// When one node is referenced inside another node, what is included is H(rlp.encode(x)), where H(x) = keccak256(x) if len(x) >= 32 else x and rlp.encode is the RLP encoding function.
    ///
    /// Assumes that `bytes` is non-empty.
    pub fn mpt_hash_phase0(
        &self,
        ctx: &mut Context<F>, // ctx in FirstPhase
        bytes: AssignedBytes<F>,
        len: AssignedValue<F>,
    ) -> usize {
        assert!(!bytes.is_empty());
        self.keccak().keccak_var_len(ctx, self.range(), bytes, None, len, 0usize)
    }

    /// When one node is referenced inside another node, what is included is H(rlp.encode(x)), where H(x) = keccak256(x) if len(x) >= 32 else x and rlp.encode is the RLP encoding function.
    /// We only return the RLC value of the MPT hash
    pub fn mpt_hash_phase1(
        &self,
        ctx_gate: &mut Context<F>, // ctx in SecondPhase
        hash_query_idx: usize,
    ) -> RlcVar<F> {
        let keccak_query = &self.keccak_var_len_rlcs()[hash_query_idx];
        let hash_rlc = keccak_query.1.rlc_val;
        let input_rlc = keccak_query.0.rlc_val;
        let len = keccak_query.0.len;
        let max_len = std::cmp::max(keccak_query.0.max_len, 32);
        let thirty_two = self.gate().get_field_element(32);
        let is_short = self.range().is_less_than(
            ctx_gate,
            len,
            Constant(thirty_two),
            bit_length(max_len as u64),
        );
        let mpt_hash_len = self.gate().select(ctx_gate, len, Constant(thirty_two), is_short);
        let mpt_hash_rlc = self.gate().select(ctx_gate, input_rlc, hash_rlc, is_short);
        RlcVar { rlc_val: mpt_hash_rlc, len: mpt_hash_len }
    }

    pub fn parse_leaf_phase0(
        &self,
        ctx: &mut Context<F>,
        leaf_bytes: AssignedBytes<F>,
        max_key_bytes: usize,
        max_value_bytes: usize,
    ) -> LeafTraceWitness<F> {
        let (max_field_bytes, max_leaf_bytes) = max_leaf_lens(max_key_bytes, max_value_bytes);
        assert_eq!(leaf_bytes.len(), max_leaf_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, leaf_bytes, &max_field_bytes, false);
        // TODO: remove unnecessary clones somehow?
        let leaf_hash_query_idx =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len);
        LeafTraceWitness { rlp: rlp_witness, leaf_hash_query_idx }
    }

    pub fn parse_leaf_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: LeafTraceWitness<F>,
    ) -> LeafTrace<F> {
        let rlp_trace =
            self.rlp.decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.rlp, false);
        let [key_path, value]: [RlpFieldTrace<F>; 2] = rlp_trace.field_trace.try_into().unwrap();
        let leaf_hash_rlc = self.mpt_hash_phase1(ctx_gate, witness.leaf_hash_query_idx);
        LeafTrace { key_path, value, leaf_hash_rlc }
    }

    pub fn parse_ext_phase0(
        &self,
        ctx: &mut Context<F>,
        ext_bytes: AssignedBytes<F>,
        max_key_bytes: usize,
    ) -> ExtensionTraceWitness<F> {
        let (max_field_bytes, max_ext_bytes) = max_ext_lens(max_key_bytes);
        let max_branch_bytes = MAX_BRANCH_LENS.1;
        let max_ext_bytes = max(max_ext_bytes, max_branch_bytes);
        debug_assert_eq!(ext_bytes.len(), max_ext_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, ext_bytes, &max_field_bytes, false);
        let ext_hash_query_idx =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len);
        ExtensionTraceWitness { rlp: rlp_witness, ext_hash_query_idx }
    }

    pub fn parse_ext_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: ExtensionTraceWitness<F>,
    ) -> ExtensionTrace<F> {
        let rlp_trace =
            self.rlp.decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.rlp, false);
        let [key_path, node_ref]: [RlpFieldTrace<F>; 2] = rlp_trace.field_trace.try_into().unwrap();
        let ext_hash_rlc = self.mpt_hash_phase1(ctx_gate, witness.ext_hash_query_idx);
        ExtensionTrace { key_path, node_ref, ext_hash_rlc }
    }

    pub fn parse_nonterminal_branch_phase0(
        &self,
        ctx: &mut Context<F>,
        branch_bytes: AssignedBytes<F>,
    ) -> BranchTraceWitness<F> {
        let (max_field_bytes, max_branch_bytes) = max_branch_lens();
        let (_, max_ext_bytes) = max_ext_lens(32);
        let max_branch_bytes = max(max_ext_bytes, max_branch_bytes);
        assert_eq!(branch_bytes.len(), max_branch_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, branch_bytes, &max_field_bytes, false);
        let branch_hash_query_idx =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len);
        BranchTraceWitness { rlp: rlp_witness, branch_hash_query_idx }
    }

    pub fn parse_nonterminal_branch_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: BranchTraceWitness<F>,
    ) -> BranchTrace<F> {
        let rlp_trace =
            self.rlp.decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.rlp, false);
        let node_refs: [RlpFieldTrace<F>; 17] = rlp_trace.field_trace.try_into().unwrap();
        let branch_hash_rlc = self.mpt_hash_phase1(ctx_gate, witness.branch_hash_query_idx);
        BranchTrace { node_refs, branch_hash_rlc }
    }

    pub fn compute_rlc_trace(
        &self,
        ctx: RlcContextPair<F>,
        inputs: Vec<AssignedValue<F>>,
        len: AssignedValue<F>,
    ) -> RlcTrace<F> {
        self.rlc().compute_rlc(ctx, self.gate(), inputs, len)
    }

    pub fn parse_mpt_inclusion_fixed_key_phase0(
        &self,
        ctx: &mut Context<F>,
        proof: MPTFixedKeyProof<F>,
        key_byte_len: usize,
        value_max_byte_len: usize,
        max_depth: usize,
    ) -> MPTFixedKeyProofWitness<F> {
        assert_eq!(proof.key_byte_len, key_byte_len);
        assert_eq!(proof.value_max_byte_len, value_max_byte_len);
        assert_eq!(proof.max_depth, max_depth);
        assert_eq!(proof.nodes.len(), max_depth - 1);
        assert_eq!(proof.key_bytes.len(), key_byte_len);
        assert_eq!(proof.value_bytes.len(), value_max_byte_len);
        assert_eq!(proof.root_hash_bytes.len(), 32);

        let ext_max_byte_len = Self::ext_max_byte_len(key_byte_len);
        let branch_max_byte_len = Self::branch_max_byte_len();
        let node_max_byte_len = max(ext_max_byte_len, branch_max_byte_len);

        let mut dummy_ext = DUMMY_EXT.clone();
        dummy_ext.resize(node_max_byte_len, 0u8);
        let mut dummy_branch = DUMMY_BRANCH.clone();
        dummy_branch.resize(node_max_byte_len, 0u8);
        let dummy_ext: Vec<_> =
            dummy_ext.into_iter().map(|b| Constant(F::from(b as u64))).collect();
        let dummy_branch: Vec<_> =
            dummy_branch.into_iter().map(|b| Constant(F::from(b as u64))).collect();

        /* Validate inputs, check that:
         * all inputs are bytes
         * node_types[idx] in {0, 1}
         * key_frag_is_odd[idx] in {0, 1}
         * key_frag_hexes are hexs
         * 0 < depth <= max_depth
         * 0 <= value_byte_len <= value_max_byte_len
         * 0 <= key_frag_byte_len[idx] <= key_byte_len + 1
         */
        for byte in proof
            .key_bytes
            .iter()
            .chain(proof.value_bytes.iter())
            .chain(proof.root_hash_bytes.iter())
            .chain(proof.leaf_bytes.iter())
            .chain(proof.nodes.iter().flat_map(|node| node.rlp_bytes.iter()))
        {
            self.range().range_check(ctx, *byte, 8);
        }
        for bit in proof
            .nodes
            .iter()
            .map(|node| &node.node_type)
            .chain(proof.key_frag.iter().map(|frag| &frag.is_odd))
        {
            self.gate().assert_bit(ctx, *bit);
        }
        for nibble in proof.key_frag.iter().flat_map(|frag| frag.nibbles.iter()) {
            self.range().range_check(ctx, *nibble, 4);
        }
        self.range().check_less_than_safe(ctx, proof.depth, proof.max_depth as u64 + 1);
        self.range().check_less_than_safe(
            ctx,
            proof.value_byte_len,
            proof.value_max_byte_len as u64 + 1,
        );
        for frag_len in proof.key_frag.iter().map(|frag| frag.byte_len) {
            self.range().check_less_than_safe(ctx, frag_len, proof.key_byte_len as u64 + 2);
        }

        /* Parse RLP
         * RLP Leaf      for leaf_bytes
         * RLP Extension for select(dummy_extension[idx], nodes[idx], node_types[idx])
         * RLP Branch    for select(nodes[idx], dummy_branch[idx], node_types[idx])
         */
        let leaf_parsed =
            self.parse_leaf_phase0(ctx, proof.leaf_bytes.clone(), key_byte_len, value_max_byte_len);
        let mut exts_parsed = Vec::with_capacity(max_depth - 1);
        let mut branches_parsed = Vec::with_capacity(max_depth - 1);
        for node in proof.nodes.iter() {
            debug_assert_eq!(node.rlp_bytes.len(), node_max_byte_len);
            let (ext_in, branch_in): (Vec<_>, Vec<_>) = node
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

            let ext_parsed = self.parse_ext_phase0(ctx, ext_in, key_byte_len);
            exts_parsed.push(ext_parsed);

            let branch_parsed = self.parse_nonterminal_branch_phase0(ctx, branch_in);
            branches_parsed.push(branch_parsed);
        }

        // Check key fragment and prefix consistency
        let mut key_frag_ext_bytes = Vec::with_capacity(max_depth - 1);
        let mut key_frag_leaf_bytes = Vec::with_capacity(max_depth);
        let mut frag_lens = Vec::with_capacity(max_depth);
        // assert to avoid capacity checks?
        assert_eq!(proof.key_frag.len(), max_depth);
        for (idx, key_frag) in proof.key_frag.iter().enumerate() {
            debug_assert_eq!(key_frag.nibbles.len(), 2 * key_byte_len);
            let leaf_path_bytes = hex_prefix_encode(
                ctx,
                self.gate(),
                &key_frag.nibbles,
                key_frag.is_odd,
                key_byte_len,
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

        let mut key_hexs = Vec::with_capacity(2 * proof.key_byte_len);
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

        MPTFixedKeyProofWitness {
            value_bytes: proof.value_bytes,
            value_byte_len: proof.value_byte_len,
            root_hash_bytes: proof.root_hash_bytes,
            depth: proof.depth,
            nodes: proof.nodes,
            key_frag: proof.key_frag,
            key_byte_len: proof.key_byte_len,
            max_depth: proof.max_depth,
            leaf_parsed,
            exts_parsed,
            branches_parsed,
            key_frag_ext_bytes,
            key_frag_leaf_bytes,
            key_hexs,
            frag_lens,
        }
    }

    pub fn parse_mpt_inclusion_fixed_key_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: MPTFixedKeyProofWitness<F>,
    ) {
        let max_depth = witness.max_depth;
        let nodes = witness.nodes;
        let leaf_parsed = self.parse_leaf_phase1((ctx_gate, ctx_rlc), witness.leaf_parsed);
        let exts_parsed: Vec<ExtensionTrace<F>> = witness
            .exts_parsed
            .into_iter()
            .map(|x| self.parse_ext_phase1((ctx_gate, ctx_rlc), x))
            .collect();
        let branches_parsed: Vec<BranchTrace<F>> = witness
            .branches_parsed
            .into_iter()
            .map(|x| self.parse_nonterminal_branch_phase1((ctx_gate, ctx_rlc), x))
            .collect();
        let key_frag_ext_byte_rlcs: Vec<_> = witness
            .key_frag_ext_bytes
            .into_iter()
            .zip(witness.key_frag.iter())
            .map(|(bytes, frag)| self.compute_rlc_trace((ctx_gate, ctx_rlc), bytes, frag.byte_len))
            .collect();
        let key_frag_leaf_byte_rlcs: Vec<_> = witness
            .key_frag_leaf_bytes
            .into_iter()
            .zip(witness.key_frag.iter())
            .map(|(bytes, frag)| self.compute_rlc_trace((ctx_gate, ctx_rlc), bytes, frag.byte_len))
            .collect();
        let key_hexs = witness.key_hexs;

        // Match fragments to node key
        for ((ext_parsed, key_frag_ext_byte_rlc), node) in
            exts_parsed.iter().zip(key_frag_ext_byte_rlcs.into_iter()).zip(nodes.iter())
        {
            // When node is extension, check node key RLC equals key frag RLC
            let mut node_key_is_equal = rlc_is_equal(
                ctx_gate,
                self.gate(),
                ext_parsed.key_path.field_trace,
                key_frag_ext_byte_rlc,
            );
            // is equal or node not extension
            let is_not_ext = self.gate().not(ctx_gate, node.node_type);
            node_key_is_equal = self.gate().or(ctx_gate, node_key_is_equal, is_not_ext);
            // assuming node type is not extension if idx > pf.len() [we don't care what happens for these idx]
            self.gate().assert_is_const(ctx_gate, &node_key_is_equal, &F::one());
        }
        let depth_minus_one = self.gate().sub(ctx_gate, witness.depth, Constant(F::one()));
        // Quiz for auditers: is the following necessary?
        // match hex-prefix encoding of leaf path to the parsed leaf encoded path
        let key_frag_leaf_bytes_rlc =
            rlc_select_from_idx(ctx_gate, self.gate(), key_frag_leaf_byte_rlcs, depth_minus_one);
        rlc_constrain_equal(ctx_gate, &key_frag_leaf_bytes_rlc, &leaf_parsed.key_path.field_trace);

        // Check key fragments concatenate to key using hex RLC
        let key_hex_rlc = self.rlp.rlc().compute_rlc_fixed_len(ctx_rlc, key_hexs);
        let (fragment_rlcs, fragment_first_nibble): (Vec<_>, Vec<_>) = witness
            .key_frag
            .into_iter()
            .zip(witness.frag_lens.into_iter())
            .map(|(key_frag, frag_lens)| {
                let first_nibble = key_frag.nibbles[0];
                (
                    self.rlc().compute_rlc(
                        (ctx_gate, ctx_rlc),
                        self.gate(),
                        key_frag.nibbles,
                        frag_lens,
                    ),
                    first_nibble,
                )
            })
            .unzip();
        let assigned_len =
            ctx_gate.load_constant(self.gate().get_field_element(key_hex_rlc.len as u64));

        self.rlp.rlc().constrain_rlc_concat_var(
            (ctx_gate, ctx_rlc),
            self.gate(),
            fragment_rlcs.into_iter().map(|f| (f.rlc_val, f.len, f.max_len)),
            (&key_hex_rlc.rlc_val, &assigned_len),
            witness.depth,
            max_depth,
        );

        /* Check value matches. Currently value_bytes is RLC encoded
         * and value_byte_len is the RLC encoding's length
         */
        let value_rlc_trace = self.rlp.rlc().compute_rlc(
            (ctx_gate, ctx_rlc),
            self.gate(),
            witness.value_bytes,
            witness.value_byte_len,
        );

        rlc_constrain_equal(ctx_gate, &value_rlc_trace, &leaf_parsed.value.field_trace);

        /* Check hash chains
         * hash(node[0]) = root_hash
         * hash(node[idx + 1]) is in node[idx]
         * hash(leaf_bytes) is in node[depth - 2]
         */
        let mut matches = Vec::with_capacity(max_depth - 1);
        // assert so later array indexing doesn't do bound check
        assert_eq!(exts_parsed.len(), max_depth - 1);
        assert_eq!(branches_parsed.len(), max_depth - 1);
        assert_eq!(nodes.len(), max_depth - 1);
        let root_hash_rlc = self.rlc().compute_rlc_fixed_len(ctx_rlc, witness.root_hash_bytes);
        // TODO: use rust iterators instead here
        for idx in 0..max_depth {
            // `node_hash_rlc` can be viewed as a fixed length RLC
            let mut node_hash_rlc = leaf_parsed.leaf_hash_rlc;
            if idx < max_depth - 1 {
                node_hash_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    exts_parsed[idx].ext_hash_rlc,
                    branches_parsed[idx].branch_hash_rlc,
                    nodes[idx].node_type,
                );
                let is_leaf = self.gate().is_equal(
                    ctx_gate,
                    witness.depth,
                    Constant(self.gate().get_field_element((idx + 1) as u64)),
                );
                node_hash_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    leaf_parsed.leaf_hash_rlc,
                    node_hash_rlc,
                    is_leaf,
                );
            }
            if idx == 0 {
                ctx_gate.constrain_equal(&root_hash_rlc.rlc_val, &node_hash_rlc.rlc_val);
                self.gate().assert_is_const(
                    ctx_gate,
                    &node_hash_rlc.len,
                    &self.gate().get_field_element(32),
                );
            } else {
                let ext_ref_rlc = exts_parsed[idx - 1].node_ref.field_trace;
                let branch_ref_rlc = rlc_select_from_idx(
                    ctx_gate,
                    self.gate(),
                    branches_parsed[idx - 1].node_refs.iter().map(|node| node.field_trace),
                    fragment_first_nibble[idx - 1],
                );
                let match_hash_rlc = rlc_select(
                    ctx_gate,
                    self.gate(),
                    ext_ref_rlc,
                    branch_ref_rlc,
                    nodes[idx - 1].node_type,
                );
                // as long as one of the RLCs is fixed len (in this case `node_hash_rlc`), we don't need to check
                // whether lengths are equal
                let is_match = rlc_is_equal(ctx_gate, self.gate(), match_hash_rlc, node_hash_rlc);
                matches.push(is_match);
            }
        }
        let match_sums = self.gate().partial_sums(ctx_gate, matches.iter().copied()).collect_vec();

        let match_cnt = self.gate().select_from_idx(
            ctx_gate,
            once(Constant(F::zero())).chain(match_sums.into_iter().map(Existing)),
            depth_minus_one,
        );
        ctx_gate.constrain_equal(&match_cnt, &depth_minus_one);
    }

    /*
    pub fn parse_mpt_inclusion_var_key(
        &self,
        _ctx: &mut Context<F>,
        _range: &RangeConfig<F>,
        proof: &MPTVarKeyProof<F>,
        key_max_byte_len: usize,
        value_max_byte_len: usize,
        max_depth: usize,
    ) {
        assert_eq!(proof.key_max_byte_len, key_max_byte_len);
        assert_eq!(proof.value_max_byte_len, value_max_byte_len);
        assert_eq!(proof.max_depth, max_depth);

        todo!()
    }
    */
}

pub fn hex_prefix_encode_first<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    first_nibble: AssignedValue<F>,
    is_odd: AssignedValue<F>,
    is_ext: bool,
) -> AssignedValue<F> {
    let sixteen = gate.get_field_element(16);
    let thirty_two = gate.get_field_element(32);
    if is_ext {
        gate.inner_product(
            ctx,
            [Existing(is_odd), Existing(is_odd)],
            [Constant(sixteen), Existing(first_nibble)],
        )
    } else {
        // (1 - is_odd) * 32 + is_odd * (48 + x_0)
        // | 32 | 16 | is_odd | 32 + 16 * is_odd | is_odd | x_0 | out |
        let pre_val = thirty_two + sixteen * is_odd.value();
        let val = pre_val + *first_nibble.value() * is_odd.value();
        ctx.assign_region_last(
            [
                Constant(thirty_two),
                Constant(sixteen),
                Existing(is_odd),
                Witness(pre_val),
                Existing(is_odd),
                Existing(first_nibble),
                Witness(val),
            ],
            [0, 3],
        )
    }
}

pub fn hex_prefix_encode<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    key_frag_hexs: &[AssignedValue<F>],
    is_odd: AssignedValue<F>,
    key_byte_len: usize,
    is_ext: bool,
) -> AssignedBytes<F> {
    let mut path_bytes = Vec::with_capacity(key_byte_len);
    let sixteen = gate.get_field_element(16);
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
                        Constant(F::zero())
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
    let two = gate.get_field_element(2);
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
            Constant(F::one()),
            Witness(val),
        ],
        [0, 3],
    );
    let byte_len_is_zero = gate.is_zero(ctx, key_frag_byte_len);
    // TODO: should we constrain is_odd to be 0 when is_zero = 1?
    gate.select(ctx, Constant(F::zero()), hex_len, byte_len_is_zero)
}

#[derive(Clone, Debug)]
pub struct MPTFixedKeyInput {
    // claim specification: (path, value)
    /// A Merkle-Patricia Trie is a mapping `path => value`
    ///
    /// As an example, the MPT state trie of Ethereum has
    /// `path = keccak256(address) => value = rlp(account)`
    pub path: H256,
    pub value: Vec<u8>,
    pub root_hash: H256,

    pub proof: Vec<Vec<u8>>,

    pub value_max_byte_len: usize,
    pub max_depth: usize,
}

lazy_static! {
    static ref DUMMY_BRANCH: Vec<u8> = Vec::from_hex("f1808080808080808080808080808080a0000000000000000000000000000000000000000000000000000000000000000080").unwrap();
    static ref DUMMY_EXT: Vec<u8> = Vec::from_hex(
            "e21ba00000000000000000000000000000000000000000000000000000000000000000").unwrap();
}

impl MPTFixedKeyInput {
    pub fn assign<F: Field>(&self, ctx: &mut Context<F>) -> MPTFixedKeyProof<F> {
        let Self { path, value, root_hash, proof, value_max_byte_len, max_depth } = self;
        let depth = proof.len();
        assert!(depth <= *max_depth);
        let mut value = value.clone();
        let mut proof = proof.clone();
        let value_max_byte_len = *value_max_byte_len;
        let max_depth = *max_depth;
        let bytes_to_nibbles = |bytes: &[u8]| {
            let mut nibbles = Vec::with_capacity(bytes.len() * 2);
            for byte in bytes {
                nibbles.push(byte >> 4);
                nibbles.push(byte & 0xf);
            }
            nibbles
        };

        let path_nibbles = bytes_to_nibbles(path.as_bytes());
        let mut path_idx = 0;

        // below "key" and "path" are used interchangeably, sorry for confusion
        const KEY_BYTE_LEN: usize = 32;
        let mut leaf = proof.pop().unwrap();
        let (_, max_leaf_bytes) = max_leaf_lens(KEY_BYTE_LEN, value_max_byte_len);

        let (_, max_ext_bytes) = max_ext_lens(KEY_BYTE_LEN);
        let max_branch_bytes = MAX_BRANCH_LENS.1;
        let max_node_bytes = max(max_ext_bytes, max_branch_bytes);

        let mut key_frag = Vec::with_capacity(max_depth);
        let mut nodes = Vec::with_capacity(max_depth - 1);
        let mut process_node = |node: &[u8]| {
            let decode = Rlp::new(node);
            let node_type = decode.item_count().unwrap() == 2;
            if node_type {
                let encoded_path = decode.at(0).unwrap().data().unwrap();
                let byte_len = encoded_path.len();
                let encoded_nibbles = bytes_to_nibbles(encoded_path);
                let is_odd = encoded_nibbles[0] == 1u8 || encoded_nibbles[0] == 3u8;
                let mut frag = encoded_nibbles[2 - usize::from(is_odd)..].to_vec();
                path_idx += frag.len();
                frag.resize(2 * KEY_BYTE_LEN, 0);
                key_frag.push((frag, byte_len, is_odd));
            } else {
                let mut frag = vec![0u8; 2 * KEY_BYTE_LEN];
                frag[0] = path_nibbles[path_idx];
                key_frag.push((frag, 1, true));
                path_idx += 1;
            }
            node_type
        };
        for mut node in proof {
            let node_type = process_node(&node);
            node.resize(max_node_bytes, 0);
            nodes.push((node, node_type));
        }
        let mut dummy_branch = DUMMY_BRANCH.clone();
        dummy_branch.resize(max_node_bytes, 0);
        nodes.resize(max_depth - 1, (dummy_branch, false));

        process_node(&leaf);
        key_frag.resize(max_depth, (vec![0u8; 2 * KEY_BYTE_LEN], 0, false));
        leaf.resize(max_leaf_bytes, 0);

        // assign all values
        let value_byte_len = ctx.load_witness(F::from(value.len() as u64));
        let depth = ctx.load_witness(F::from(depth as u64));
        let mut load_bytes =
            |bytes: &[u8]| ctx.assign_witnesses(bytes.iter().map(|x| F::from(*x as u64)));
        let key_bytes = load_bytes(path.as_bytes());
        value.resize(value_max_byte_len, 0);
        let value_bytes = load_bytes(&value);
        let root_hash_bytes = load_bytes(root_hash.as_bytes());
        let leaf_bytes = load_bytes(&leaf);
        let nodes = nodes
            .into_iter()
            .map(|(node_bytes, node_type)| {
                let rlp_bytes = ctx.assign_witnesses(node_bytes.iter().map(|x| F::from(*x as u64)));
                let node_type = ctx.load_witness(F::from(node_type));
                MPTNode { rlp_bytes, node_type }
            })
            .collect_vec();
        let key_frag = key_frag
            .into_iter()
            .map(|(nibbles, byte_len, is_odd)| {
                let nibbles = ctx.assign_witnesses(nibbles.iter().map(|x| F::from(*x as u64)));
                let byte_len = ctx.load_witness(F::from(byte_len as u64));
                let is_odd = ctx.load_witness(F::from(is_odd));
                MPTKeyFragment { nibbles, is_odd, byte_len }
            })
            .collect_vec();

        MPTFixedKeyProof {
            key_bytes,
            value_bytes,
            value_byte_len,
            root_hash_bytes,
            leaf_bytes,
            nodes,
            depth,
            key_frag,
            key_byte_len: KEY_BYTE_LEN,
            value_max_byte_len,
            max_depth,
        }
    }
}
