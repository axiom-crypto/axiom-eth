use crate::{
    halo2_proofs::{circuit::Value, plonk::ConstraintSystem},
    keccak::{KeccakChip, KeccakConfig},
    rlp::{
        max_rlp_len_len,
        rlc::{
            rlc_constrain_equal, rlc_is_equal, rlc_select, rlc_select_from_idx, RlcTrace, RlcVarLen,
        },
        RlpChip, RlpConfig, RlpFieldTrace,
    },
    rlp::{rlc::RlcChip, RlpArrayTraceWitness},
    util::EthConfigParams,
    Field,
};
use ::rlp::Rlp;
use ethers_core::{types::H256, utils::hex::FromHex};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use lazy_static::lazy_static;
use std::{cmp::max, env::set_var, iter::once};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct LeafTrace<'v, F: Field> {
    key_path: RlpFieldTrace<'v, F>,
    value: RlpFieldTrace<'v, F>,
    leaf_hash_rlc: RlcVarLen<'v, F>,
}

#[derive(Clone, Debug)]
pub struct LeafTraceWitness<'v, F: Field> {
    pub rlp_witness: RlpArrayTraceWitness<'v, F>,
    pub leaf_hash_query_idx: usize,
    pub max_leaf_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ExtensionTrace<'v, F: Field> {
    key_path: RlpFieldTrace<'v, F>,
    node_ref: RlpFieldTrace<'v, F>,
    ext_hash_rlc: RlcVarLen<'v, F>,
}

#[derive(Clone, Debug)]
pub struct ExtensionTraceWitness<'v, F: Field> {
    pub rlp_witness: RlpArrayTraceWitness<'v, F>,
    pub ext_hash_query_idx: usize,
    pub max_ext_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct BranchTrace<'v, F: Field> {
    node_refs: [RlpFieldTrace<'v, F>; 17],
    branch_hash_rlc: RlcVarLen<'v, F>,
}

#[derive(Clone, Debug)]
pub struct BranchTraceWitness<'v, F: Field> {
    pub rlp_witness: RlpArrayTraceWitness<'v, F>,
    pub branch_hash_query_idx: usize,
    pub max_branch_bytes: usize,
}

// helper types for readability
pub type AssignedBytes<'v, F> = Vec<AssignedValue<'v, F>>;
pub type AssignedNibbles<'v, F> = Vec<AssignedValue<'v, F>>;

#[derive(Clone, Debug)]
pub struct MPTNode<'v, F: Field> {
    pub rlp_bytes: AssignedBytes<'v, F>,
    pub node_type: AssignedValue<'v, F>, // index 0 = root; 0 = branch, 1 = extension
}

#[derive(Clone, Debug)]
/// A fragment of the key (bytes), stored as nibbles before hex-prefix encoding
pub struct MPTKeyFragment<'v, F: Field> {
    pub nibbles: AssignedNibbles<'v, F>,
    pub is_odd: AssignedValue<'v, F>,
    // hex_len = 2 * byte_len + is_odd - 2
    // if nibble for branch: byte_len = is_odd = 1
    /// The byte length of the hex-prefix encoded fragment
    pub byte_len: AssignedValue<'v, F>,
}

#[derive(Clone, Debug)]
pub struct MPTFixedKeyProof<'v, F: Field> {
    // claim specification: (key, value)
    pub key_bytes: AssignedBytes<'v, F>,
    pub value_bytes: AssignedBytes<'v, F>,
    pub value_byte_len: AssignedValue<'v, F>,
    pub root_hash_bytes: AssignedBytes<'v, F>,

    // proof specification
    pub depth: AssignedValue<'v, F>,
    /// RLP encoding of the final leaf node
    pub leaf_bytes: AssignedBytes<'v, F>,
    pub nodes: Vec<MPTNode<'v, F>>,
    pub key_frag: Vec<MPTKeyFragment<'v, F>>,

    pub key_byte_len: usize,
    pub value_max_byte_len: usize,
    pub max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct MPTFixedKeyProofWitness<'v, F: Field> {
    pub proof: MPTFixedKeyProof<'v, F>,
    pub leaf_parsed: LeafTraceWitness<'v, F>,
    pub exts_parsed: Vec<ExtensionTraceWitness<'v, F>>,
    pub branches_parsed: Vec<BranchTraceWitness<'v, F>>,
    /// the hex-prefix encoded path for (potential) extension nodes
    pub key_frag_ext_bytes: Vec<Vec<AssignedValue<'v, F>>>,
    /// the hex-prefix encoded path for (potential) leaf nodes
    pub key_frag_leaf_bytes: Vec<Vec<AssignedValue<'v, F>>>,
    pub frag_lens: Vec<AssignedValue<'v, F>>,
    pub key_hexs: AssignedNibbles<'v, F>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MPTVarKeyProof<'v, F: Field> {
    // claim specification
    key_bytes: AssignedBytes<'v, F>,
    key_byte_len: AssignedValue<'v, F>,
    value_bytes: AssignedBytes<'v, F>,
    value_byte_len: AssignedValue<'v, F>,
    root_hash_bytes: AssignedBytes<'v, F>,

    // proof specification
    leaf_bytes: AssignedBytes<'v, F>,
    proof_nodes: Vec<AssignedBytes<'v, F>>,
    node_types: Vec<AssignedValue<'v, F>>, // index 0 = root; 0 = branch, 1 = extension
    depth: AssignedValue<'v, F>,

    key_frag_hexs: Vec<AssignedNibbles<'v, F>>,
    // hex_len = 2 * byte_len + is_odd - 2
    key_frag_is_odd: Vec<AssignedValue<'v, F>>,
    key_frag_byte_len: Vec<AssignedValue<'v, F>>,

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

#[derive(Clone, Debug)]
pub struct MPTConfig<F: Field> {
    pub rlp: RlpConfig<F>,
    pub keccak: KeccakConfig<F>,
}

impl<F: Field> MPTConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        params: EthConfigParams,
        context_id: usize,
    ) -> Self {
        let degree = params.degree;
        let mut rlp = RlpConfig::configure(
            meta,
            params.num_rlc_columns,
            &params.num_range_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            8, // always want 8 to range check bytes
            context_id,
            degree as usize,
        );
        set_var("KECCAK_DEGREE", degree.to_string());
        set_var("KECCAK_ROWS", params.keccak_rows_per_round.to_string());
        set_var("UNUSABLE_ROWS", params.unusable_rows.to_string());
        let keccak = KeccakConfig::new(meta, rlp.rlc.gamma);
        #[cfg(feature = "display")]
        println!("Unusable rows: {}", meta.minimum_rows());
        rlp.range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { rlp, keccak }
    }
}

#[derive(Clone, Debug)]
pub struct MPTChip<'v, F: Field> {
    pub rlp: RlpChip<'v, F>,
    pub keccak: KeccakChip<'v, F>,
}

impl<'v, F: Field> MPTChip<'v, F> {
    pub fn new(config: MPTConfig<F>, gamma: Value<F>) -> MPTChip<'v, F> {
        Self { rlp: RlpChip::new(config.rlp, gamma), keccak: KeccakChip::new(config.keccak) }
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.rlp.gate()
    }

    pub fn range(&self) -> &RangeConfig<F> {
        &self.rlp.range
    }

    pub fn rlp(&self) -> &RlpChip<'v, F> {
        &self.rlp
    }

    pub fn keccak(&self) -> &KeccakChip<'v, F> {
        &self.keccak
    }

    pub fn rlc(&self) -> &RlcChip<'v, F> {
        self.rlp.rlc()
    }

    pub fn get_challenge(&mut self, ctx: &mut Context<F>) {
        self.rlp.get_challenge(ctx);
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

    // When one node is referenced inside another node, what is included is H(rlp.encode(x)), where H(x) = keccak256(x) if len(x) >= 32 else x and rlp.encode is the RLP encoding function.
    pub fn mpt_hash_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        bytes: AssignedBytes<'v, F>,
        len: AssignedValue<'v, F>,
    ) -> usize {
        debug_assert_ne!(bytes.len(), 0);
        self.keccak.keccak_var_len(ctx, &self.rlp.range, bytes, None, len, 0usize)
    }

    // When one node is referenced inside another node, what is included is H(rlp.encode(x)), where H(x) = keccak256(x) if len(x) >= 32 else x and rlp.encode is the RLP encoding function.
    // We only return the RLC value of the MPT hash
    pub fn mpt_hash_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        hash_query_idx: usize,
        max_len: usize,
    ) -> RlcVarLen<'v, F> {
        let keccak_query = &self.keccak.var_len_rlcs[hash_query_idx];
        let hash_rlc = &keccak_query.1.rlc_val;
        let bytes = keccak_query.0.values[..32].to_vec();
        let len = keccak_query.0.len.clone();
        let thirty_two = self.gate().get_field_element(32);
        let is_short = self.range().is_less_than(
            ctx,
            Existing(&len),
            Constant(thirty_two),
            bit_length(max_len as u64),
        );
        let mpt_hash_len =
            self.gate().select(ctx, Existing(&len), Constant(thirty_two), Existing(&is_short));
        let short_rlc = self.rlc().compute_rlc(ctx, self.gate(), bytes, len).rlc_val;
        let mpt_hash_rlc =
            self.gate().select(ctx, Existing(&short_rlc), Existing(hash_rlc), Existing(&is_short));
        RlcVarLen { rlc_val: mpt_hash_rlc, len: mpt_hash_len }
    }

    pub fn parse_leaf_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        leaf_bytes: AssignedBytes<'v, F>,
        max_key_bytes: usize,
        max_value_bytes: usize,
    ) -> LeafTraceWitness<'v, F> {
        let (max_field_bytes, max_leaf_bytes) = max_leaf_lens(max_key_bytes, max_value_bytes);
        debug_assert_eq!(leaf_bytes.len(), max_leaf_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, leaf_bytes, &max_field_bytes, false);
        // TODO: remove unnecessary clones by using lifetimes better
        let leaf_hash_query_idx =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len.clone());
        LeafTraceWitness { rlp_witness, leaf_hash_query_idx, max_leaf_bytes }
    }

    pub fn parse_leaf_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: LeafTraceWitness<'v, F>,
    ) -> LeafTrace<'v, F> {
        let rlp_trace = self.rlp.decompose_rlp_array_phase1(ctx, witness.rlp_witness, false);
        let [key_path, value]: [RlpFieldTrace<F>; 2] = rlp_trace.field_trace.try_into().unwrap();
        let leaf_hash_rlc =
            self.mpt_hash_phase1(ctx, witness.leaf_hash_query_idx, witness.max_leaf_bytes);
        LeafTrace { key_path, value, leaf_hash_rlc }
    }

    pub fn parse_ext_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        ext_bytes: AssignedBytes<'v, F>,
        max_key_bytes: usize,
    ) -> ExtensionTraceWitness<'v, F> {
        let (max_field_bytes, max_ext_bytes) = max_ext_lens(max_key_bytes);
        let max_branch_bytes = MAX_BRANCH_LENS.1;
        let max_ext_bytes = max(max_ext_bytes, max_branch_bytes);
        debug_assert_eq!(ext_bytes.len(), max_ext_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, ext_bytes, &max_field_bytes, false);
        // TODO: remove unnecessary clones by using lifetimes better
        let ext_hash_query_idx =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len.clone());
        ExtensionTraceWitness { rlp_witness, ext_hash_query_idx, max_ext_bytes }
    }

    pub fn parse_ext_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: ExtensionTraceWitness<'v, F>,
    ) -> ExtensionTrace<'v, F> {
        let rlp_trace = self.rlp.decompose_rlp_array_phase1(ctx, witness.rlp_witness, false);
        let [key_path, node_ref]: [RlpFieldTrace<F>; 2] = rlp_trace.field_trace.try_into().unwrap();
        let ext_hash_rlc =
            self.mpt_hash_phase1(ctx, witness.ext_hash_query_idx, witness.max_ext_bytes);
        ExtensionTrace { key_path, node_ref, ext_hash_rlc }
    }

    pub fn parse_nonterminal_branch_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        branch_bytes: AssignedBytes<'v, F>,
    ) -> BranchTraceWitness<'v, F> {
        let (max_field_bytes, max_branch_bytes) = max_branch_lens();
        let (_, max_ext_bytes) = max_ext_lens(32);
        let max_branch_bytes = max(max_ext_bytes, max_branch_bytes);
        assert_eq!(branch_bytes.len(), max_branch_bytes);

        let rlp_witness =
            self.rlp.decompose_rlp_array_phase0(ctx, branch_bytes, &max_field_bytes, false);
        let branch_hash_query_idx =
            self.mpt_hash_phase0(ctx, rlp_witness.rlp_array.clone(), rlp_witness.rlp_len.clone());
        BranchTraceWitness { rlp_witness, branch_hash_query_idx, max_branch_bytes }
    }

    pub fn parse_nonterminal_branch_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: BranchTraceWitness<'v, F>,
    ) -> BranchTrace<'v, F> {
        let rlp_trace = self.rlp.decompose_rlp_array_phase1(ctx, witness.rlp_witness, false);
        let node_refs: [RlpFieldTrace<F>; 17] = rlp_trace.field_trace.try_into().unwrap();
        let branch_hash_rlc =
            self.mpt_hash_phase1(ctx, witness.branch_hash_query_idx, witness.max_branch_bytes);
        BranchTrace { node_refs, branch_hash_rlc }
    }

    pub fn compute_rlc_trace(
        &self,
        ctx: &mut Context<'v, F>,
        inputs: Vec<AssignedValue<'v, F>>,
        len: AssignedValue<'v, F>,
    ) -> RlcTrace<'v, F> {
        self.rlp.rlc.compute_rlc(ctx, self.rlp.range.gate(), inputs, len)
    }

    pub fn parse_mpt_inclusion_fixed_key_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        proof: MPTFixedKeyProof<'v, F>,
        key_byte_len: usize,
        value_max_byte_len: usize,
        max_depth: usize,
    ) -> MPTFixedKeyProofWitness<'v, F> {
        debug_assert_eq!(proof.key_byte_len, key_byte_len);
        debug_assert_eq!(proof.value_max_byte_len, value_max_byte_len);
        debug_assert_eq!(proof.max_depth, max_depth);
        debug_assert_eq!(proof.nodes.len(), max_depth - 1);
        debug_assert_eq!(proof.key_bytes.len(), key_byte_len);
        debug_assert_eq!(proof.value_bytes.len(), value_max_byte_len);
        debug_assert_eq!(proof.root_hash_bytes.len(), 32);

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
            self.range().range_check(ctx, byte, 8);
        }
        for bit in proof
            .nodes
            .iter()
            .map(|node| &node.node_type)
            .chain(proof.key_frag.iter().map(|frag| &frag.is_odd))
        {
            self.gate().assert_bit(ctx, bit);
        }
        for nibble in proof.key_frag.iter().flat_map(|frag| frag.nibbles.iter()) {
            self.range().range_check(ctx, nibble, 4);
        }
        self.range().check_less_than_safe(ctx, &proof.depth, proof.max_depth as u64 + 1);
        self.range().check_less_than_safe(
            ctx,
            &proof.value_byte_len,
            proof.value_max_byte_len as u64 + 1,
        );
        for frag_len in proof.key_frag.iter().map(|frag| &frag.byte_len) {
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
                .zip(dummy_ext.iter().cloned())
                .zip(dummy_branch.iter().cloned())
                .map(|((node_byte, dummy_ext_byte), dummy_branch_byte)| {
                    (
                        self.gate().select(
                            ctx,
                            Existing(node_byte),
                            dummy_ext_byte,
                            Existing(&node.node_type),
                        ),
                        self.gate().select(
                            ctx,
                            dummy_branch_byte,
                            Existing(node_byte),
                            Existing(&node.node_type),
                        ),
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
                &key_frag.is_odd,
                key_byte_len,
                false,
            );
            if idx < max_depth - 1 {
                // all except first byte are same as `leaf_path_bytes`
                let ext_path_byte_first = hex_prefix_encode_first(
                    ctx,
                    self.gate(),
                    &key_frag.nibbles[0],
                    &key_frag.is_odd,
                    true,
                );
                let ext_path_bytes = [&[ext_path_byte_first], &leaf_path_bytes[1..]].concat();
                key_frag_ext_bytes.push(ext_path_bytes);
            }
            key_frag_leaf_bytes.push(leaf_path_bytes);

            let frag_len = hex_prefix_len(ctx, self.gate(), &key_frag.byte_len, &key_frag.is_odd);
            frag_lens.push(frag_len);
        }

        let mut key_hexs = Vec::with_capacity(2 * proof.key_byte_len);
        for byte in proof.key_bytes.iter() {
            let bits = self.gate().num_to_bits(ctx, byte, 8);
            let [hex1, hex2] = [4, 0].map(|idx| {
                self.gate().inner_product(
                    ctx,
                    bits[idx..idx + 4].iter().map(Existing),
                    (0..4).map(|x| Constant(self.gate().pow_of_two()[x])),
                )
            });
            key_hexs.extend([hex1, hex2]);
        }

        MPTFixedKeyProofWitness {
            proof,
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
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: MPTFixedKeyProofWitness<'v, F>,
    ) {
        debug_assert_eq!(ctx.current_phase(), 1);
        let MPTFixedKeyProof {
            key_bytes: _,
            value_bytes,
            value_byte_len,
            root_hash_bytes,
            leaf_bytes: _,
            nodes,
            depth,
            key_frag,
            key_byte_len,
            value_max_byte_len: _,
            max_depth,
        } = witness.proof;
        let leaf_parsed = self.parse_leaf_phase1(ctx, witness.leaf_parsed);
        let exts_parsed: Vec<ExtensionTrace<'_, F>> =
            witness.exts_parsed.into_iter().map(|x| self.parse_ext_phase1(ctx, x)).collect();
        let branches_parsed: Vec<BranchTrace<'_, F>> = witness
            .branches_parsed
            .into_iter()
            .map(|x| self.parse_nonterminal_branch_phase1(ctx, x))
            .collect();
        let key_frag_ext_byte_rlcs: Vec<_> = witness
            .key_frag_ext_bytes
            .into_iter()
            .zip(key_frag.iter())
            .map(|(bytes, frag)| self.compute_rlc_trace(ctx, bytes, frag.byte_len.clone()))
            .collect();
        let key_frag_leaf_byte_rlcs: Vec<_> = witness
            .key_frag_leaf_bytes
            .into_iter()
            .zip(key_frag.iter())
            .map(|(bytes, frag)| self.compute_rlc_trace(ctx, bytes, frag.byte_len.clone()))
            .collect();
        let key_hexs = witness.key_hexs;

        // Match fragments to node key
        for ((ext_parsed, key_frag_ext_byte_rlc), node) in
            exts_parsed.iter().zip(key_frag_ext_byte_rlcs.iter()).zip(nodes.iter())
        {
            // When node is extension, check node key RLC equals key frag RLC
            let mut node_key_is_equal = rlc_is_equal(
                ctx,
                self.gate(),
                &ext_parsed.key_path.field_trace,
                key_frag_ext_byte_rlc,
            );
            // is equal or node not extension
            let is_not_ext = self.gate().not(ctx, Existing(&node.node_type));
            node_key_is_equal =
                self.gate().or(ctx, Existing(&node_key_is_equal), Existing(&is_not_ext));
            // assuming node type is not extension if idx > pf.len() [we don't care what happens for these idx]
            self.gate().assert_is_const(ctx, &node_key_is_equal, F::one());
        }
        let depth_minus_one = self.gate().sub(ctx, Existing(&depth), Constant(F::one()));
        // Quiz for auditers: is the following necessary?
        // match hex-prefix encoding of leaf path to the parsed leaf encoded path
        let key_frag_leaf_bytes_rlc = rlc_select_from_idx(
            ctx,
            self.gate(),
            key_frag_leaf_byte_rlcs.iter().map(|trace| trace.into()).collect(),
            &depth_minus_one,
        );
        rlc_constrain_equal(ctx, &key_frag_leaf_bytes_rlc, &leaf_parsed.key_path.field_trace);

        // Check key fragments concatenate to key using hex RLC
        let key_hex_rlc = self.rlp.rlc.compute_rlc_fixed_len(ctx, self.gate(), key_hexs);
        let fragment_rlcs = key_frag
            .into_iter()
            .into_iter()
            .zip(witness.frag_lens.into_iter())
            .map(|(key_frag, frag_lens)| {
                self.rlc().compute_rlc(ctx, self.gate(), key_frag.nibbles, frag_lens)
            })
            .collect_vec();
        self.rlp.rlc.load_rlc_cache(
            ctx,
            self.rlp.range.gate(),
            bit_length(2 * key_byte_len as u64),
        );
        let assigned_len =
            self.gate().load_constant(ctx, self.gate().get_field_element(key_hex_rlc.len as u64));

        self.rlp.rlc.constrain_rlc_concat_var(
            ctx,
            self.gate(),
            fragment_rlcs.iter().map(|f| (&f.rlc_val, &f.len, f.max_len)),
            (&key_hex_rlc.rlc_val, &assigned_len),
            &depth,
            max_depth,
            self.rlc().gamma_pow_cached(),
        );

        /* Check value matches. Currently value_bytes is RLC encoded
         * and value_byte_len is the RLC encoding's length
         */
        let value_rlc_trace =
            self.rlp.rlc.compute_rlc(ctx, self.gate(), value_bytes, value_byte_len.clone());

        rlc_constrain_equal(ctx, &value_rlc_trace, &leaf_parsed.value.field_trace);

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
        for idx in 0..max_depth {
            // `node_hash_rlc` can be viewed as a fixed length RLC
            let mut node_hash_rlc = leaf_parsed.leaf_hash_rlc.clone();
            if idx < max_depth - 1 {
                node_hash_rlc = rlc_select(
                    ctx,
                    self.gate(),
                    &exts_parsed[idx].ext_hash_rlc,
                    &branches_parsed[idx].branch_hash_rlc,
                    &nodes[idx].node_type,
                );
                let is_leaf = self.gate().is_equal(
                    ctx,
                    Existing(&depth),
                    Constant(self.gate().get_field_element((idx + 1) as u64)),
                );
                node_hash_rlc = rlc_select(
                    ctx,
                    self.gate(),
                    &leaf_parsed.leaf_hash_rlc,
                    &node_hash_rlc,
                    &is_leaf,
                );
            }
            if idx == 0 {
                let root_hash_rlc =
                    self.rlc().compute_rlc_fixed_len(ctx, self.gate(), root_hash_bytes.clone());
                ctx.constrain_equal(&root_hash_rlc.rlc_val, &node_hash_rlc.rlc_val);
                self.gate().assert_is_const(
                    ctx,
                    &node_hash_rlc.len,
                    self.gate().get_field_element(32),
                );
            } else {
                let ext_ref_rlc = &exts_parsed[idx - 1].node_ref.field_trace;
                let branch_ref_rlc = rlc_select_from_idx(
                    ctx,
                    self.gate(),
                    branches_parsed[idx - 1]
                        .node_refs
                        .iter()
                        .map(|node| (&node.field_trace).into())
                        .collect(),
                    &fragment_rlcs[idx - 1].values[0],
                );
                let match_hash_rlc = rlc_select(
                    ctx,
                    self.gate(),
                    ext_ref_rlc,
                    &branch_ref_rlc,
                    &nodes[idx - 1].node_type,
                );
                // as long as one of the RLCs is fixed len (in this case `node_hash_rlc`), we don't need to check
                // whether lengths are equal
                let is_match = rlc_is_equal(ctx, self.gate(), &match_hash_rlc, &node_hash_rlc);
                matches.push(is_match);
            }
        }
        let match_sums = self.gate().sum_with_assignments(ctx, matches.iter().map(Existing));

        let match_cnt = self.gate().select_from_idx(
            ctx,
            once(Constant(F::zero())).chain(match_sums.iter().step_by(3).map(Existing)),
            Existing(&depth_minus_one),
        );
        ctx.constrain_equal(&match_cnt, &depth_minus_one);
    }

    pub fn parse_mpt_inclusion_var_key(
        &self,
        _ctx: &mut Context<'_, F>,
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
}

pub fn hex_prefix_encode_first<'v, F: ScalarField>(
    ctx: &mut Context<'_, F>,
    gate: &impl GateInstructions<F>,
    first_nibble: &AssignedValue<'v, F>,
    is_odd: &AssignedValue<'v, F>,
    is_ext: bool,
) -> AssignedValue<'v, F> {
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
        let pre_val = Value::known(thirty_two) + Value::known(sixteen) * is_odd.value();
        let val = pre_val + first_nibble.value().copied() * is_odd.value();
        gate.assign_region_last(
            ctx,
            vec![
                Constant(thirty_two),
                Constant(sixteen),
                Existing(is_odd),
                Witness(pre_val),
                Existing(is_odd),
                Existing(first_nibble),
                Witness(val),
            ],
            vec![(0, None), (3, None)],
        )
    }
}

pub fn hex_prefix_encode<'v, F: ScalarField>(
    ctx: &mut Context<'_, F>,
    gate: &impl GateInstructions<F>,
    key_frag_hexs: &AssignedNibbles<'v, F>,
    is_odd: &AssignedValue<'v, F>,
    key_byte_len: usize,
    is_ext: bool,
) -> AssignedBytes<'v, F> {
    let mut path_bytes = Vec::with_capacity(key_byte_len);
    let sixteen = gate.get_field_element(16);
    for byte_idx in 0..=key_byte_len {
        if byte_idx == 0 {
            let byte = hex_prefix_encode_first(ctx, gate, &key_frag_hexs[0], is_odd, is_ext);
            path_bytes.push(byte);
        } else {
            let [odd_byte, even_byte] = [0, 1].map(|is_even| {
                gate.mul_add(
                    ctx,
                    Existing(&key_frag_hexs[2 * byte_idx - 1 - is_even]),
                    Constant(sixteen),
                    if is_even == 0 && byte_idx >= key_byte_len {
                        Constant(F::zero())
                    } else {
                        Existing(&key_frag_hexs[2 * byte_idx - is_even])
                    },
                )
            });
            let byte =
                gate.select(ctx, Existing(&odd_byte), Existing(&even_byte), Existing(is_odd));
            path_bytes.push(byte);
        }
    }
    path_bytes
}

pub fn hex_prefix_len<'v, F: ScalarField>(
    ctx: &mut Context<'v, F>,
    gate: &impl GateInstructions<F>,
    key_frag_byte_len: &AssignedValue<'v, F>,
    is_odd: &AssignedValue<'v, F>,
) -> AssignedValue<'v, F> {
    let two = gate.get_field_element(2);
    let pre_val = Value::known(two) * key_frag_byte_len.value() + is_odd.value();
    // 2 * key_frag_byte_len + is_odd - 2
    let val = pre_val - Value::known(two);
    let hex_len = gate.assign_region_last(
        ctx,
        vec![
            Existing(is_odd),
            Constant(two),
            Existing(key_frag_byte_len),
            Witness(pre_val),
            Constant(-two),
            Constant(F::one()),
            Witness(val),
        ],
        vec![(0, None), (3, None)],
    );
    let byte_len_is_zero = gate.is_zero(ctx, key_frag_byte_len);
    // TODO: should we constrain is_odd to be 0 when is_zero = 1?
    gate.select(ctx, Constant(F::zero()), Existing(&hex_len), Existing(&byte_len_is_zero))
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
    pub fn assign<'v, F: Field>(
        &self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
    ) -> MPTFixedKeyProof<'v, F> {
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
        let value_byte_len = gate.load_witness(ctx, Value::known(F::from(value.len() as u64)));
        let depth = gate.load_witness(ctx, Value::known(F::from(depth as u64)));
        let mut load_bytes = |bytes: &[u8]| {
            gate.assign_witnesses(ctx, bytes.iter().map(|x| Value::known(F::from(*x as u64))))
        };
        let key_bytes = load_bytes(path.as_bytes());
        value.resize(value_max_byte_len, 0);
        let value_bytes = load_bytes(&value);
        let root_hash_bytes = load_bytes(root_hash.as_bytes());
        let leaf_bytes = load_bytes(&leaf);
        let nodes = nodes
            .into_iter()
            .map(|(node_bytes, node_type)| {
                let rlp_bytes = gate.assign_witnesses(
                    ctx,
                    node_bytes.iter().map(|x| Value::known(F::from(*x as u64))),
                );
                let node_type = gate.load_witness(ctx, Value::known(F::from(node_type)));
                MPTNode { rlp_bytes, node_type }
            })
            .collect_vec();
        let key_frag = key_frag
            .into_iter()
            .map(|(nibbles, byte_len, is_odd)| {
                let nibbles = gate.assign_witnesses(
                    ctx,
                    nibbles.iter().map(|x| Value::known(F::from(*x as u64))),
                );
                let byte_len = gate.load_witness(ctx, Value::known(F::from(byte_len as u64)));
                let is_odd = gate.load_witness(ctx, Value::known(F::from(is_odd)));
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
