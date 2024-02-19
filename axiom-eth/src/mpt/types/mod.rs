use crate::{
    rlc::types::{RlcFixedTrace, RlcTrace},
    rlp::types::{RlpArrayWitness, RlpFieldTrace},
};

use super::*;

mod input;
pub use input::*;

/// Witness for the terminal node of an MPT proof.
/// This can be either a leaf (`ext`) or extracted from a branch (`branch`).
/// The type is determined by `node_type`.
#[derive(Clone, Debug)]
pub struct TerminalWitness<F: ScalarField> {
    pub node_type: AssignedValue<F>,
    pub ext: LeafWitness<F>,
    pub branch: BranchWitness<F>,
    // pub max_leaf_bytes: usize,
}

// TODO: there is no difference structurally between `TerminalTrace` and `MPTNodeTrace` right now. Should combine somehow while still keeping the distinction between the two.
/// The RLC traces corresponding to [`TerminalWitness`]
pub struct TerminalTrace<F: ScalarField> {
    pub node_type: AssignedValue<F>,
    pub ext: LeafTrace<F>,
    pub branch: BranchTrace<F>,
    // pub max_leaf_bytes: usize,
}

impl<F: ScalarField> TerminalTrace<F> {
    /// Returns the RLC of the MPT hash of the node by correcting selecting based on node type
    pub fn mpt_hash_rlc(
        &self,
        ctx_gate: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> RlcVar<F> {
        rlc_select(
            ctx_gate,
            gate,
            self.ext.rlcs.mpt_hash,
            self.branch.rlcs.mpt_hash,
            self.node_type,
        )
    }

    /// Returns the RLC of the keccak of the node by correcting selecting based on node type
    pub fn keccak_rlc(
        &self,
        ctx_gate: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> AssignedValue<F> {
        assert_eq!(self.ext.rlcs.hash.len, self.branch.rlcs.hash.len);
        gate.select(
            ctx_gate,
            self.ext.rlcs.hash.rlc_val,
            self.branch.rlcs.hash.rlc_val,
            self.node_type,
        )
    }
}

#[derive(Clone, Debug)]
pub struct LeafTrace<F: ScalarField> {
    pub key_path: RlpFieldTrace<F>,
    pub value: RlpFieldTrace<F>,
    pub rlcs: MPTHashTrace<F>,
}

#[derive(Clone, Debug)]
pub struct LeafWitness<F: ScalarField> {
    pub rlp: RlpArrayWitness<F>,
    pub hash_query: MPTHashWitness<F>,
}

#[derive(Clone, Debug)]
pub struct ExtensionTrace<F: ScalarField> {
    pub key_path: RlpFieldTrace<F>,
    pub node_ref: RlpFieldTrace<F>,
    pub rlcs: MPTHashTrace<F>,
}

#[derive(Clone, Debug)]
pub struct ExtensionWitness<F: ScalarField> {
    pub rlp: RlpArrayWitness<F>,
    pub hash_query: MPTHashWitness<F>,
}

#[derive(Clone, Debug)]
pub struct BranchTrace<F: ScalarField> {
    // rlc without rlp prefix
    pub node_refs: [RlpFieldTrace<F>; BRANCH_NUM_ITEMS],
    pub rlcs: MPTHashTrace<F>,
}

#[derive(Clone, Debug)]
pub struct BranchWitness<F: ScalarField> {
    pub rlp: RlpArrayWitness<F>,
    pub hash_query: MPTHashWitness<F>,
}

// helper types for readability
pub type AssignedBytes<F> = Vec<AssignedValue<F>>; // TODO: use SafeByte
pub type AssignedNibbles<F> = Vec<AssignedValue<F>>;

#[derive(Clone, Debug)]
pub struct MPTNode<F: ScalarField> {
    pub rlp_bytes: AssignedBytes<F>,
    /// 0 = branch, 1 = extension
    pub node_type: AssignedValue<F>,
}

#[derive(Clone, Debug)]
/// The `node_type` flag selects whether the node is parsed as a branch or extension node.
pub struct MPTNodeWitness<F: ScalarField> {
    /// 0 = branch, 1 = extension
    pub node_type: AssignedValue<F>,
    /// The node parsed as an extension node, or dummy extension node otherwise
    pub ext: ExtensionWitness<F>,
    /// The node parsed as a branch node, or dummy branch node otherwise
    pub branch: BranchWitness<F>,
}

#[derive(Clone, Debug)]
/// The `node_type` flag selects whether the node is parsed as a branch or extension node.
pub struct MPTNodeTrace<F: ScalarField> {
    /// 0 = branch, 1 = extension
    pub node_type: AssignedValue<F>,
    /// The node parsed as an extension node, or dummy extension node otherwise
    pub ext: ExtensionTrace<F>,
    /// The node parsed as a branch node, or dummy branch node otherwise
    pub branch: BranchTrace<F>,
}

impl<F: ScalarField> MPTNodeTrace<F> {
    /// Returns the RLC of the MPT hash of the node by correcting selecting based on node type
    pub fn mpt_hash_rlc(
        &self,
        ctx_gate: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> RlcVar<F> {
        rlc_select(
            ctx_gate,
            gate,
            self.ext.rlcs.mpt_hash,
            self.branch.rlcs.mpt_hash,
            self.node_type,
        )
    }

    /// Returns the RLC of the keccak of the node by correcting selecting based on node type
    pub fn keccak_rlc(
        &self,
        ctx_gate: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> AssignedValue<F> {
        assert_eq!(self.ext.rlcs.hash.len, self.branch.rlcs.hash.len);
        gate.select(
            ctx_gate,
            self.ext.rlcs.hash.rlc_val,
            self.branch.rlcs.hash.rlc_val,
            self.node_type,
        )
    }
}

#[derive(Clone, Debug)]
/// A fragment of the key (bytes), stored as nibbles before hex-prefix encoding
pub struct MPTFragment<F: ScalarField> {
    /// A variable length string of hex-numbers, resized to a fixed max length with 0s
    pub nibbles: AssignedNibbles<F>,
    pub is_odd: AssignedValue<F>,
    // hex_len = 2 * byte_len + is_odd - 2
    // if nibble for branch: byte_len = is_odd = 1
    /// The byte length of the hex-prefix encoded fragment
    pub byte_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct MPTProofWitness<F: ScalarField> {
    // we keep only the parts of the proof necessary:
    pub value_bytes: AssignedBytes<F>,
    pub value_byte_len: AssignedValue<F>,
    pub root_hash_bytes: AssignedBytes<F>,
    /// The variable length of the key
    pub key_byte_len: Option<AssignedValue<F>>,
    /// The variable length of the proof. This includes the leaf node in the case of an inclusion proof. There is no leaf node in the case of a non-inclusion proof.
    pub depth: AssignedValue<F>,
    /// The non-leaf nodes of the mpt proof, resized to `max_depth - 1`. Each node has been parsed with both a hypothetical branch and extension node. The actual type is determined by the `node_type` flag.
    ///
    /// The actual variable length of `nodes` is `depth - 1` if `slot_is_empty == true` (excludes leaf node), otherwise `depth`.
    pub nodes: Vec<MPTNodeWitness<F>>,
    /// The last node parsed
    pub terminal_node: TerminalWitness<F>,

    /// Boolean indicating whether the MPT contains a value at `key`
    pub slot_is_empty: AssignedValue<F>,

    pub max_key_byte_len: usize,
    pub max_depth: usize,

    /// The key fragments (nibbles), without encoding, provided as private inputs
    pub key_frag: Vec<MPTFragment<F>>,
    /// The hex-prefix encoded path for (potential) extension nodes (hex-prefix encoding has leaf vs. extension distinction).
    /// These are derived from the nodes themselves.
    pub key_frag_ext_bytes: Vec<AssignedBytes<F>>,
    /// The hex-prefix encoded path for (potential) leaf nodes (hex-prefix encoding has leaf vs. extension distinction).
    /// These are derived from the nodes themselves.
    pub key_frag_leaf_bytes: Vec<AssignedBytes<F>>,
    pub frag_lens: Vec<AssignedValue<F>>,
    pub key_hexs: AssignedNibbles<F>,
}

pub type MPTHashWitness<F> = KeccakVarLenQuery<F>;

#[derive(Clone, Copy, Debug)]
pub struct MPTHashTrace<F: ScalarField> {
    /// 32-byte keccak hash RLC
    pub hash: RlcFixedTrace<F>,
    /// input if len < 32, hash otherwise.
    pub mpt_hash: RlcTrace<F>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Hash)]
pub struct PathBytes(pub Vec<u8>);

impl<T: AsRef<[u8]>> From<&T> for PathBytes {
    fn from(value: &T) -> Self {
        Self(value.as_ref().to_vec())
    }
}

impl From<Vec<u8>> for PathBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<H256> for PathBytes {
    fn from(value: H256) -> Self {
        Self(value.0.to_vec())
    }
}

impl AsRef<[u8]> for PathBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
