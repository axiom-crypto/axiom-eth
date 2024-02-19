//! Module that handles the logic of formatting an MPT proof into witnesses
//! used as inputs in the MPT chip. This mostly involves
//! - resizing vectors to fixed length by right padding with 0s,
//! - modifying last node in proof for exclusion proofs
//! - extracting the terminal node from the proof
use super::*;

#[derive(Clone, Debug, Default, Hash, Serialize, Deserialize)]
/// The pre-assigned inputs for the MPT proof
pub struct MPTInput {
    // claim specification: (path, value)
    /// A Merkle-Patricia Trie is a mapping `path => value`
    ///
    /// As an example, the MPT state trie of Ethereum has
    /// `path = keccak256(address) => value = rlp(account)`
    pub path: PathBytes,
    pub value: Vec<u8>,
    pub root_hash: H256,

    /// Inclusion proofs will always end in a terminal node: we extract this terminal node in cases where it was originally embedded inside the last branch node.
    pub proof: Vec<Vec<u8>>,

    pub slot_is_empty: bool,

    pub value_max_byte_len: usize,
    pub max_depth: usize,
    pub max_key_byte_len: usize,
    pub key_byte_len: Option<usize>,
}

/// The assigned input for an MPT proof.
/// The `AssignedBytes` here have **not** been range checked.
/// The range checks are performed in the `parse_mpt_inclusion_phase0` function.
#[derive(Clone, Debug)]
pub struct MPTProof<F: ScalarField> {
    // claim specification: (key, value)
    /// The key bytes, fixed length
    pub key_bytes: AssignedBytes<F>,
    /// The RLP encoded `value` as bytes, variable length, resized to `value_max_byte_len`
    pub value_bytes: AssignedBytes<F>,
    pub value_byte_len: AssignedValue<F>,
    pub root_hash_bytes: AssignedBytes<F>,

    // proof specification
    /// The variable length of the key
    pub key_byte_len: Option<AssignedValue<F>>,
    /// The variable length of the proof, including the leaf node if !slot_is_empty.
    /// We always have the terminal node as a separate node, even if the original proof may embed it into the last branch node.
    pub depth: AssignedValue<F>,
    /// RLP encoding of the final leaf node
    pub leaf: MPTNode<F>,
    /// The non-leaf nodes of the mpt proof, resized to `max_depth - 1` with dummy **branch** nodes.
    /// The actual variable length is `depth - 1` if `slot_is_empty == true` (excludes leaf node), otherwise `depth`.
    pub nodes: Vec<MPTNode<F>>,
    /// The key fragments of the mpt proof, variable length, resized to `max_depth` with dummy fragments.
    /// Each fragment (nibbles aka hexes) is variable length, resized to `2 * key_byte_len` with 0s
    pub key_frag: Vec<MPTFragment<F>>,
    /// Boolean indicating whether the MPT contains a value at `key`
    pub slot_is_empty: AssignedValue<F>,

    /// The maximum byte length of the key
    pub max_key_byte_len: usize,
    /// `max_depth` should be `>=1`
    pub max_depth: usize,
}

impl MPTInput {
    /// Does **not** perform any range checks on witnesses to check if they are actually bytes.
    /// This should be done in the `parse_mpt_inclusion_phase0` function
    pub fn assign<F: ScalarField>(self, ctx: &mut Context<F>) -> MPTProof<F> {
        let Self {
            path,
            mut value,
            root_hash,
            mut proof,
            value_max_byte_len,
            max_depth,
            slot_is_empty,
            max_key_byte_len,
            key_byte_len,
        } = self;
        let depth = proof.len();
        // if empty, we have a dummy node stored as a terminal node so that the circuit still works
        // we ignore any results from the node, however.
        if proof.is_empty() {
            proof.push(NULL_LEAF.clone());
        }
        //assert!(depth <= max_depth - usize::from(slot_is_empty));
        assert!(max_depth > 0);
        assert!(max_key_byte_len > 0);

        let bytes_to_nibbles = |bytes: &[u8]| {
            let mut nibbles = Vec::with_capacity(bytes.len() * 2);
            for byte in bytes {
                nibbles.push(byte >> 4);
                nibbles.push(byte & 0xf);
            }
            nibbles
        };
        let hex_len = |byte_len: usize, is_odd: bool| 2 * byte_len + usize::from(is_odd) - 2;
        let path_nibbles = bytes_to_nibbles(path.as_ref());
        let mut path_idx = 0;

        // below "key" and "path" are used interchangeably, sorry for confusion
        // if slot_is_empty, leaf is dummy, but with value 0x0 to make constraints pass (assuming claimed value is also 0x0)
        let mut leaf = proof.pop().unwrap();
        let (_, max_leaf_bytes) = max_leaf_lens(max_key_byte_len, value_max_byte_len);

        let (_, max_ext_bytes) = max_ext_lens(max_key_byte_len);
        let max_node_bytes = max(max_ext_bytes, MAX_BRANCH_ENCODING_BYTES);

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
                frag.resize(2 * max_key_byte_len, 0);
                key_frag.push((frag, byte_len, is_odd));
            } else {
                let mut frag = vec![0u8; 2 * max_key_byte_len];
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

        let leaf_type = process_node(&leaf);
        let leaf_type = ctx.load_witness(F::from(leaf_type));
        let max_leaf_bytes = max(max_node_bytes, max_leaf_bytes);
        leaf.resize(max_leaf_bytes, 0);
        let mut path_bytes = path.0;

        let key_byte_len = key_byte_len.map(|key_byte_len| {
            #[cfg(not(test))]
            assert_eq!(key_byte_len, path_bytes.len());
            ctx.load_witness(F::from(key_byte_len as u64))
        });
        // if slot_is_empty, we modify key_frag so it still concatenates to `path`
        if slot_is_empty {
            // remove just added leaf frag
            // key_frag.pop().unwrap();
            if key_frag.is_empty() {
                // that means proof was empty
                let mut nibbles = path_nibbles;
                nibbles.resize(2 * max_key_byte_len, 0);
                key_frag = vec![(nibbles, path_bytes.len() + 1, false)];
            } else {
                // the last frag in non-inclusion doesn't match path
                key_frag.pop().unwrap();
                let hex_len = key_frag
                    .iter()
                    .map(|(_, byte_len, is_odd)| hex_len(*byte_len, *is_odd))
                    .sum::<usize>();
                let mut remaining = path_nibbles[hex_len..].to_vec();
                let is_odd = remaining.len() % 2 == 1;
                let byte_len = (remaining.len() + 2 - usize::from(is_odd)) / 2;
                remaining.resize(2 * max_key_byte_len, 0);
                key_frag.push((remaining, byte_len, is_odd));
            }
        }
        key_frag.resize(max_depth, (vec![0u8; 2 * max_key_byte_len], 0, false));

        // assign all values
        let value_byte_len = ctx.load_witness(F::from(value.len() as u64));
        let depth = ctx.load_witness(F::from(depth as u64));
        let load_bytes = |bytes: Vec<u8>, ctx: &mut Context<F>| {
            ctx.assign_witnesses(bytes.iter().map(|x| F::from(*x as u64)))
        };
        path_bytes.resize(max_key_byte_len, 0);
        let key_bytes = load_bytes(path_bytes, ctx);
        value.resize(value_max_byte_len, 0);
        let value_bytes = load_bytes(value.to_vec(), ctx);
        let root_hash_bytes = load_bytes(root_hash.as_bytes().to_vec(), ctx);
        let leaf_bytes = load_bytes(leaf.to_vec(), ctx);
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
                MPTFragment { nibbles, is_odd, byte_len }
            })
            .collect_vec();
        let slot_is_empty = ctx.load_witness(F::from(slot_is_empty));
        MPTProof {
            key_bytes,
            value_bytes,
            value_byte_len,
            root_hash_bytes,
            key_byte_len,
            depth,
            leaf: MPTNode { rlp_bytes: leaf_bytes, node_type: leaf_type },
            nodes,
            key_frag,
            slot_is_empty,
            max_key_byte_len,
            max_depth,
        }
    }
}
