use eth_types::Field;
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::{fe_to_biguint, value_to_option},
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Challenge, Circuit, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed,
        Instance, SecondPhase, Selector,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use hex::FromHex;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use rlp::{decode, decode_list, encode, Rlp};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{cmp::max, io::Write, marker::PhantomData};

use crate::{
    eth::{EthConfigParams, Strategy},
    keccak::{print_bytes, KeccakChip},
    rlp::rlc::{log2, RlcFixedTrace, RlcTrace},
    rlp::rlp::{max_rlp_len_len, RlpArrayChip, RlpArrayTrace},
};
#[derive(Clone, Debug)]
pub struct LeafTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    key_path: RlcTrace<F>,
    value: RlcTrace<F>,
    leaf_hash: RlcTrace<F>,
    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ExtensionTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    key_path: RlcTrace<F>,
    node_ref: RlcTrace<F>,
    ext_hash: RlcTrace<F>,
    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct BranchTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    node_refs: Vec<RlcTrace<F>>,
    branch_hash: RlcTrace<F>,
    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

// helper types for readability
pub type AssignedBytes<F> = Vec<AssignedValue<F>>;
pub type AssignedNibbles<F> = Vec<AssignedValue<F>>;

#[derive(Clone, Debug)]
pub struct MPTFixedKeyProof<F: Field> {
    // claim specification
    pub key_bytes: AssignedBytes<F>,
    pub value_bytes: AssignedBytes<F>,
    pub value_byte_len: AssignedValue<F>,
    pub root_hash_bytes: AssignedBytes<F>,

    // proof specification
    pub leaf_bytes: AssignedBytes<F>,
    pub nodes: Vec<Vec<AssignedValue<F>>>,
    pub node_types: Vec<AssignedValue<F>>, // index 0 = root; 0 = branch, 1 = extension
    pub depth: AssignedValue<F>,

    pub key_frag_hexs: Vec<AssignedNibbles<F>>,
    // hex_len = 2 * byte_len + is_odd - 2
    // if nibble for branch: byte_len = is_odd = 1
    pub key_frag_is_odd: Vec<AssignedValue<F>>,
    pub key_frag_byte_len: Vec<AssignedValue<F>>,

    pub key_byte_len: usize,
    pub value_max_byte_len: usize,
    pub max_depth: usize,
}

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

#[derive(Clone, Debug)]
pub struct MPTChip<F: Field> {
    pub rlp: RlpArrayChip<F>,
    pub keccak: KeccakChip<F>,
}

impl<F: Field> MPTChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        challenge_id: String,
        context_id: String,
        params: EthConfigParams,
    ) -> Self {
        let rlp = RlpArrayChip::configure(
            meta,
            params.num_basic_chips, // 2 advice per basic chip
            0,                      // use the fixed columns of rlp.range
            challenge_id.clone(),
            context_id,
            match params.range_strategy {
                Strategy::Simple => RangeStrategy::Vertical,
                _ => RangeStrategy::PlonkPlus,
            },
            &params.num_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
        );
        // println!("params adv {:?} fix {:?}", params.num_advice, params.num_fixed);
        let keccak = KeccakChip::configure(
            meta,
            "keccak".to_string(),
            1088,
            256,
            params.keccak_num_advice,
            params.keccak_num_xor,
            params.keccak_num_xorandn,
            0, // keccak should just use the fixed columns of rlp.range
        );
        Self { rlp, keccak }
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

    pub fn mpt_hash(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        bytes: &AssignedBytes<F>,
        len: &AssignedValue<F>,
        max_len: usize,
    ) -> Result<RlcTrace<F>, Error> {
        assert_ne!(bytes.len(), 0);
        let (hash_bytes, _) =
            self.keccak.keccak_bytes_var_len(ctx, range, bytes, len.clone(), 0usize, max_len)?;
        let is_short =
            range.is_less_than(ctx, &Existing(&len), &Constant(F::from(32)), log2(max_len))?;
        let mut mpt_hash_bytes = Vec::with_capacity(32);
        for idx in 0..32 {
            if idx < max_len {
                // trailing entries of bytes are constrained to be 0
                let byte = range.gate.select(
                    ctx,
                    &Existing(&bytes[idx]),
                    &Existing(&hash_bytes[idx]),
                    &Existing(&is_short),
                )?;
                mpt_hash_bytes.push(byte);
            } else {
                let byte = range.gate.select(
                    ctx,
                    &Constant(F::zero()),
                    &Existing(&hash_bytes[idx]),
                    &Existing(&is_short),
                )?;
                mpt_hash_bytes.push(byte);
            }
        }
        let mpt_hash_len = range.gate.select(
            ctx,
            &Existing(&len),
            &Constant(F::from(32)),
            &Existing(&is_short),
        )?;
        let hash = self.rlp.rlc.compute_rlc(ctx, range, &mpt_hash_bytes, mpt_hash_len, 32)?;
        Ok(hash)
    }

    pub fn parse_leaf(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        leaf_bytes: &AssignedBytes<F>,
        max_key_bytes: usize,
        max_value_bytes: usize,
    ) -> Result<LeafTrace<F>, Error> {
        let (max_field_bytes, max_leaf_bytes) = max_leaf_lens(max_key_bytes, max_value_bytes);
        assert_eq!(leaf_bytes.len(), max_leaf_bytes);

        let rlp_trace = self.rlp.decompose_rlp_array(
            ctx,
            range,
            leaf_bytes,
            max_field_bytes,
            max_leaf_bytes,
            2,
        )?;
        let leaf_hash =
            self.mpt_hash(ctx, range, &leaf_bytes, &rlp_trace.array_trace.rlc_len, max_leaf_bytes)?;

        let leaf_trace = LeafTrace {
            rlp_trace: rlp_trace.array_trace,
            key_path: rlp_trace.field_traces[0].clone(),
            value: rlp_trace.field_traces[1].clone(),
            leaf_hash,
            prefix: rlp_trace.prefix,
            len_trace: rlp_trace.len_trace,
            field_prefixs: rlp_trace.field_prefixs,
            field_len_traces: rlp_trace.field_len_traces,
        };
        Ok(leaf_trace)
    }

    pub fn parse_ext(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        ext_bytes: &AssignedBytes<F>,
        max_key_bytes: usize,
    ) -> Result<ExtensionTrace<F>, Error> {
        let (max_field_bytes, max_ext_bytes) = max_ext_lens(max_key_bytes);
        let (_, max_branch_bytes) = max_branch_lens();
        let max_ext_bytes = max(max_ext_bytes, max_branch_bytes);
        assert_eq!(ext_bytes.len(), max_ext_bytes);

        let rlp_trace = self.rlp.decompose_rlp_array(
            ctx,
            range,
            ext_bytes,
            max_field_bytes,
            max_ext_bytes,
            2,
        )?;

        let ext_hash =
            self.mpt_hash(ctx, range, &ext_bytes, &rlp_trace.array_trace.rlc_len, max_ext_bytes)?;

        let ext_trace = ExtensionTrace {
            rlp_trace: rlp_trace.array_trace,
            key_path: rlp_trace.field_traces[0].clone(),
            node_ref: rlp_trace.field_traces[1].clone(),
            ext_hash,
            prefix: rlp_trace.prefix,
            len_trace: rlp_trace.len_trace,
            field_prefixs: rlp_trace.field_prefixs,
            field_len_traces: rlp_trace.field_len_traces,
        };
        Ok(ext_trace)
    }

    pub fn parse_nonterminal_branch(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        branch_bytes: &AssignedBytes<F>,
    ) -> Result<BranchTrace<F>, Error> {
        let (max_field_bytes, max_branch_bytes) = max_branch_lens();
        let (_, max_ext_bytes) = max_ext_lens(32);
        let max_branch_bytes = max(max_ext_bytes, max_branch_bytes);
        assert_eq!(branch_bytes.len(), max_branch_bytes);

        let rlp_trace = self.rlp.decompose_rlp_array(
            ctx,
            range,
            branch_bytes,
            max_field_bytes,
            max_branch_bytes,
            17,
        )?;

        let branch_hash = self.mpt_hash(
            ctx,
            range,
            &branch_bytes,
            &rlp_trace.array_trace.rlc_len,
            max_branch_bytes,
        )?;

        let branch_trace = BranchTrace {
            rlp_trace: rlp_trace.array_trace,
            node_refs: rlp_trace.field_traces,
            branch_hash,
            prefix: rlp_trace.prefix,
            len_trace: rlp_trace.len_trace,
            field_prefixs: rlp_trace.field_prefixs,
            field_len_traces: rlp_trace.field_len_traces,
        };
        Ok(branch_trace)
    }

    pub fn hex_prefix_len(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        key_frag_byte_len: &AssignedValue<F>,
        is_odd: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let assigned = range.gate.assign_region_smart(
            ctx,
            vec![
                Existing(&is_odd),
                Constant(F::from(2)),
                Existing(&key_frag_byte_len),
                Witness(
                    is_odd.value().copied() + Value::known(F::from(2)) * key_frag_byte_len.value(),
                ),
                Constant(-F::from(2)),
                Constant(F::one()),
                Witness(
                    is_odd.value().copied() - Value::known(F::from(2))
                        + Value::known(F::from(2)) * key_frag_byte_len.value(),
                ),
            ],
            vec![0, 3],
            vec![],
            vec![],
        )?;
        let byte_len_is_zero = range.is_zero(ctx, key_frag_byte_len)?;
        // TODO: should we constrain is_odd to be 0 when is_zero = 1?
        range.gate.select(
            ctx,
            &Constant(F::zero()),
            &Existing(&assigned[6]),
            &Existing(&byte_len_is_zero),
        )
    }

    pub fn key_hex_to_path_rlc(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        key_frag_hexs: &AssignedNibbles<F>,
        key_frag_byte_len: &AssignedValue<F>,
        is_odd: &AssignedValue<F>,
        key_byte_len: usize,
        is_ext: bool,
    ) -> Result<AssignedValue<F>, Error> {
        let mut path_bytes = Vec::with_capacity(key_byte_len);
        for byte_idx in 0..key_byte_len + 1 {
            if byte_idx == 0 {
                if is_ext {
                    let (_, _, byte) = range.gate.inner_product(
                        ctx,
                        &vec![Existing(&is_odd), Existing(&is_odd)],
                        &vec![Constant(F::from(16)), Existing(&key_frag_hexs[0])],
                    )?;
                    path_bytes.push(byte);
                } else {
                    // (1 - is_odd) * 32 + is_odd * (48 + x_0)
                    // | 32 | 16 | is_odd | 32 + 16 * is_odd | is_odd | x_0 | out |
                    let assigned = range.gate.assign_region_smart(
                        ctx,
                        vec![
                            Constant(F::from(32)),
                            Constant(F::from(16)),
                            Existing(&is_odd),
                            Witness(
                                Value::known(F::from(32))
                                    + Value::known(F::from(16)) * is_odd.value(),
                            ),
                            Existing(&is_odd),
                            Existing(&key_frag_hexs[0]),
                            Witness(
                                Value::known(F::from(32))
                                    + Value::known(F::from(16)) * is_odd.value()
                                    + is_odd.value().copied() * key_frag_hexs[0].value(),
                            ),
                        ],
                        vec![0, 3],
                        vec![],
                        vec![],
                    )?;
                    // println!("ASSIGN {:?}", assigned);
                    let byte = assigned[6].clone();
                    path_bytes.push(byte);
                }
            } else if byte_idx < key_byte_len {
                let odd_byte = range.gate.assign_region_smart(
                    ctx,
                    vec![
                        Existing(&key_frag_hexs[2 * byte_idx]),
                        Existing(&key_frag_hexs[2 * byte_idx - 1]),
                        Constant(F::from(16)),
                        Witness(
                            key_frag_hexs[2 * byte_idx].value().copied()
                                + Value::known(F::from(16))
                                    * key_frag_hexs[2 * byte_idx - 1].value(),
                        ),
                    ],
                    vec![0],
                    vec![],
                    vec![],
                )?;
                let even_byte = range.gate.assign_region_smart(
                    ctx,
                    vec![
                        Existing(&key_frag_hexs[2 * byte_idx - 1]),
                        Existing(&key_frag_hexs[2 * byte_idx - 2]),
                        Constant(F::from(16)),
                        Witness(
                            key_frag_hexs[2 * byte_idx - 1].value().copied()
                                + Value::known(F::from(16))
                                    * key_frag_hexs[2 * byte_idx - 2].value(),
                        ),
                    ],
                    vec![0],
                    vec![],
                    vec![],
                )?;
                let byte = range.gate.select(
                    ctx,
                    &Existing(&odd_byte[3]),
                    &Existing(&even_byte[3]),
                    &Existing(&is_odd),
                )?;
                path_bytes.push(byte);
            } else {
                let odd_byte = range.gate.assign_region_smart(
                    ctx,
                    vec![
                        Constant(F::zero()),
                        Existing(&key_frag_hexs[2 * byte_idx - 1]),
                        Constant(F::from(16)),
                        Witness(
                            Value::known(F::from(16)) * key_frag_hexs[2 * byte_idx - 1].value(),
                        ),
                    ],
                    vec![0],
                    vec![],
                    vec![],
                )?;
                let even_byte = range.gate.assign_region_smart(
                    ctx,
                    vec![
                        Existing(&key_frag_hexs[2 * byte_idx - 1]),
                        Existing(&key_frag_hexs[2 * byte_idx - 2]),
                        Constant(F::from(16)),
                        Witness(
                            key_frag_hexs[2 * byte_idx - 1].value().copied()
                                + Value::known(F::from(16))
                                    * key_frag_hexs[2 * byte_idx - 2].value(),
                        ),
                    ],
                    vec![0],
                    vec![],
                    vec![],
                )?;
                let byte = range.gate.select(
                    ctx,
                    &Existing(&odd_byte[3]),
                    &Existing(&even_byte[3]),
                    &Existing(&is_odd),
                )?;
                path_bytes.push(byte);
            }
            /*if byte_idx == 1 {
                dbg!(&path_bytes, &key_frag_hexs);
            }*/
        }
        let path_byte_len = 1 + max_rlp_len_len(key_byte_len) + key_byte_len;
        // print_bytes("[path_bytes]".to_string(), &path_bytes);
        let path_rlc = self.rlp.rlc.compute_rlc(
            ctx,
            range,
            &path_bytes,
            key_frag_byte_len.clone(),
            path_byte_len,
        )?;
        Ok(path_rlc.rlc_val)
    }

    pub fn parse_mpt_inclusion_fixed_key(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        proof: &MPTFixedKeyProof<F>,
        key_byte_len: usize,
        value_max_byte_len: usize,
        max_depth: usize,
    ) -> Result<(), Error> {
        assert_eq!(proof.key_byte_len, key_byte_len);
        assert_eq!(proof.value_max_byte_len, value_max_byte_len);
        assert_eq!(proof.max_depth, max_depth);
        assert_eq!(proof.node_types.len(), max_depth - 1);
        assert_eq!(proof.key_bytes.len(), key_byte_len);
        assert_eq!(proof.value_bytes.len(), value_max_byte_len);
        assert_eq!(proof.root_hash_bytes.len(), 32);
        assert_eq!(proof.key_frag_hexs.len(), max_depth);

        let ext_max_byte_len = Self::ext_max_byte_len(key_byte_len);
        let branch_max_byte_len = Self::branch_max_byte_len();
        let node_max_byte_len = max(ext_max_byte_len, branch_max_byte_len);

        let dummy_ext_str =
            "e21ba00000000000000000000000000000000000000000000000000000000000000000";
        let mut dummy_ext_bytes = Vec::from_hex(dummy_ext_str).unwrap();
        dummy_ext_bytes.append(&mut vec![0u8; node_max_byte_len - dummy_ext_bytes.len()]);
        let dummy_branch_str = "f1808080808080808080808080808080a0000000000000000000000000000000000000000000000000000000000000000080";
        let mut dummy_branch_bytes = Vec::from_hex(dummy_branch_str).unwrap();
        dummy_branch_bytes.append(&mut vec![0u8; node_max_byte_len - dummy_branch_bytes.len()]);
        let dummy_ext: Vec<QuantumCell<F>> =
            dummy_ext_bytes.into_iter().map(|b| Constant(F::from(b as u64))).collect();
        let dummy_branch: Vec<QuantumCell<F>> =
            dummy_branch_bytes.into_iter().map(|b| Constant(F::from(b as u64))).collect();

        /* Validate inputs, check that:
         * all inputs are bytes
         * node_types[idx] in {0, 1}
         * key_frag_is_odd[idx] in {0, 1}
         * key_frag_hexes are hexs
         * 0 < depth <= max_depth
         * 0 <= value_byte_len <= value_max_byte_len
         * 0 <= key_frag_byte_len[idx] <= key_byte_len + 1
         */
        for byte in proof.key_bytes.iter() {
            self.keccak.byte_to_hex(ctx, range, &byte)?;
        }
        for byte in proof.value_bytes.iter() {
            self.keccak.byte_to_hex(ctx, range, &byte)?;
        }
        for byte in proof.root_hash_bytes.iter() {
            self.keccak.byte_to_hex(ctx, range, &byte)?;
        }
        for byte in proof.leaf_bytes.iter() {
            self.keccak.byte_to_hex(ctx, range, &byte)?;
        }
        for node in proof.nodes.iter() {
            for byte in node.iter() {
                self.keccak.byte_to_hex(ctx, range, &byte)?;
            }
        }
        for bit in proof.node_types.iter() {
            range.gate.assign_region_smart(
                ctx,
                vec![Constant(F::zero()), Existing(&bit), Existing(&bit), Existing(&bit)],
                vec![0],
                vec![],
                vec![],
            )?;
        }
        // todo: use keccak is_bit gate instead
        for bit in proof.key_frag_is_odd.iter() {
            range.gate.assign_region_smart(
                ctx,
                vec![Constant(F::zero()), Existing(&bit), Existing(&bit), Existing(&bit)],
                vec![0],
                vec![],
                vec![],
            )?;
        }
        for frag in proof.key_frag_hexs.iter() {
            for hex in frag.iter() {
                // use xor to lookup hex and save on lookup args
                self.keccak.xor(ctx, &[hex, hex])?;
            }
        }
        range.check_less_than_safe(
            ctx,
            &proof.depth,
            proof.max_depth + 1,
            log2(proof.max_depth + 1),
        )?;
        range.check_less_than_safe(
            ctx,
            &proof.value_byte_len,
            proof.value_max_byte_len + 1,
            log2(proof.value_max_byte_len + 1),
        )?;
        for frag_len in proof.key_frag_byte_len.iter() {
            range.check_less_than_safe(
                ctx,
                &frag_len,
                proof.key_byte_len + 2,
                log2(proof.key_byte_len + 2),
            )?;
        }

        /* Parse RLP
         * RLP Leaf      for leaf_bytes
         * RLP Extension for select(dummy_extension[idx], nodes[idx], node_types[idx])
         * RLP Branch    for select(nodes[idx], dummy_branch[idx], node_types[idx])
         */
        // println!("parsing leaf");
        let leaf_parsed =
            self.parse_leaf(ctx, range, &proof.leaf_bytes, key_byte_len, value_max_byte_len)?;
        let mut exts_parsed = Vec::with_capacity(max_depth - 1);
        let mut branches_parsed = Vec::with_capacity(max_depth - 1);
        for idx in 0..max_depth - 1 {
            let mut ext_in = Vec::with_capacity(ext_max_byte_len);
            for byte_idx in 0..node_max_byte_len {
                let ext_byte = range.gate.select(
                    ctx,
                    &Existing(&proof.nodes[idx][byte_idx]),
                    &dummy_ext[byte_idx],
                    &Existing(&proof.node_types[idx]),
                )?;
                ext_in.push(ext_byte);
            }
            // println!("parsing ext");
            let ext_parsed = self.parse_ext(ctx, range, &ext_in, key_byte_len)?;
            exts_parsed.push(ext_parsed);

            let mut branch_in = Vec::with_capacity(branch_max_byte_len);
            for byte_idx in 0..node_max_byte_len {
                let branch_byte = range.gate.select(
                    ctx,
                    &dummy_branch[byte_idx],
                    &Existing(&proof.nodes[idx][byte_idx]),
                    &Existing(&proof.node_types[idx]),
                )?;
                branch_in.push(branch_byte);
            }
            //println!("parsing branch");
            let branch_parsed = self.parse_nonterminal_branch(ctx, range, &branch_in)?;
            branches_parsed.push(branch_parsed);
        }

        /* Check key fragment and prefix consistency
         */
        let mut key_frag_ext_byte_rlcs = Vec::with_capacity(max_depth - 1);
        let mut key_frag_leaf_byte_rlcs = Vec::with_capacity(max_depth);
        for idx in 0..max_depth {
            //println!("frag_check idx {:?} len {:?}", idx, proof.key_frag_byte_len[idx].value());
            //print_bytes("frag hexes".to_string(), &proof.key_frag_hexs[idx]);
            assert_eq!(proof.key_frag_hexs[idx].len(), 2 * key_byte_len);
            if idx < max_depth - 1 {
                let ext_path_rlc = self.key_hex_to_path_rlc(
                    ctx,
                    range,
                    &proof.key_frag_hexs[idx],
                    &proof.key_frag_byte_len[idx],
                    &proof.key_frag_is_odd[idx],
                    key_byte_len,
                    true,
                )?;
                key_frag_ext_byte_rlcs.push(ext_path_rlc);
            }
            let leaf_path_rlc = self.key_hex_to_path_rlc(
                ctx,
                range,
                &proof.key_frag_hexs[idx],
                &proof.key_frag_byte_len[idx],
                &proof.key_frag_is_odd[idx],
                key_byte_len,
                false,
            )?;
            key_frag_leaf_byte_rlcs.push(leaf_path_rlc);
        }
        /* Match fragments to node key
         */
        for idx in 0..max_depth - 1 {
            // When node is extension, check node key RLC equals key frag RLC
            let mut node_key_is_equal = self.rlp.rlc.is_equal(
                ctx,
                &Existing(&exts_parsed[idx].key_path.rlc_val),
                &Existing(&key_frag_ext_byte_rlcs[idx]),
            )?;
            // is equal or node not extension
            let is_not_ext = range.gate.not(ctx, &Existing(&proof.node_types[idx]))?;
            node_key_is_equal =
                self.rlp.rlc.or(ctx, &Existing(&node_key_is_equal), &Existing(&is_not_ext))?;
            // assuming node type is not extension if idx > pf.len() [we don't care what happens for these idx]
            ctx.constants_to_assign.push((F::one(), Some(node_key_is_equal.cell())));
        }

        /* Check key fragments concatenate to key using hex RLC
         */
        let mut key_hexs = Vec::with_capacity(2 * key_byte_len);
        for byte in proof.key_bytes.iter() {
            let (hex1, hex2) = self.keccak.byte_to_hex(ctx, range, &byte)?;
            key_hexs.push(hex1);
            key_hexs.push(hex2);
        }
        let key_hex_rlc =
            self.rlp.rlc.compute_rlc_fixed_len(ctx, range, &key_hexs, 2 * key_byte_len)?;
        let mut fragment_rlcs = Vec::new();
        for idx in 0..max_depth {
            let frag_len = self.hex_prefix_len(
                ctx,
                range,
                &proof.key_frag_byte_len[idx],
                &proof.key_frag_is_odd[idx],
            )?;
            // let len = value_to_option(frag_len.value()).unwrap().get_lower_32();
            let fragment_rlc = self.rlp.rlc.compute_rlc(
                ctx,
                range,
                &proof.key_frag_hexs[idx],
                frag_len,
                2 * key_byte_len,
            )?;
            fragment_rlcs.push(fragment_rlc);
        }
        let rlc_cache = self.rlp.rlc.load_rlc_cache(ctx, log2(2 * key_byte_len))?;
        let assigned_len = range.gate.assign_region_smart(
            ctx,
            vec![Constant(F::from(key_hex_rlc.len as u64))],
            vec![],
            vec![],
            vec![],
        )?;

        self.rlp.rlc.constrain_rlc_concat_var(
            ctx,
            range,
            &fragment_rlcs.iter().map(|f| (f.rlc_val.clone(), f.rlc_len.clone())).collect(),
            &vec![2 * key_byte_len; max_depth],
            (key_hex_rlc.rlc_val.clone(), assigned_len[0].clone()),
            2 * key_byte_len,
            proof.depth.clone(),
            max_depth,
            &rlc_cache,
        )?;

        /* Check value matches. Currently proof.value_bytes is RLC encoded
         * and proof.value_byte_len is the RLC encoding's length
         */
        let value_rlc_trace = self.rlp.rlc.compute_rlc(
            ctx,
            range,
            &proof.value_bytes,
            proof.value_byte_len.clone(),
            value_max_byte_len,
        )?;

        ctx.region
            .constrain_equal(value_rlc_trace.rlc_val.cell(), leaf_parsed.value.rlc_val.cell())?;

        /* Check hash chains
         * hash(node[0]) = root_hash
         * hash(node[idx + 1]) is in node[idx]
         * hash(leaf_bytes) is in node[depth - 2]
         */
        let mut matches = Vec::with_capacity(max_depth - 1);
        for idx in 0..max_depth {
            let mut node_hash_rlc = leaf_parsed.leaf_hash.rlc_val.clone();
            if idx < max_depth - 1 {
                let node_inter_hash_rlc = self.rlp.rlc.select(
                    ctx,
                    &Existing(&exts_parsed[idx].ext_hash.rlc_val),
                    &Existing(&branches_parsed[idx].branch_hash.rlc_val),
                    &Existing(&proof.node_types[idx]),
                )?;
                let is_leaf = range.is_equal(
                    ctx,
                    &Existing(&proof.depth),
                    &Constant(F::from((idx + 1) as u64)),
                )?;
                node_hash_rlc = self.rlp.rlc.select(
                    ctx,
                    &Existing(&leaf_parsed.leaf_hash.rlc_val),
                    &Existing(&node_inter_hash_rlc),
                    &Existing(&is_leaf),
                )?;
                /*println!(
                    "exts_rlc {:?} branches_rlc {:?}",
                    exts_parsed[idx].ext_hash.rlc_val.value(),
                    branches_parsed[idx].branch_hash.rlc_val.value()
                );
                println!(
                    "is_leaf {:?} leaf_rlc {:?} node_rlc {:?}",
                    is_leaf.value(),
                    leaf_parsed.leaf_hash.rlc_val.value(),
                    node_inter_hash_rlc.value()
                );*/
            }

            if idx == 0 {
                let root_hash_rlc =
                    self.rlp.rlc.compute_rlc_fixed_len(ctx, range, &proof.root_hash_bytes, 32)?;
                // print_bytes("root hash".to_string(), &proof.root_hash_bytes);
                /*println!(
                    "a {:?} b {:?} node_type {:?}",
                    root_hash_rlc.rlc_val.value(),
                    node_hash_rlc.value(),
                    proof.node_types[0].value()
                );*/
                self.rlp.rlc.constrain_equal(
                    ctx,
                    &Existing(&root_hash_rlc.rlc_val),
                    &Existing(&node_hash_rlc),
                )?;
            } else {
                let ext_ref_rlc = exts_parsed[idx - 1].node_ref.rlc_val.clone();
                let branch_ref_rlc = self.rlp.rlc.select_from_idx(
                    ctx,
                    &branches_parsed[idx - 1]
                        .node_refs
                        .iter()
                        .map(|x| Existing(&x.rlc_val))
                        .collect(),
                    &Existing(&proof.key_frag_hexs[idx - 1][0]),
                )?;
                let match_hash_rlc = self.rlp.rlc.select(
                    ctx,
                    &Existing(&ext_ref_rlc),
                    &Existing(&branch_ref_rlc),
                    &Existing(&proof.node_types[idx - 1]),
                )?;
                /*println!(
                    "idx {:?} match_hash_rlc {:#?} node_hash_rlc {:#?}",
                    idx,
                    match_hash_rlc.value(),
                    node_hash_rlc.value()
                );*/
                let is_match = self.rlp.rlc.is_equal(
                    ctx,
                    &Existing(&match_hash_rlc),
                    &Existing(&node_hash_rlc),
                )?;
                // dbg!(&is_match);
                matches.push(is_match);
            }
        }
        let mut match_sums = Vec::with_capacity(3 * (max_depth - 2) + 1);
        let mut running_sum = Value::known(F::zero());
        let mut gate_offsets = Vec::with_capacity(max_depth - 2);
        for (idx, match_) in matches.iter().enumerate() {
            if idx == 0 {
                match_sums.push(Existing(match_));
                running_sum = running_sum + match_.value();
            } else {
                match_sums.push(Existing(match_));
                match_sums.push(Constant(F::one()));
                running_sum = running_sum + match_.value();
                match_sums.push(Witness(running_sum));
            }
            if idx < max_depth - 2 {
                gate_offsets.push(3 * idx);
            }
        }

        let assigned =
            self.rlp.rlc.assign_region_rlc(ctx, &match_sums, vec![], gate_offsets, None)?;
        // println!("assigned sums {:?}", assigned);

        let depth_minus_one =
            self.rlp.range.gate.sub(ctx, &Existing(&proof.depth), &Constant(F::one()))?;
        let match_cnt = self.rlp.rlc.select_from_idx(
            ctx,
            &[Constant(F::zero())]
                .into_iter()
                .chain((0..max_depth - 1).map(|idx| Existing(&assigned[3 * idx])).into_iter())
                .collect(),
            &Existing(&depth_minus_one),
        )?;
        // println!("match_cnt {:#?} depth {:#?}", match_cnt, proof.depth);
        ctx.region.constrain_equal(match_cnt.cell(), depth_minus_one.cell())?;

        Ok(())
    }

    pub fn parse_mpt_inclusion_var_key(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        proof: &MPTVarKeyProof<F>,
        key_max_byte_len: usize,
        value_max_byte_len: usize,
        max_depth: usize,
    ) -> Result<(), Error> {
        assert_eq!(proof.key_max_byte_len, key_max_byte_len);
        assert_eq!(proof.value_max_byte_len, value_max_byte_len);
        assert_eq!(proof.max_depth, max_depth);

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{fs, io::BufRead};

    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };

    #[derive(Clone, Debug)]
    pub struct MPTCircuit<F> {
        pub key_bytes: Vec<Option<u8>>,
        pub value_bytes: Vec<Option<u8>>,
        pub value_byte_len: Option<usize>,
        pub root_hash_bytes: Vec<Option<u8>>,

        // proof specification
        pub leaf_bytes: Vec<Option<u8>>,
        pub nodes: Vec<Vec<Option<u8>>>,
        pub node_types: Vec<Option<u8>>, // index 0 = root; 0 = branch, 1 = extension
        pub depth: Option<usize>,

        pub key_frag_hexs: Vec<Vec<Option<u8>>>,
        // hex_len = 2 * byte_len + is_odd - 2
        // if nibble for branch: byte_len = is_odd = 1
        pub key_frag_is_odd: Vec<Option<u8>>,
        pub key_frag_byte_len: Vec<Option<usize>>,

        pub key_byte_len: usize,
        pub value_max_byte_len: usize,
        pub max_depth: usize,
        _marker: PhantomData<F>,

        k: usize,
    }

    impl<F: Field> Circuit<F> for MPTCircuit<F> {
        type Config = MPTChip<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let params_str = fs::read_to_string("configs/mpt_circuit.config").unwrap();
            let params: EthConfigParams = serde_json::from_str(params_str.as_str()).unwrap();

            MPTChip::configure(meta, "gamma".to_string(), "rlc".to_string(), params)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let witness_time = start_timer!(|| "witness gen");
            config.rlp.range.load_lookup_table(&mut layouter)?;
            config.keccak.load_lookup_table(&mut layouter)?;
            let gamma = layouter.get_challenge(config.rlp.rlc.gamma);
            dbg!(&gamma);

            let using_simple_floor_planner = true;
            let mut first_pass = true;
            let mut phase = 0u8;
            layouter.assign_region(
                || "MPT Fixed Test",
                |region| {
                    if using_simple_floor_planner && first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    phase = phase + 1u8;

                    dbg!(phase);
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            num_advice: vec![
                                ("default".to_string(), config.rlp.range.gate.num_advice),
                                ("rlc".to_string(), config.rlp.rlc.basic_chips.len()),
                                ("keccak".to_string(), config.keccak.rotation.len()),
                                ("keccak_xor".to_string(), config.keccak.xor_values.len() / 3),
                                (
                                    "keccak_xorandn".to_string(),
                                    config.keccak.xorandn_values.len() / 4,
                                ),
                            ],
                        },
                    );
                    let ctx = &mut aux;
                    ctx.challenge.insert("gamma".to_string(), gamma);

                    let key_bytes = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        self.key_bytes
                            .iter()
                            .map(|x| {
                                Witness(
                                    x.map(|v| Value::known(F::from(v as u64)))
                                        .unwrap_or(Value::unknown()),
                                )
                            })
                            .collect(),
                        vec![],
                        vec![],
                        vec![],
                    )?;
                    let value_bytes = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        self.value_bytes
                            .iter()
                            .map(|x| {
                                Witness(
                                    x.map(|v| Value::known(F::from(v as u64)))
                                        .unwrap_or(Value::unknown()),
                                )
                            })
                            .collect(),
                        vec![],
                        vec![],
                        vec![],
                    )?;
                    let value_byte_len = config
                        .rlp
                        .range
                        .gate
                        .assign_region_smart(
                            ctx,
                            vec![Witness(
                                self.value_byte_len
                                    .map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown()),
                            )],
                            vec![],
                            vec![],
                            vec![],
                        )?
                        .into_iter()
                        .nth(0)
                        .unwrap();
                    let root_hash_bytes = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        self.root_hash_bytes
                            .iter()
                            .map(|x| {
                                Witness(
                                    x.map(|v| Value::known(F::from(v as u64)))
                                        .unwrap_or(Value::unknown()),
                                )
                            })
                            .collect(),
                        vec![],
                        vec![],
                        vec![],
                    )?;
                    let leaf_bytes = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        self.leaf_bytes
                            .iter()
                            .map(|x| {
                                Witness(
                                    x.map(|v| Value::known(F::from(v as u64)))
                                        .unwrap_or(Value::unknown()),
                                )
                            })
                            .collect(),
                        vec![],
                        vec![],
                        vec![],
                    )?;
                    let mut nodes = Vec::new();
                    for node in self.nodes.iter() {
                        let node_pre = config.rlp.range.gate.assign_region_smart(
                            ctx,
                            node.iter()
                                .map(|x| {
                                    Witness(
                                        x.map(|v| Value::known(F::from(v as u64)))
                                            .unwrap_or(Value::unknown()),
                                    )
                                })
                                .collect(),
                            vec![],
                            vec![],
                            vec![],
                        )?;
                        nodes.push(node_pre);
                    }
                    let node_types = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        self.node_types
                            .iter()
                            .map(|x| {
                                Witness(
                                    x.map(|v| Value::known(F::from(v as u64)))
                                        .unwrap_or(Value::unknown()),
                                )
                            })
                            .collect(),
                        vec![],
                        vec![],
                        vec![],
                    )?;
                    let depth = config
                        .rlp
                        .range
                        .gate
                        .assign_region_smart(
                            ctx,
                            vec![Witness(
                                self.depth
                                    .map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown()),
                            )],
                            vec![],
                            vec![],
                            vec![],
                        )?
                        .into_iter()
                        .nth(0)
                        .unwrap();
                    let mut key_frag_hexs = Vec::new();
                    for key_frag_hex in self.key_frag_hexs.iter() {
                        let key_frag_hex_pre = config.rlp.range.gate.assign_region_smart(
                            ctx,
                            key_frag_hex
                                .iter()
                                .map(|x| {
                                    Witness(
                                        x.map(|v| Value::known(F::from(v as u64)))
                                            .unwrap_or(Value::unknown()),
                                    )
                                })
                                .collect(),
                            vec![],
                            vec![],
                            vec![],
                        )?;
                        key_frag_hexs.push(key_frag_hex_pre);
                    }
                    let key_frag_is_odd = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        self.key_frag_is_odd
                            .iter()
                            .map(|x| {
                                Witness(
                                    x.map(|v| Value::known(F::from(v as u64)))
                                        .unwrap_or(Value::unknown()),
                                )
                            })
                            .collect(),
                        vec![],
                        vec![],
                        vec![],
                    )?;
                    let key_frag_byte_len = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        self.key_frag_byte_len
                            .iter()
                            .map(|x| {
                                Witness(
                                    x.map(|v| Value::known(F::from(v as u64)))
                                        .unwrap_or(Value::unknown()),
                                )
                            })
                            .collect(),
                        vec![],
                        vec![],
                        vec![],
                    )?;

                    let mpt_proof = MPTFixedKeyProof {
                        key_bytes,
                        value_bytes,
                        value_byte_len,
                        root_hash_bytes,
                        leaf_bytes,
                        nodes,
                        node_types,
                        depth,
                        key_frag_hexs,
                        key_frag_is_odd,
                        key_frag_byte_len,
                        key_byte_len: self.key_byte_len,
                        value_max_byte_len: self.value_max_byte_len,
                        max_depth: self.max_depth,
                    };
                    let res = config.parse_mpt_inclusion_fixed_key(
                        ctx,
                        &config.rlp.range,
                        &mpt_proof,
                        self.key_byte_len,
                        self.value_max_byte_len,
                        self.max_depth,
                    )?;

                    let stats = config.rlp.range.finalize(ctx)?;
                    #[cfg(feature = "display")]
                    {
                        println!("[stats] {:?}", stats);
                        println!(
                            "[ctx.advice_rows sums] {:#?}",
                            ctx.advice_rows
                                .iter()
                                .map(|(key, val)| (key, val.iter().sum::<usize>()))
                                .collect::<Vec<_>>()
                        );
                        let total_rlc = ctx.advice_rows["rlc"].iter().sum::<usize>();
                        println!("optimal rlc #: {}", (total_rlc + (1 << self.k) - 1) >> self.k);
                        let total_default = ctx.advice_rows["default"].iter().sum::<usize>();
                        println!(
                            "optimal default #: {}",
                            (total_default + (1 << self.k) - 1) >> self.k
                        );
                        println!(
                            "optimal lookup #: {}",
                            (ctx.cells_to_lookup.len() + (1 << self.k) - 1) >> self.k
                        );
                        println!("optimal fixed #: {}", (stats.1 + (1 << self.k) - 1) >> self.k);
                        let total_keccak = ctx.advice_rows["keccak"].iter().sum::<usize>();
                        println!(
                            "optimal keccak #: {}",
                            (total_keccak + (1 << self.k) - 1) >> self.k
                        );
                        let total_xor = ctx.advice_rows["keccak_xor"].iter().sum::<usize>();
                        println!("optimal xor #: {}", (total_xor + (1 << self.k) - 1) >> self.k,);
                        let total_xorandn = ctx.advice_rows["keccak_xorandn"].iter().sum::<usize>();
                        println!(
                            "Optimal xorandn #: {}",
                            (total_xorandn + (1 << self.k) - 1) >> self.k
                        );
                    }
                    Ok(())
                },
            )?;
            end_timer!(witness_time);
            Ok(())
        }
    }

    impl<F: Field> Default for MPTCircuit<F> {
        fn default() -> Self {
            let block_str = std::fs::read_to_string("scripts/input_gen/block.json").unwrap();
            let block: serde_json::Value = serde_json::from_str(block_str.as_str()).unwrap();
            // println!("stateRoot {:?}", block["stateRoot"]);

            let pf_str = std::fs::read_to_string("scripts/input_gen/acct_storage_pf.json").unwrap();
            let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
            let acct_pf = pf["accountProof"].clone();
            let storage_pf = pf["storageProof"][0].clone();
            // println!("acct_pf {:?}", acct_pf);
            // println!("storage_root {:?}", pf["storageHash"]);
            // println!("storage_pf {:?}", storage_pf);

            let key_bytes_str_pre: String =
                serde_json::from_value(storage_pf["key"].clone()).unwrap();
            let mut hasher = Keccak256::default();
            // println!("MPTC {:?}", Vec::from_hex(&key_bytes_str_pre).unwrap());
            hasher.update(&Vec::from_hex(&key_bytes_str_pre).unwrap());
            let key_bytes_str = hasher.finalize();
            let mut key_byte_hexs = Vec::new();
            for idx in 0..32 {
                key_byte_hexs.push(key_bytes_str[idx] / 16);
                key_byte_hexs.push(key_bytes_str[idx] % 16);
            }
            // println!("key_bytes_str {:?}", key_bytes_str);
            let value_bytes_str: String =
                serde_json::from_value(storage_pf["value"].clone()).unwrap();
            let root_hash_str: String = serde_json::from_value(pf["storageHash"].clone()).unwrap();
            let pf_strs: Vec<String> = serde_json::from_value(storage_pf["proof"].clone()).unwrap();
            let leaf_str: String = pf_strs[pf_strs.len() - 1].clone();

            let key_byte_len = 32;
            let value_max_byte_len = 33;
            let (_, max_leaf_bytes) = max_leaf_lens(key_byte_len, value_max_byte_len);
            let mut leaf_bytes: Vec<Option<u8>> =
                Vec::from_hex(&leaf_str[2..]).unwrap().iter().map(|x| Some(*x)).collect();
            leaf_bytes.append(&mut vec![Some(0u8); max_leaf_bytes - leaf_bytes.len()]);

            let (_, max_ext_bytes) = max_ext_lens(32);
            let (_, max_branch_bytes) = max_branch_lens();
            let max_node_bytes = max(max_ext_bytes, max_branch_bytes);
            // println!("max_node_bytes {:?} max_leaf_bytes {:?}", max_node_bytes, max_leaf_bytes);

            let max_depth = 8;
            let mut node_types = Vec::new();
            let mut nodes = Vec::new();
            let mut key_frag_hexs: Vec<Vec<Option<u8>>> = Vec::new();
            let mut key_frag_is_odd = Vec::new();
            let mut key_frag_byte_len = Vec::new();
            let mut key_idx = 0;
            for idx in 0..max_depth {
                if idx < pf_strs.len() - 1 {
                    let mut node: Vec<Option<u8>> = Vec::from_hex(&pf_strs[idx][2..])
                        .unwrap()
                        .iter()
                        .map(|x| Some(*x))
                        .collect();
                    node.append(&mut vec![Some(0u8); max_node_bytes - node.len()]);
                    nodes.push(node);

                    let hex = Vec::from_hex(&pf_strs[idx][2..]).unwrap();
                    let decode = Rlp::new(&hex);
                    if decode.item_count().unwrap() == 2 {
                        node_types.push(Some(1));
                    } else {
                        node_types.push(Some(0));
                    }
                } else if idx < max_depth - 1 {
                    node_types.push(Some(0));
                    let dummy_branch_str =
                    "f1808080808080808080808080808080a0000000000000000000000000000000000000000000000000000000000000000080";
                    let mut node: Vec<Option<u8>> =
                        Vec::from_hex(dummy_branch_str).unwrap().iter().map(|x| Some(*x)).collect();
                    node.append(&mut vec![Some(0u8); max_node_bytes - node.len()]);
                    nodes.push(node);
                }

                if idx < pf_strs.len() {
                    let hex = Vec::from_hex(&pf_strs[idx][2..]).unwrap();
                    let decode = Rlp::new(&hex);
                    if decode.item_count().unwrap() == 2 {
                        let field = decode.at(0).unwrap().data().unwrap();
                        key_frag_byte_len.push(Some(field.len()));
                        let field_vec = field.to_vec();
                        let mut field_hexs = Vec::new();
                        for b in field_vec.iter() {
                            field_hexs.push(b / 16);
                            field_hexs.push(b % 16);
                        }
                        let start_idx = {
                            if field_hexs[0] == 1u8 || field_hexs[0] == 3u8 {
                                key_frag_is_odd.push(Some(1u8));
                                1
                            } else {
                                key_frag_is_odd.push(Some(0u8));
                                2
                            }
                        };

                        let mut frag: Vec<Option<u8>> =
                            field_hexs[start_idx..].iter().map(|x| Some(*x)).collect();
                        frag.append(&mut vec![Some(0u8); 64 - frag.len()]);
                        key_frag_hexs.push(frag);
                    } else {
                        let mut frag: Vec<Option<u8>> = vec![Some(key_byte_hexs[key_idx])];
                        println!("frag {:?} key_idx {:?}", frag, key_idx);
                        frag.append(&mut vec![Some(0u8); 64 - frag.len()]);
                        key_frag_hexs.push(frag);
                        key_frag_byte_len.push(Some(1usize));
                        key_frag_is_odd.push(Some(1u8));
                    }
                    key_idx = key_idx + 2 * key_frag_byte_len[key_frag_byte_len.len() - 1].unwrap()
                        - 2
                        + key_frag_is_odd[key_frag_is_odd.len() - 1].unwrap() as usize;
                } else {
                    let frag: Vec<Option<u8>> = vec![Some(0u8); 64];
                    key_frag_hexs.push(frag);
                    key_frag_byte_len.push(Some(0usize));
                    key_frag_is_odd.push(Some(0u8));
                }
            }

            // println!("key_frag_hexs {:?}", key_frag_hexs);

            //	let mut value_bytes: Vec<Option<u8>> = Vec::from_hex(&value_bytes_str[2..]).unwrap().iter().map(|x| Some(*x)).collect();
            let mut value_bytes: Vec<Option<u8>> =
                rlp::encode(&Vec::from_hex(&value_bytes_str[2..]).unwrap())
                    .iter()
                    .map(|x| Some(*x))
                    .collect();
            let value_byte_len = Some(value_bytes.len());
            // println!("value_bytes {:?}", value_bytes);
            value_bytes.extend(vec![Some(0u8); 33 - value_bytes.len()].into_iter());

            MPTCircuit {
                key_bytes: key_bytes_str.iter().map(|x| Some(*x)).collect(),
                value_bytes: value_bytes,
                value_byte_len,
                root_hash_bytes: Vec::from_hex(&root_hash_str[2..])
                    .unwrap()
                    .iter()
                    .map(|x| Some(*x))
                    .collect(),
                leaf_bytes,
                nodes,
                node_types,
                depth: Some(pf_strs.len()),
                key_frag_hexs,
                key_frag_is_odd,
                key_frag_byte_len,
                key_byte_len,
                value_max_byte_len,
                max_depth,
                _marker: PhantomData,
                k: 20,
            }
        }
    }

    #[test]
    pub fn test_mock_mpt_inclusion_fixed() -> Result<(), Error> {
        let params_str = std::fs::read_to_string("configs/mpt_circuit.config").unwrap();
        let params: EthConfigParams = serde_json::from_str(params_str.as_str()).unwrap();
        let k = params.degree;

        let mut circuit = MPTCircuit::<Fr>::default();
        circuit.k = k as usize;
        // println!("MPTCircuit {:?}", circuit);
        let prover_try = MockProver::run(k, &circuit, vec![]);
        let prover = prover_try.unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));

        Ok(())
    }

    #[test]
    fn bench_mpt_inclusion_fixed() -> Result<(), Box<dyn std::error::Error>> {
        let mut folder = std::path::PathBuf::new();
        folder.push("configs/bench_mpt.config");
        let bench_params_file = std::fs::File::open(folder.as_path())?;
        folder.pop();
        folder.pop();

        folder.push("data");
        folder.push("mpt_bench.csv");
        dbg!(&folder);
        let mut fs_results = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        write!(fs_results, "degree,total_advice,num_rlc_chip,num_default,num_lookup,num_fixed,num_keccak,num_xor,num_xorandn,proof_time,proof_size,verify_time\n")?;

        let mut params_folder = std::path::PathBuf::new();
        params_folder.push("./params");
        if !params_folder.is_dir() {
            std::fs::create_dir(params_folder.as_path())?;
        }

        let bench_params_reader = std::io::BufReader::new(bench_params_file);
        for line in bench_params_reader.lines() {
            let bench_params: EthConfigParams =
                serde_json::from_str(line.unwrap().as_str()).unwrap();
            println!(
                "---------------------- degree = {} ------------------------------",
                bench_params.degree
            );
            let mut rng = rand::thread_rng();

            {
                folder.pop();
                folder.push("configs/mpt_circuit.config");
                let mut f = std::fs::File::create(folder.as_path())?;
                write!(f, "{}", serde_json::to_string(&bench_params).unwrap())?;
                folder.pop();
                folder.pop();
                folder.push("data");
            }
            let params_time = start_timer!(|| "Params construction");
            let params = {
                params_folder.push(format!("kzg_bn254_{}.srs", bench_params.degree));
                let fd = std::fs::File::open(params_folder.as_path());
                let params = if let Ok(mut f) = fd {
                    println!("Found existing params file. Reading params...");
                    ParamsKZG::<Bn256>::read(&mut f).unwrap()
                } else {
                    println!("Creating new params file...");
                    let mut f = std::fs::File::create(params_folder.as_path())?;
                    let params = ParamsKZG::<Bn256>::setup(bench_params.degree, &mut rng);
                    params.write(&mut f).unwrap();
                    params
                };
                params_folder.pop();
                params
            };
            end_timer!(params_time);

            let mut circuit = MPTCircuit::<Fr>::default();
            circuit.k = bench_params.degree as usize;

            let vk_time = start_timer!(|| "Generating vkey");
            let vk = keygen_vk(&params, &circuit)?;
            end_timer!(vk_time);

            let pk_time = start_timer!(|| "Generating pkey");
            let pk = keygen_pk(&params, vk, &circuit)?;
            end_timer!(pk_time);

            // create a proof
            let proof_time = start_timer!(|| "SHPLONK");
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                _,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
                _,
            >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)?;
            let proof = transcript.finalize();
            end_timer!(proof_time);

            let verify_time = start_timer!(|| "Verify time");
            let verifier_params = params.verifier_params();
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                SingleStrategy<'_, Bn256>,
            >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
            .is_ok());
            end_timer!(verify_time);

            let proof_size = {
                folder.push("mpt_circuit_proof.data");
                let mut fd = std::fs::File::create(folder.as_path()).unwrap();
                folder.pop();
                fd.write_all(&proof).unwrap();
                fd.metadata().unwrap().len()
            };

            write!(
                fs_results,
                "{},{},{},{},{},{},{},{}, {}, {:?},{},{:?}\n",
                bench_params.degree,
                bench_params.num_basic_chips * 2
                    + bench_params.num_advice[0]
                    + bench_params.num_lookup_advice[0]
                    + bench_params.keccak_num_advice
                    + bench_params.keccak_num_xor * 3
                    + bench_params.keccak_num_xorandn * 4,
                bench_params.num_basic_chips,
                bench_params.num_advice[0],
                bench_params.num_lookup_advice[0],
                bench_params.num_fixed,
                bench_params.keccak_num_advice,
                bench_params.keccak_num_xor,
                bench_params.keccak_num_xorandn,
                proof_time.time.elapsed(),
                proof_size,
                verify_time.time.elapsed()
            )?;
            /*
            let circuit = KeccakCircuit::default();
            let proof_time = start_timer!(|| "GWC");
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverGWC<'_, Bn256>,
                Challenge255<G1Affine>,
                _,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
                _,
            >(&params, &pk, &[circuit], &[&[]], OsRng::default(), &mut transcript)?;
            let proof = transcript.finalize();
            end_timer!(proof_time);
            */
        }
        Ok(())
    }
}
