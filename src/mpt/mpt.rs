use std::{cmp::max, marker::PhantomData};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use eth_types::Field;

use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy}, GateInstructions, RangeInstructions,
    },
    utils::fe_to_biguint,
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

use crate::{
    keccak::KeccakChip,
    rlp::rlc::{log2, RlcFixedTrace, RlcTrace},
    rlp::rlp::{max_rlp_len_len, RlpArrayChip, RlpArrayTrace}
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

#[derive(Clone, Debug)]
pub struct MPTFixedKeyProof<F: Field> {
    // claim specification
    key_bytes: Vec<AssignedValue<F>>,
    value_bytes: Vec<AssignedValue<F>>,
    value_byte_len: AssignedValue<F>,
    root_hash_bytes: Vec<AssignedValue<F>>,

    // proof specification
    leaf_bytes: Vec<AssignedValue<F>>,
    nodes: Vec<Vec<AssignedValue<F>>>,
    node_types: Vec<AssignedValue<F>>,     // index 0 = root; 0 = branch, 1 = extension
    depth: AssignedValue<F>,

    key_frag_hexs: Vec<Vec<AssignedValue<F>>>,
    // hex_len = 2 * byte_len + is_odd - 2
    // if nibble for branch: byte_len = is_odd = 1
    key_frag_is_odd: Vec<AssignedValue<F>>,
    key_frag_byte_len: Vec<AssignedValue<F>>,

    key_byte_len: usize,
    value_max_byte_len: usize,
    max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct MPTVarKeyProof<F: Field> {
    // claim specification
    key_bytes: Vec<AssignedValue<F>>,
    key_byte_len: AssignedValue<F>,
    value_bytes: Vec<AssignedValue<F>>,
    value_byte_len: AssignedValue<F>,
    root_hash_bytes: Vec<AssignedValue<F>>,

    // proof specification
    leaf_bytes: Vec<AssignedValue<F>>,
    proof_nodes: Vec<Vec<AssignedValue<F>>>,
    node_types: Vec<AssignedValue<F>>,     // index 0 = root; 0 = branch, 1 = extension
    depth: AssignedValue<F>,

    key_frag_hexs: Vec<Vec<AssignedValue<F>>>,
    // hex_len = 2 * byte_len + is_odd - 2
    key_frag_is_odd: Vec<AssignedValue<F>>,
    key_frag_byte_len: Vec<AssignedValue<F>>,
    
    key_max_byte_len: usize,
    value_max_byte_len: usize,
    max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct MPTChip<F: Field> {
    rlp: RlpArrayChip<F>,
    keccak: KeccakChip<F>,
}

impl<F: Field> MPTChip<F> {
    pub fn configure(
	meta: &mut ConstraintSystem<F>,
	num_basic_chips: usize,
        num_chips_fixed: usize,
        challenge_id: String,
        context_id: String,
        range_strategy: RangeStrategy,
        num_advice: &[usize],
        mut num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
    ) -> Self {
	let rlp = RlpArrayChip::configure(
            meta,
            num_basic_chips,
            num_chips_fixed,
            challenge_id.clone(),
            context_id,
            range_strategy,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
        );
        let params_str = std::fs::read_to_string("configs/keccak.config").unwrap();
        let params: crate::keccak::KeccakCircuitParams =
            serde_json::from_str(params_str.as_str()).unwrap();
        println!("params adv {:?} fix {:?}", params.num_advice, params.num_fixed);
        let keccak = KeccakChip::configure(
            meta,
            "keccak".to_string(),
            1088,
            256,
            params.num_advice,
            params.num_xor,
            params.num_xorandn,
            params.num_fixed,
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
	let max_ext_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	max_ext_bytes
    }

    fn branch_max_byte_len() -> usize {
	let max_node_ref_bytes = 32;
	let max_node_ref_rlp_bytes =
	    1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
	let mut max_field_bytes = vec![max_node_ref_rlp_bytes; 16];
	max_field_bytes.push(2);
	let max_branch_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	max_branch_bytes
    }

    pub fn mpt_hash(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	bytes: &Vec<AssignedValue<F>>,
	len: &AssignedValue<F>,
	max_len: usize,
    ) -> Result<RlcTrace<F>, Error> {
	let hash_bytes = self.keccak.keccak_bytes_var_len(
	    ctx, range, bytes, len.clone(), 0usize, max_len
	)?;
	let is_short = range.is_less_than(
	    ctx, &Existing(&len), &Constant(F::from(32)), log2(max_len)
	)?;
	let mut mpt_hash_bytes = Vec::with_capacity(32);
	for idx in 0..32 {
	    if idx < max_len {
		// trailing entries of bytes are constrained to be 0
		let byte = range.gate.select(
		    ctx, &Existing(&bytes[idx]), &Existing(&hash_bytes[idx]), &Existing(&is_short)
		)?;
		mpt_hash_bytes.push(byte);
	    } else {
		let byte = range.gate.select(
		    ctx, &Constant(F::zero()), &Existing(&hash_bytes[idx]), &Existing(&is_short)
		)?;
		mpt_hash_bytes.push(byte);		
	    }
	}
	let mpt_hash_len = range.gate.select(
	    ctx, &Existing(&len), &Constant(F::from(32)), &Existing(&is_short)
	)?;
        let hash = self.rlp.rlc.compute_rlc(ctx, range, &mpt_hash_bytes, mpt_hash_len, 32)?;
	Ok(hash)
    }
    
    pub fn parse_leaf(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	leaf_bytes: &Vec<AssignedValue<F>>,
	max_key_bytes: usize,
	max_value_bytes: usize,
    ) -> Result<LeafTrace<F>, Error> {
	let max_encoded_path_bytes = max_key_bytes + 1;
	let max_encoded_path_rlp_bytes =
	    1 + max_rlp_len_len(max_encoded_path_bytes) + max_encoded_path_bytes;
	let max_value_rlp_bytes = 1 + max_rlp_len_len(max_value_bytes) + max_value_bytes;
	let max_field_bytes = vec![max_encoded_path_rlp_bytes, max_value_rlp_bytes];
	let max_leaf_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	assert!(leaf_bytes.len() == max_leaf_bytes);
		
	let rlp_trace = self.rlp.decompose_rlp_array(
	    ctx, range, leaf_bytes, max_field_bytes, max_leaf_bytes, 2
	)?;	
	let leaf_hash = self.mpt_hash(
	    ctx, range, &leaf_bytes, &rlp_trace.array_trace.rlc_len, max_leaf_bytes
	)?;
	
	let leaf_trace = LeafTrace {
	    rlp_trace: rlp_trace.array_trace.clone(),
	    key_path: rlp_trace.field_traces[0].clone(),
	    value: rlp_trace.field_traces[1].clone(),	    
	    leaf_hash,
	    prefix: rlp_trace.prefix.clone(),
	    len_trace: rlp_trace.len_trace.clone(),
	    field_prefixs: rlp_trace.field_prefixs.clone(),
	    field_len_traces: rlp_trace.field_len_traces.clone()
	};
	Ok(leaf_trace)
    }

    pub fn parse_ext(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	ext_bytes: &Vec<AssignedValue<F>>,
	max_key_bytes: usize,
    ) -> Result<ExtensionTrace<F>, Error> {
	let max_node_ref_bytes = 32;
	let max_encoded_path_bytes = max_key_bytes + 1;
	let max_encoded_path_rlp_bytes =
	    1 + max_rlp_len_len(max_encoded_path_bytes) + max_encoded_path_bytes;
	let max_node_ref_rlp_bytes = 1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
	let max_field_bytes = vec![max_encoded_path_rlp_bytes, max_node_ref_rlp_bytes];
	let max_ext_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	assert!(ext_bytes.len() == max_ext_bytes);
		
	let rlp_trace = self.rlp.decompose_rlp_array(
	    ctx, range, ext_bytes, max_field_bytes, max_ext_bytes, 2
	)?;

        let ext_hash = self.mpt_hash(
	   ctx, range, &ext_bytes, &rlp_trace.array_trace.rlc_len, max_ext_bytes
	)?;
	
	let ext_trace = ExtensionTrace {
	    rlp_trace: rlp_trace.array_trace.clone(),
	    key_path: rlp_trace.field_traces[0].clone(),
	    node_ref: rlp_trace.field_traces[1].clone(),	    
	    ext_hash,
	    prefix: rlp_trace.prefix.clone(),
	    len_trace: rlp_trace.len_trace.clone(),
	    field_prefixs: rlp_trace.field_prefixs.clone(),
	    field_len_traces: rlp_trace.field_len_traces.clone()
	};
	Ok(ext_trace)
    }

    pub fn parse_nonterminal_branch(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	branch_bytes: &Vec<AssignedValue<F>>,
    ) -> Result<BranchTrace<F>, Error> {
	let max_node_ref_bytes = 32;
	let max_node_ref_rlp_bytes =
	    1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
	let mut max_field_bytes = vec![max_node_ref_rlp_bytes; 16];
	max_field_bytes.push(2);
	let max_branch_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	assert!(branch_bytes.len() == max_branch_bytes);

	let rlp_trace = self.rlp.decompose_rlp_array(
	    ctx, range, branch_bytes, max_field_bytes, max_branch_bytes, 17
	)?;

        let branch_hash = self.mpt_hash(
	    ctx, range, &branch_bytes, &rlp_trace.array_trace.rlc_len, max_branch_bytes
	)?;
	
	let branch_trace = BranchTrace {
	    rlp_trace: rlp_trace.array_trace.clone(),
	    node_refs: rlp_trace.field_traces.clone(),
	    branch_hash,
	    prefix: rlp_trace.prefix.clone(),
	    len_trace: rlp_trace.len_trace.clone(),
	    field_prefixs: rlp_trace.field_prefixs.clone(),
	    field_len_traces: rlp_trace.field_len_traces.clone()	    
	};
	Ok(branch_trace)
    }

    pub fn key_hex_to_hex_rlc(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	key_frag_hexs: &Vec<AssignedValue<F>>,
	key_frag_byte_len: &AssignedValue<F>,
	is_odd: &AssignedValue<F>,
	key_byte_len: usize,
    ) -> Result<AssignedValue<F>, Error> {
	let assigned = range.gate.assign_region_smart(
	    ctx,
	    vec![Existing(&is_odd),
		 Constant(F::from(2)),
		 Existing(&key_frag_byte_len),
		 Witness(is_odd.value().copied()
			 + Value::known(F::from(2)) * key_frag_byte_len.value().copied()),
		 Constant(-F::from(2)),
		 Constant(F::one()),
		 Witness(is_odd.value().copied() - Value::known(F::from(2))
			 + Value::known(F::from(2)) * key_frag_byte_len.value().copied())],
	    vec![0, 3],
	    vec![],
	    vec![],
	)?;
	Ok(assigned[6].clone())	
    }

    pub fn key_hex_to_path_rlc(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	key_frag_hexs: &Vec<AssignedValue<F>>,
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
			&vec![Constant(F::from(16)), Existing(&key_frag_hexs[0])]
		    )?;
		    path_bytes.push(byte);
		} else {
		    // (1 - is_odd) * 2 + is_odd * (48 + x_0)
		    // | 2 | 46 | is_odd | 2 + 46 * is_odd | is_odd | x_0 | out |
		    let assigned = range.gate.assign_region_smart(
			ctx,
			vec![Constant(F::from(2)),
			      Constant(F::from(46)),
			      Existing(&is_odd),
			      Witness(Value::known(F::from(2))
				      + Value::known(F::from(46)) * is_odd.value()),
			      Existing(&is_odd),
			      Existing(&key_frag_hexs[0]),
			      Witness(Value::known(F::from(2))
				      + Value::known(F::from(46)) * is_odd.value().copied()
				      + is_odd.value().copied() * key_frag_hexs[0].value().copied())],
			vec![0, 3],
			vec![],
			vec![],
		    )?;
		    let byte = assigned[6].clone();
		    path_bytes.push(byte);		    
		}
	    } else if byte_idx < key_byte_len {
		let odd_byte = range.gate.assign_region_smart(
		    ctx,
		    vec![Existing(&key_frag_hexs[2 * byte_idx]),
			 Existing(&key_frag_hexs[2 * byte_idx - 1]),
			 Constant(F::from(16)),
			 Witness(key_frag_hexs[2 * byte_idx].value().copied()
				 + Value::known(F::from(16)) * key_frag_hexs[2 * byte_idx - 1].value().copied())],
		    vec![0],
		    vec![],
		    vec![],
		)?;
		let even_byte = range.gate.assign_region_smart(
		    ctx,
		    vec![Existing(&key_frag_hexs[2 * byte_idx - 1]),
			 Existing(&key_frag_hexs[2 * byte_idx - 2]),
			 Constant(F::from(16)),
			 Witness(key_frag_hexs[2 * byte_idx - 1].value().copied()
				 + Value::known(F::from(16)) * key_frag_hexs[2 * byte_idx - 2].value().copied())],
		    vec![0],
		    vec![],
		    vec![],
		)?;
		let byte = range.gate.select(
		    ctx, &Existing(&odd_byte[3]), &Existing(&even_byte[3]), &Existing(&is_odd)
		)?;
		path_bytes.push(byte);
	    } else {
		let odd_byte = range.gate.assign_region_smart(
		    ctx,
		    vec![Constant(F::zero()),
			 Existing(&key_frag_hexs[2 * byte_idx - 1]),
			 Constant(F::from(16)),
			 Witness(Value::known(F::from(16)) * key_frag_hexs[2 * byte_idx - 1].value().copied())],
		    vec![0],
		    vec![],
		    vec![],
		)?;
		let even_byte = range.gate.assign_region_smart(
		    ctx,
		    vec![Existing(&key_frag_hexs[2 * byte_idx - 1]),
			 Existing(&key_frag_hexs[2 * byte_idx - 2]),
			 Constant(F::from(16)),
			 Witness(key_frag_hexs[2 * byte_idx - 1].value().copied()
				 + Value::known(F::from(16)) * key_frag_hexs[2 * byte_idx - 2].value().copied())],
		    vec![0],
		    vec![],
		    vec![],
		)?;
		let byte = range.gate.select(
		    ctx, &Existing(&odd_byte[3]), &Existing(&even_byte[3]), &Existing(&is_odd)
		)?;
		path_bytes.push(byte);
	    }
	}
	let path_rlc = self.rlp.rlc.compute_rlc(
	    ctx, range, &path_bytes, key_frag_byte_len.clone(), key_byte_len
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
	// TODO: init with valid dummy_ext and branch
	let dummy_ext: Vec<QuantumCell<F>> = Vec::new();
	let dummy_branch: Vec<QuantumCell<F>> = Vec::new();
	
	/* Validate inputs, check that:
	   * all inputs are bytes	
	   * node_types[idx] in {0, 1}
           * key_frag_is_odd[idx] in {0, 1}         
           * key_frag_hexes are hexs   
	   * 0 < depth <= max_depth
           * 0 < value_byte_len <= value_max_byte_len
           * 0 < key_frag_byte_len[idx] <= key_byte_len + 1
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
		ctx, vec![Constant(F::zero()), Existing(&bit), Existing(&bit), Existing(&bit)],
		vec![0], vec![], vec![]
	    )?;
	}
	for bit in proof.key_frag_is_odd.iter() {
	    range.gate.assign_region_smart(
		ctx, vec![Constant(F::zero()), Existing(&bit), Existing(&bit), Existing(&bit)],
		vec![0], vec![], vec![]
	    )?;
	}
	for frag in proof.key_frag_hexs.iter() {
	    for hex in frag.iter() {
		// use xor to lookup hex and save on lookup args
		self.keccak.xor(ctx, &vec![hex, hex])?;
	    }
	}
	range.check_less_than_safe(
	    ctx,
	    &proof.depth,
	    proof.max_depth + 1,
	    log2(proof.max_depth + 1)
	)?;
	range.check_less_than_safe(
	    ctx,
	    &proof.value_byte_len,
	    proof.value_max_byte_len + 1,
	    log2(proof.value_max_byte_len + 1)
	)?;
	for frag_len in proof.key_frag_byte_len.iter() {
	    range.check_less_than_safe(
		ctx,
		&frag_len,
		proof.key_byte_len + 2,
		log2(proof.key_byte_len + 2)
	    )?;
	}

	/* Parse RLP
           * RLP Leaf      for leaf_bytes
	   * RLP Extension for select(dummy_extension[idx], nodes[idx], node_types[idx])
           * RLP Branch    for select(nodes[idx], dummy_branch[idx], node_types[idx])
	 */
	let leaf_parsed = self.parse_leaf(
	    ctx, range, &proof.leaf_bytes, key_byte_len, value_max_byte_len
	)?;
	let mut exts_parsed = Vec::with_capacity(max_depth - 1);
	let mut branches_parsed = Vec::with_capacity(max_depth - 1);
	for idx in 0..max_depth - 1 {
	    let mut ext_in = Vec::with_capacity(ext_max_byte_len);
	    for byte_idx in 0..ext_max_byte_len {
		let ext_byte = range.gate.select(
		    ctx,
		    &dummy_ext[byte_idx],
		    &Existing(&proof.nodes[idx][byte_idx]),
		    &Existing(&proof.node_types[idx])
		)?;
		ext_in.push(ext_byte);
	    }
	    let ext_parsed = self.parse_ext(ctx, range, &ext_in, key_byte_len)?;
	    exts_parsed.push(ext_parsed);

	    let mut branch_in = Vec::with_capacity(branch_max_byte_len);
	    for byte_idx in 0..branch_max_byte_len {
		let branch_byte = range.gate.select(
		    ctx,
		    &Existing(&proof.nodes[idx][byte_idx]),
		    &dummy_branch[byte_idx],
		    &Existing(&proof.node_types[idx])
		)?;
		branch_in.push(branch_byte);
	    }
	    let branch_parsed = self.parse_nonterminal_branch(ctx, range, &branch_in)?;
	    branches_parsed.push(branch_parsed);
	}

	/* Check key fragment and prefix consistency
	 */
	let mut key_frag_ext_byte_rlcs = Vec::with_capacity(max_depth - 1);
	let mut key_frag_leaf_byte_rlcs = Vec::with_capacity(max_depth);
	for idx in 0..max_depth {
	    assert_eq!(proof.key_frag_hexs[idx].len(), 2 * key_byte_len);
	    if idx < max_depth - 1 {
		let ext_path_rlc = self.key_hex_to_path_rlc(
		    ctx,
		    range,
		    &proof.key_frag_hexs[idx],
		    &proof.key_frag_byte_len[idx],
		    &proof.key_frag_is_odd[idx],
		    key_byte_len,
		    true
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
		false
	    )?;
	    key_frag_leaf_byte_rlcs.push(leaf_path_rlc);		
	}	

	/* Check key fragments concatenate to key using hex RLC
	 */
	let mut key_hexs = Vec::with_capacity(2 * key_byte_len);
	for byte in proof.key_bytes.iter() {
	    let (hex1, hex2) = self.keccak.byte_to_hex(ctx, range, &byte)?;
	    key_hexs.push(hex1);
	    key_hexs.push(hex2);
	}
	let key_hex_rlc = self.rlp.rlc.compute_rlc_fixed_len(
	    ctx, range, &key_hexs, 2 * key_byte_len
	)?;
	let mut fragment_rlcs = Vec::new();
	for idx in 0..max_depth {
	    let frag_len = self.key_hex_to_hex_rlc(
		ctx,
		range,
		&proof.key_frag_hexs[idx],
		&proof.key_frag_byte_len[idx],
		&proof.key_frag_is_odd[idx],
		key_byte_len,
	    )?;
	    let fragment_rlc = self.rlp.rlc.compute_rlc(
		ctx, range, &proof.key_frag_hexs[idx], frag_len, 2 * key_byte_len
	    )?;
	    fragment_rlcs.push(fragment_rlc);
	}
	let rlc_cache = self.rlp.rlc.load_rlc_cache(ctx, log2(2 * key_byte_len))?;
	let assigned_len = range.gate.assign_region_smart(
	    ctx, vec![Constant(F::from(key_hex_rlc.len as u64))], vec![], vec![], vec![]
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
	    &rlc_cache
	)?;

	/* Check hash chains
	   * hash(node_types[0]) = root_hash
           * hash(node_types[idx + 1]) is in node_types[idx]
           * hash(leaf_bytes) is in node_types[depth - 2]
	 */
	let mut matches = Vec::new();
	for idx in 0..max_depth {
	    let mut node_hash_rlc = leaf_parsed.leaf_hash.rlc_val.clone();
	    if idx < max_depth - 1 {
		let node_inter_hash_rlc = self.rlp.rlc.select(
		    ctx,
		    &Existing(&branches_parsed[idx].branch_hash.rlc_val),
		    &Existing(&exts_parsed[idx].ext_hash.rlc_val),
		    &Existing(&proof.node_types[idx])
		)?;
		let is_leaf = range.is_equal(ctx, &Existing(&proof.depth), &Constant(F::one()))?;
		node_hash_rlc = self.rlp.rlc.select(
		    ctx,
		    &Existing(&leaf_parsed.leaf_hash.rlc_val),
		    &Existing(&node_inter_hash_rlc),
		    &Existing(&is_leaf)
		)?;
	    }
	    
	    if idx == 0 {
		let root_hash_rlc = self.rlp.rlc.compute_rlc_fixed_len(ctx, range, &proof.root_hash_bytes, 32)?;
		self.rlp.rlc.constrain_equal(
		    ctx, &Existing(&root_hash_rlc.rlc_val), &Existing(&node_hash_rlc)
		)?;
	    } else {
		let ext_ref_rlc = exts_parsed[idx - 1].node_ref.rlc_val.clone();
		let branch_ref_rlc = self.rlp.rlc.select_from_idx(
		    ctx,
		    &branches_parsed[idx - 1].node_refs.iter().map(|x| Existing(&x.rlc_val)).collect(),
		    &Existing(&proof.key_frag_hexs[idx - 1][0])
		)?;
		let match_hash_rlc = self.rlp.rlc.select(
		    ctx, &Existing(&branch_ref_rlc), &Existing(&ext_ref_rlc), &Existing(&proof.node_types[idx - 1])
		)?;
		let is_match = self.rlp.rlc.is_equal(
		    ctx, &Existing(&match_hash_rlc), &Existing(&node_hash_rlc)
		)?;
		matches.push(is_match);		
	    }
	}
	
	let mut match_sums = Vec::new();
	let mut running_sum = Value::known(F::zero());
	let mut gate_offsets = Vec::new();
	for idx in 0..max_depth - 1 {
	    if idx == 0 {
		match_sums.push(Existing(&matches[idx]));
		running_sum = running_sum + matches[idx].value();
	    } else {
		match_sums.push(Existing(&matches[idx]));
		match_sums.push(Constant(F::one()));
		running_sum = running_sum + matches[idx].value();
		match_sums.push(Witness(running_sum));
	    }
	    gate_offsets.push(3 * idx);
	}
	let assigned = self.rlp.rlc.assign_region_rlc(
	    ctx, &match_sums, vec![], gate_offsets, None
	)?;
	let match_cnt = self.rlp.rlc.select_from_idx(
	    ctx,
	    &(0..max_depth - 1).map(|idx| Existing(&assigned[3 * idx])).collect(),
	    &Existing(&proof.depth),
	)?;
	let check_equal = self.rlp.rlc.assign_region_rlc(
	    ctx,
	    &vec![Constant(F::one()),
		  Constant(F::one()),
		  Existing(&match_cnt),
		  Existing(&proof.depth)],
	    vec![], vec![0], None
	)?;
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

    #[test]
    pub fn test_mock_leaf_check() {

    }
}
