use std::cmp::max;
use std::marker::PhantomData;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use halo2_base::{
    AssignedValue, Context, ContextParams,
    QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
    gates::{
	GateInstructions,
	range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
	RangeInstructions},
    utils::fe_to_biguint,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error,
	    Expression, FirstPhase, Fixed, Instance, SecondPhase, Selector},
    poly::Rotation,
};

use eth_types::Field;

use crate::rlp::rlc::{
    log2, RlcChip, RlcTrace
};

// returns array whose first end_idx - start_idx cells are
//     array[start_idx..end_idx]
// and whose last cells are 0.
// These cells are witnessed but _NOT_ constrained
pub fn witness_subarray_from_idxs<'a, F: Field>(
    ctx: &mut Context<'_, F>,
    range: &RangeConfig<F>,
    array: &Vec<AssignedValue<F>>,
    start_idx: Value<F>,
    end_idx: Value<F>,
    max_len: usize,
) -> Result<Vec<AssignedValue<F>>, Error> {
    let val_vec = array.iter().map(|x| x.value().copied()).collect::<Vec<Value<F>>>();
    let vec_val: Value<Vec<F>> = Value::from_iter(val_vec);    
    let ret_vals = start_idx.zip(end_idx).zip(vec_val)
	.map(|((si, ei), vv)| {
	    let mut ret_vals = Vec::with_capacity(max_len);
	    for idx in 0..max_len {
		let val = {
		    if BigUint::from(idx) < fe_to_biguint(&(ei - si)) {
			vv[fe_to_biguint(&si).to_usize().unwrap() + idx].clone()
		    } else {
			F::from(0)
		    }
		};
		ret_vals.push(val);
	    }
	    ret_vals
	});
    let ret_val_witnesses = ret_vals.transpose_vec(max_len).iter().map(|v| Witness(*v)).collect();
    let ret = range.gate.assign_region_smart(
	ctx,
	ret_val_witnesses,
	vec![],
	vec![],
	vec![]
    )?;
    Ok(ret)
}

pub fn array_to_byte_val<'a, F: Field>(
    ctx: &mut Context<'_, F>,
    range: &RangeConfig<F>,
    array: &Vec<AssignedValue<F>>,
    len: &AssignedValue<F>,
) -> Result<AssignedValue<F>, Error> {
    let byte_val = {
	if array.len() > 0 {
	    let mut byte_val_vec = range.gate.accumulated_product(
		ctx,
		&vec![Constant(F::from(256)); array.len() - 1],
		&array.iter().map(|c| Existing(&c)).collect()
	    )?;
	    byte_val_vec.insert(0, byte_val_vec[0].clone());
	    let out = range.gate.select_from_idx(
		ctx,
		&byte_val_vec.iter().map(|c| Existing(&c)).collect(),
		&Existing(&len)
	    )?;
	    out
	} else {
	    let out = range.gate.assign_region_smart(
		ctx,
		vec![Constant(F::from(0))],
		vec![],
		vec![],
		vec![]
	    )?;
	    out[0].clone()
	}
    };
    Ok(byte_val)
}

#[derive(Clone, Debug)]
pub struct RlpFieldPrefixParsed<F: Field> {
    is_valid: AssignedValue<F>,
    is_literal: AssignedValue<F>,
    is_big: AssignedValue<F>,
    
    next_len: AssignedValue<F>,
    len_len: AssignedValue<F>,
    prefix: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayPrefixParsed<F: Field> {
    is_valid: AssignedValue<F>,
    is_empty: AssignedValue<F>,
    is_big: AssignedValue<F>,
    
    next_len: AssignedValue<F>,
    len_len: AssignedValue<F>,
    prefix: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct RlpFieldTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_trace: RlcTrace<F>,

    max_field_len: usize,
}

#[derive(Clone, Debug)]
pub struct RlpArrayTrace<F: Field> {
    pub array_trace: RlcTrace<F>,
    pub prefix: AssignedValue<F>,
    pub len_trace: RlcTrace<F>,
    pub field_prefixs: Vec<AssignedValue<F>>,
    pub field_len_traces: Vec<RlcTrace<F>>,
    pub field_traces: Vec<RlcTrace<F>>,

    max_field_lens: Vec<usize>,
    max_array_len: usize,
    num_fields: usize,
}

#[derive(Clone, Debug)]
pub struct RlpArrayChip<F: Field> {
    pub rlc: RlcChip<F>,
    pub range: RangeConfig<F>,
}

impl<F: Field> RlpArrayChip<F> {
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
	let rlc = RlcChip::configure(
	    meta,
	    num_basic_chips,
	    num_chips_fixed,
	    challenge_id,
	    context_id
	);
	let range = RangeConfig::configure(
	    meta,
	    range_strategy,
	    num_advice,
	    num_lookup_advice,
	    num_fixed,
	    lookup_bits,
	    "default".to_string()
	);
	Self {
	    rlc,
	    range
	}
    }

    pub fn parse_rlp_field_prefix(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	prefix: &AssignedValue<F>,
    ) -> Result<RlpFieldPrefixParsed<F>, Error> {
	let is_literal = range.is_less_than(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(128u64)),
	    8,
	)?;
	let is_len_or_literal = range.is_less_than(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(184u64)),
	    8,
	)?;
	let is_valid = range.is_less_than(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(192u64)),
	    8,
	)?;

	let field_len = range.gate.sub(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(128u64))
	)?;
	let len_len = range.gate.sub(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(183u64)),
	)?;

	let is_possibly_big = range.gate.not(
	    ctx,
	    &Existing(&is_len_or_literal)
	)?;
	let is_big = range.gate.and(
	    ctx,
	    &Existing(&is_valid),
	    &Existing(&is_possibly_big)
	)?;

	// length of the next RLP field
	let next_len = range.gate.select(
 	    ctx,
	    &Existing(&len_len),
	    &Existing(&field_len),
	    &Existing(&is_big)
	)?;

	let len_len_final = range.gate.mul(
	    ctx,
	    &Existing(&len_len),
	    &Existing(&is_big)
	)?;
	
	Ok(RlpFieldPrefixParsed {
		    is_valid,
	    is_literal,
	    is_big,
	    next_len,
	    len_len: len_len_final,
	    prefix: prefix.clone(),
	})
    }
    
    pub fn parse_rlp_array_prefix(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	prefix: &AssignedValue<F>,
    ) -> Result<RlpArrayPrefixParsed<F>, Error> {	
	let is_field = range.is_less_than(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(192u64)),
	    8,
	)?;
	let is_valid = range.gate.not(
	    ctx,
	    &Existing(&is_field)
	)?;
	
	let is_empty = range.is_equal(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(192u64))
	)?;
	let is_empty_or_small_array = range.is_less_than(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(248u64)),
	    8
	)?;

	let is_possibly_big = range.gate.not(
	    ctx,
	    &Existing(&is_empty_or_small_array)
	)?;
	let is_big = range.gate.and(
	    ctx,
	    &Existing(&is_possibly_big),
	    &Existing(&is_valid)
	)?;

	let array_len = range.gate.sub(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(192u64))
	)?;
	let len_len = range.gate.sub(
	    ctx,
	    &Existing(prefix),
	    &Constant(F::from(247u64)),
	)?;
	let next_len = range.gate.select(
 	    ctx,
	    &Existing(&len_len),
	    &Existing(&array_len),
	    &Existing(&is_big)
	)?;			

	let len_len_final = range.gate.mul(
	    ctx,
	    &Existing(&len_len),
	    &Existing(&is_big)
	)?;
	
	Ok(RlpArrayPrefixParsed {
	    is_valid,
	    is_empty,
	    is_big,
	    next_len,
	    len_len: len_len_final,
	    prefix: prefix.clone(),
	})
    }

    fn parse_rlp_len(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	rlp_cells: &Vec<AssignedValue<F>>,
	len_len: &AssignedValue<F>,
	max_len_len: usize,
    ) -> Result<(Vec<AssignedValue<F>>, AssignedValue<F>), Error> {
	let len_cells = witness_subarray_from_idxs(
	    ctx,
	    range,
	    rlp_cells,
	    Value::known(F::from(1)),
	    Value::known(F::from(1)) + len_len.value().copied(),
	    max_len_len
	)?;
	let len_byte_val = array_to_byte_val(ctx, range, &len_cells, &len_len)?;
	Ok((len_cells, len_byte_val))
    }
    
    pub fn decompose_rlp_field(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	rlp_field: &Vec<AssignedValue<F>>,
	max_field_len: usize,
    ) -> Result<RlpFieldTrace<F>, Error> {
 	let max_len_len = {
	    if max_field_len > 55 {
		(log2(max_field_len) + 7) / 8
	    } else {
		0
	    }
	};
	let max_rlp_field_len = 1 + max_len_len + max_field_len;
	assert_eq!(rlp_field.len(), max_rlp_field_len);
	
	let cache_bits = log2(max_rlp_field_len);
	let rlc_cache = self.rlc.load_rlc_cache(ctx, cache_bits)?;

	// TODO: Do len range checks
	
	// Witness consists of
	// * prefix_parsed
	// * len_rlc
	// * field_rlc
	// * rlp_field_rlc
	//
	// check that:
	// * len_rlc.rlc_len in [0, max_len_len]
	// * field_rlc.rlc_len in [0, max_field_len]
	// * rlp_field_rlc.rlc_len in [0, max_rlp_field_len]
	//
	// * rlp_field_rlc.rlc_len = 1 + len_rlc.rlc_len + field_rlc.rlc_len
	// * len_rlc.rlc_len = prefix_parsed.is_big * prefix_parsed.next_len
	// * field_rlc.rlc_len = prefix_parsed.is_big * prefix_parsed.next_len
	//                       + (1 - prefix_parsed.is_big) * byte_value(len)
	//
	// * rlp_field_rlc = accumulate(
	//                       [(prefix, 1),
	//                        (len_rlc.rlc_val, len_rlc.rlc_len),
	//                        (field_rlc.rlc_val, field_rlc.rlc_len)])

	let prefix = rlp_field[0].clone();
	let prefix_parsed = self.parse_rlp_field_prefix(ctx, range, &prefix)?;
		
	let len_len = prefix_parsed.len_len.clone();
	let (len_cells, len_byte_val) = self.parse_rlp_len(
	    ctx,
	    range,
	    &rlp_field,
	    &len_len,
	    max_len_len
	)?;
					    
	let field_len = range.gate.select(
	    ctx,
	    &Existing(&len_byte_val),
	    &Existing(&prefix_parsed.next_len),
	    &Existing(&prefix_parsed.is_big)
	)?;
	
	let field_cells = witness_subarray_from_idxs(
	    ctx,
	    range,
	    &rlp_field,
	    Value::known(F::from(1)) + len_len.value().copied(),
	    Value::known(F::from(1)) + len_len.value().copied() + field_len.value().copied(),
	    max_field_len,
	)?;
	
	let (_, _, rlp_len) = range.gate.inner_product(
	    ctx,
	    &vec![Constant(F::from(1)), Constant(F::from(1)), Constant(F::from(1))],
	    &vec![Constant(F::from(1)), Existing(&len_len), Existing(&field_len)],
	)?;
	
	let len_rlc = self.rlc.compute_rlc(ctx, range, &len_cells, len_len, max_len_len)?;	
	let field_rlc = self.rlc.compute_rlc(ctx, range, &field_cells, field_len, max_field_len)?;	
	let rlp_field_rlc = self.rlc.compute_rlc(ctx, range, rlp_field, rlp_len, max_rlp_field_len)?;
	let one_vec = self.rlc.assign_region_rlc(ctx, &vec![Constant(F::from(1))], vec![], vec![], None)?;
	let one = one_vec[0].clone();
	
	let concat_check = self.rlc.constrain_rlc_concat(
	    ctx,
	    range,
	    &vec![(prefix.clone(), one),
		 (len_rlc.rlc_val.clone(), len_rlc.rlc_len.clone()),
		 (field_rlc.rlc_val.clone(), field_rlc.rlc_len.clone())],
	    &vec![1, max_len_len, max_field_len],
	    (rlp_field_rlc.rlc_val.clone(), rlp_field_rlc.rlc_len.clone()),
	    rlp_field_rlc.max_len,
	    &rlc_cache
	)?;

	let parsed_rlp_field = RlpFieldTrace {
	    rlp_trace: rlp_field_rlc,
	    prefix,
	    len_trace: len_rlc,
	    field_trace: field_rlc,
	    max_field_len,
	};
	Ok(parsed_rlp_field)
    }
    
    pub fn decompose_rlp_array(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	rlp_array: &Vec<AssignedValue<F>>,
	max_field_lens: Vec<usize>,
	max_array_len: usize,
	num_fields: usize,
    ) -> Result<RlpArrayTrace<F>, Error> {
	let max_len_len = {
	    if max_array_len > 55 {
		(log2(max_array_len) + 7) / 8
	    } else {
		0
	    }
	};
	assert_eq!(rlp_array.len(), max_array_len);

	// Witness consists of
	// * prefix_parsed
	// * len_rlc
	// * field_rlcs: Vec<RlpFieldTrace>
	// * rlp_array_rlc
	//
	// check that:
	// * len_rlc.rlc_len in [0, max_len_len]
	// * field_rlcs[idx].rlc_len in [0, max_field_len[idx]]
	// * rlp_field_rlc.rlc_len in [0, max_rlp_field_len]
	//
	// * rlp_field_rlc.rlc_len = 1 + len_rlc.rlc_len + field_rlc.rlc_len
	// * len_rlc.rlc_len = prefix_parsed.is_big * prefix_parsed.next_len
	// * field_rlc.rlc_len = prefix_parsed.is_big * prefix_parsed.next_len
	//                       + (1 - prefix_parsed.is_big) * byte_value(len)
	//
	// * rlp_field_rlc = accumulate(
	//                       [(prefix, 1),
	//                        (len_rlc.rlc_val, len_rlc.rlc_len),
	//                        (field_rlc.rlc_val, field_rlc.rlc_len)])

	let prefix = rlp_array[0].clone();
	let prefix_parsed = self.parse_rlp_array_prefix(ctx, range, &prefix)?;
		
	let len_len = prefix_parsed.len_len.clone();
	let (len_cells, len_byte_val) = self.parse_rlp_len(
	    ctx,
	    range,
	    &rlp_array,
	    &len_len,
	    max_len_len
	)?;

	let all_fields_len = range.gate.select(
	    ctx,
	    &Existing(&len_byte_val),
	    &Existing(&prefix_parsed.next_len),
	    &Existing(&prefix_parsed.is_big)
	)?;

	let (_, _, rlp_len) = range.gate.inner_product(
	    ctx,
	    &vec![Constant(F::from(1)), Constant(F::from(1)), Constant(F::from(1))],
	    &vec![Constant(F::from(1)), Existing(&len_len), Existing(&all_fields_len)],
	)?;

	let mut prefix_vec = Vec::new();
	let mut prefix_idxs = Vec::new();
	
	let mut field_len_len_vec = Vec::new();
	let mut field_len_cells_vec = Vec::new();
	
	let mut field_len_vec = Vec::new();
	let mut field_cells_vec = Vec::new();
	let prefix_idx = range.gate.add(ctx, &Constant(F::from(1)), &Existing(&len_len))?;
	prefix_idxs.push(prefix_idx.clone());

	for idx in 0..num_fields {
	    let prefix = range.gate.select_from_idx(
		ctx,
		&rlp_array.iter().map(|x| Existing(&x)).collect(),
		&Existing(&prefix_idxs[idx])
	    )?;
	    prefix_vec.push(prefix.clone());
	    let prefix_parsed = self.parse_rlp_field_prefix(ctx, range, &prefix)?;

	    let len_len = prefix_parsed.len_len.clone();
	    let field_len_cells = witness_subarray_from_idxs(
		ctx,
		range,
		&rlp_array,
		prefix_idxs[idx].value().copied() + Value::known(F::from(1)),
		prefix_idxs[idx].value().copied() + Value::known(F::from(1)) + len_len.value().copied(),
		(log2(max_field_lens[idx]) + 7) / 8,			
	    )?;
	    let field_byte_val = array_to_byte_val(ctx, range, &field_len_cells, &len_len)?;
	    let field_len = range.gate.select(
		ctx,
		&Existing(&field_byte_val),
		&Existing(&prefix_parsed.next_len),
		&Existing(&prefix_parsed.is_big)
	    )?;
	    let field_cells = witness_subarray_from_idxs(
		ctx,
		range,
		&rlp_array,
		prefix_idxs[idx].value().copied() + Value::known(F::from(1)) + len_len.value().copied(),
		prefix_idxs[idx].value().copied() + Value::known(F::from(1)) + len_len.value().copied() + field_len.value().copied(),
		max_field_lens[idx]
	    )?;

	    field_len_len_vec.push(len_len.clone());
	    field_len_cells_vec.push(field_len_cells);
	    field_len_vec.push(field_len.clone());
	    field_cells_vec.push(field_cells);			
	    
	    if idx < num_fields - 1 {
		let (_, _, next_prefix_idx) = range.gate.inner_product(
		    ctx,
		    &vec![Constant(F::from(1)), Constant(F::from(1)), Constant(F::from(1)), Constant(F::from(1))],
		    &vec![Existing(&prefix_idxs[idx]), Existing(&len_len), Existing(&field_len), Constant(F::from(1))],
		)?;
		prefix_idxs.push(next_prefix_idx);
	    }
	}
	
	let len_rlc = self.rlc.compute_rlc(ctx, range, &len_cells, len_len.clone(), max_len_len)?;
	
	let mut field_len_rlcs = Vec::new();
	let mut field_cells_rlcs = Vec::new();
	for idx in 0..num_fields {
	    let field_len_rlc = self.rlc.compute_rlc(
		ctx,
		range,
		&field_len_cells_vec[idx],
		field_len_len_vec[idx].clone(),
		(log2(max_field_lens[idx]) + 7) / 8,
	    )?;
	    let field_cells_rlc = self.rlc.compute_rlc(
		ctx,
		range,
		&field_cells_vec[idx],
		field_len_vec[idx].clone(),
		max_field_lens[idx]
	    )?;
	    field_len_rlcs.push(field_len_rlc);
	    field_cells_rlcs.push(field_cells_rlc);
	}
	let rlp_rlc = self.rlc.compute_rlc(ctx, range, &rlp_array, rlp_len, max_array_len)?;
	let one_vec = self.rlc.assign_region_rlc(ctx, &vec![Constant(F::from(1))], vec![], vec![], None)?;
	let one = one_vec[0].clone();

	let rlc_cache = self.rlc.load_rlc_cache(ctx, log2(max_array_len))?;
	
	let mut max_lens = vec![1, max_len_len];
	let mut rlc_and_len_inputs = vec![
	    (prefix.clone(), one.clone()),
	    (len_rlc.rlc_val.clone(), len_rlc.rlc_len.clone())
	];
	for idx in 0..num_fields {
	    max_lens.extend(vec![1, (log2(max_field_lens[idx]) + 7) / 8, max_field_lens[idx]]);
	    rlc_and_len_inputs.extend(vec![
		(prefix_vec[idx].clone(), one.clone()),
		(field_len_rlcs[idx].rlc_val.clone(), field_len_rlcs[idx].rlc_len.clone()),
		(field_cells_rlcs[idx].rlc_val.clone(), field_cells_rlcs[idx].rlc_len.clone()),
	    ]);
	}
	
	let concat_check = self.rlc.constrain_rlc_concat(
	    ctx,
	    range,
	    &rlc_and_len_inputs,
	    &max_lens,
	    (rlp_rlc.rlc_val.clone(), rlp_rlc.rlc_len.clone()),
	    max_array_len,
	    &rlc_cache
	)?;
		
	let parsed_rlp_array = RlpArrayTrace {
	    array_trace: rlp_rlc,
	    prefix,
	    len_trace: len_rlc,
	    field_prefixs: prefix_vec,
	    field_len_traces: field_len_rlcs,
	    field_traces: field_cells_rlcs,
	    max_field_lens,
	    max_array_len,
	    num_fields,
	};	
	Ok(parsed_rlp_array)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RlpTestCircuit<F> {
    inputs: Vec<u8>,
    max_len: usize,
    max_field_lens: Vec<usize>,
    is_array: bool,
    num_fields: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for RlpTestCircuit<F> {
    type Config = RlpArrayChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
	Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
	RlpArrayChip::configure(
	    meta,
	    1,
	    1,
	    "gamma".to_string(),
	    "rlc".to_string(),
	    Vertical,
	    &[1],
	    &[0],
	    1,
	    10		    
	)
    }

    fn synthesize(
	&self,
	config: Self::Config,
	mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
	config.range.load_lookup_table(&mut layouter)?;
	
	let gamma = layouter.get_challenge(config.rlc.gamma);
	let using_simple_floor_planner = true;
	let mut first_pass = true;	   
	let ok = layouter.assign_region(
	    || "RLP test",
	    |mut region| {
		if first_pass && using_simple_floor_planner { first_pass = false; }		
		let mut aux = Context::new(
		    region,
		    ContextParams { num_advice: vec![
			("default".to_string(), config.range.gate.num_advice),
			("rlc".to_string(), config.rlc.basic_chips.len())
		    ] }
		);
		let ctx = &mut aux;
		ctx.challenge.insert("gamma".to_string(), gamma);
		
		let inputs_assigned = config.range.gate.assign_region_smart(
		    ctx,
		    self.inputs.iter().map(|x| Witness(Value::known(F::from(*x as u64)))).collect(),
		    vec![],
		    vec![],
		    vec![]
		)?;

		if self.is_array {
		    let rlp_array_trace = config.decompose_rlp_array(
			ctx,
			&config.range,
			&inputs_assigned,
			self.max_field_lens.clone(),
			self.max_len,
			self.num_fields
		    )?;
		} else {
		    let rlp_field_trace = config.decompose_rlp_field(
			ctx,
			&config.range,
			&inputs_assigned,
			self.max_len,
		    )?;
		}

		let stats = config.range.finalize(ctx)?;
		Ok(())
	    }
	)?;

	Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use std::marker::PhantomData;
    use halo2_proofs::{
	dev::{MockProver},
	halo2curves::bn256::Fr,
    };
    use crate::rlp::{
	rlc::log2,
	rlp::RlpTestCircuit,	
    };

    #[test]
    pub fn test_mock_rlp_array() {
	let k = 18;
	let input_bytes: Vec<u8> = Vec::from_hex("f8408d123000000000000000000000028824232222222222238b32222222222222222412528a04233333333333332322912323333333333333333333333333333333000000").unwrap();
	    
	let circuit = RlpTestCircuit::<Fr> {
	    inputs: input_bytes,
	    max_len: 69,
	    max_field_lens: vec![15, 9, 11, 10, 17],
	    is_array: true,
	    num_fields: 5,
	    _marker: PhantomData
	};
	let prover_try = MockProver::run(k, &circuit, vec![]);
	let prover = prover_try.unwrap();
	prover.assert_satisfied();
	assert_eq!(prover.verify(), Ok(()));
    }
    
    #[test]
    pub fn test_mock_rlp_field() {
	let k = 18;
	let input_bytes: Vec<u8> = Vec::from_hex("a012341234123412341234123412341234123412341234123412341234123412340000").unwrap();
	    
	let circuit = RlpTestCircuit::<Fr> {
	    inputs: input_bytes,
	    max_len: 34,
	    max_field_lens: vec![],
	    is_array: false,
	    num_fields: 0,
	    _marker: PhantomData
	};
	let prover_try = MockProver::run(k, &circuit, vec![]);
	let prover = prover_try.unwrap();
	prover.assert_satisfied();
	assert_eq!(prover.verify(), Ok(()));
    }
    
    #[test]
    pub fn test_mock_rlp_long_field() {
	let k = 18;
	let input_bytes: Vec<u8> = Vec::from_hex("a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap();

	let circuit = RlpTestCircuit::<Fr> {
	    inputs: input_bytes,
	    max_len: 60,
	    max_field_lens: vec![],
	    is_array: false,
	    num_fields: 0,
	    _marker: PhantomData
	};
	let prover_try = MockProver::run(k, &circuit, vec![]);
	let prover = prover_try.unwrap();
	prover.assert_satisfied();
	assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    pub fn test_mock_rlp_long_long_field() {
	let k = 18;
	let input_bytes: Vec<u8> = Vec::from_hex("b83adb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap();

	let circuit = RlpTestCircuit::<Fr> {
	    inputs: input_bytes,
	    max_len: 60,
	    max_field_lens: vec![],
	    is_array: false,
	    num_fields: 0,
	    _marker: PhantomData
	};
	let prover_try = MockProver::run(k, &circuit, vec![]);
	let prover = prover_try.unwrap();
	prover.assert_satisfied();
	assert_eq!(prover.verify(), Ok(()));
    }
}
