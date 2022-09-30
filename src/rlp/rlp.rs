use std::cmp::max;
use std::marker::PhantomData;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use halo2_ecc::{
    gates::{
	Context, ContextParams,
	GateInstructions,
	QuantumCell::{Constant, Existing, Witness},
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

#[derive(Clone, Debug)]
pub struct RlpFieldPrefixParsed<F: Field> {
    is_valid: AssignedCell<F, F>,
    is_literal: AssignedCell<F, F>,
    is_big: AssignedCell<F, F>,
    
    next_len: AssignedCell<F, F>,
    len_len: AssignedCell<F, F>,
    prefix: AssignedCell<F, F>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayPrefixParsed<F: Field> {
    is_valid: AssignedCell<F, F>,
    is_empty: AssignedCell<F, F>,
    is_big: AssignedCell<F, F>,
    
    next_len: AssignedCell<F, F>,
    len_len: AssignedCell<F, F>,
    prefix: AssignedCell<F, F>,
}

#[derive(Clone, Debug)]
pub struct RlpFieldTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    prefix: AssignedCell<F, F>,
    len_trace: RlcTrace<F>,
    field_trace: RlcTrace<F>,

    min_field_len: usize,
    max_field_len: usize,
}

#[derive(Clone, Debug)]
pub struct RlpArrayTrace<F: Field> {
    array_trace: RlcTrace<F>,
    prefix: AssignedCell<F, F>,
    len_trace: RlcTrace<F>,
    field_traces: Vec<RlpFieldTrace<F>>,

    min_field_lens: Vec<usize>,
    max_field_lens: Vec<usize>,
    max_array_len: usize,
    num_fields: usize,
}

#[derive(Clone, Debug)]
pub struct RlpArrayChip<F: Field> {
    rlc: RlcChip<F>,
    range: RangeConfig<F>,
}

impl<F: Field> RlpArrayChip<F> {
    pub fn configure(
	meta: &mut ConstraintSystem<F>,
        range_strategy: RangeStrategy,
        num_advice: usize,
        mut num_lookup_advice: usize,
        num_fixed: usize,
        lookup_bits: usize,
    ) -> Self {
	let rlc = RlcChip::configure(meta);
	let range = RangeConfig::configure(
	    meta,
	    range_strategy,
	    num_advice,
	    num_lookup_advice,
	    num_fixed,
	    lookup_bits
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
	prefix: &AssignedCell<F, F>,
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
	    &Constant(F::from(184u64)),
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
	prefix: &AssignedCell<F, F>,
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
	    &Constant(F::from(248u64)),
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
	
	let stats = range.finalize(ctx)?;
	println!("RLP array prefix stats: {:?}", stats);
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
	rlp_cells: &Vec<AssignedCell<F, F>>,
	len_len: &AssignedCell<F, F>,
	max_len_len: usize,
    ) -> Result<(Vec<AssignedCell<F, F>>, AssignedCell<F, F>), Error> {
	let mut len_vals = Vec::new();
	for idx in 0..max_len_len {
	    let len_val = len_len.value()
		.zip(rlp_cells[1 + idx].value())
		.map(|(l, r)| {
		    if BigUint::from(idx) < fe_to_biguint(l) {
			r.clone()
		    } else {
			F::from(0)
		    }
		});
	    len_vals.push(Witness(len_val));
	}
	let len_cells = range.gate.assign_region_smart(
	    ctx,
	    len_vals,
	    vec![],
	    vec![],
	    vec![]
	)?;
	let len_byte_val = {
	    if len_cells.len() > 0 {
		let len_cells_byte_val_vec = range.gate.accumulated_product(
		    ctx,
		    &vec![Constant(F::from(8)); len_cells.len() - 1],
		    &len_cells.iter().map(|c| Existing(&c)).collect()
		)?;
		
		let out = range.gate.select_from_idx(
		    ctx,
		    &len_cells_byte_val_vec.iter().map(|c| Existing(&c)).collect(),
		    &Existing(&len_len)
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
					    
	Ok((len_cells, len_byte_val))
    }
    
    pub fn decompose_rlp_field(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	rlp_field: &Vec<AssignedCell<F, F>>,
	min_field_len: usize,
	max_field_len: usize,
    ) -> Result<RlpFieldTrace<F>, Error> {
	let max_field_bytes = (log2(max_field_len) + 2) / 3;
 	let max_len_len = {
	    if max_field_bytes > 55 {
		max_field_bytes
	    } else {
		0
	    }
	};
	let max_rlp_field_len = 1 + max_len_len + max_field_len;
	assert_eq!(rlp_field.len(), max_rlp_field_len);
	
	let cache_bits = log2(max_rlp_field_len);
	let rlc_cache = self.rlc.load_rlc_cache(
	    layouter,
	    cache_bits
	)?;

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

	let using_simple_floor_planner = true;
	let mut first_pass = true;	
	let (len_cells, len_len, field_cells, field_len, rlp_len) = layouter.assign_region(
	    || "assign witness cells",
	    |mut region| {
		if first_pass && using_simple_floor_planner {
		    first_pass = false;
		}
		
		let mut aux = Context::new(
		    region,
		    ContextParams {
			num_advice: range.gate.num_advice,
			using_simple_floor_planner,
			first_pass,
		    },
		);
		let ctx = &mut aux;

		let prefix_parsed = self.parse_rlp_field_prefix(
		    ctx,
		    range,
		    &prefix
		)?;
		
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

		let mut field_vals = Vec::with_capacity(max_field_len);
		for idx in 0..max_field_len {
		    let val_vec = rlp_field.iter().map(|x| x.value().copied()).collect::<Vec<Value<F>>>();
		    let vec_val: Value<Vec<F>> = Value::from_iter(val_vec);
		    let field_val = field_len.value()
			.zip(len_len.value())
			.zip(vec_val)
			.map(|((fl, ll), rf)| {
			    if BigUint::from(idx) < fe_to_biguint(fl) {
				rf[1 + fe_to_biguint(ll).to_usize().unwrap() + idx].clone()
			    } else {
				F::from(0)
			    }
			});
		    field_vals.push(Witness(field_val));
		}
		let field_cells = range.gate.assign_region_smart(
		    ctx,
		    field_vals,
		    vec![],
		    vec![],
		    vec![]
		)?;

		let (_, _, rlp_len, _) = range.gate.inner_product(
		    ctx,
		    &vec![Constant(F::from(1)), Constant(F::from(1)), Constant(F::from(1))],
		    &vec![Constant(F::from(1)), Existing(&len_len), Existing(&field_len)],
		)?;

		let stats = range.finalize(ctx)?;
		println!("stats: {:?}", stats);
		Ok((len_cells, len_len, field_cells, field_len, rlp_len))
	    }
	)?;
	
	let len_rlc = self.rlc.compute_rlc(
	    layouter,
	    range,
	    &len_cells,
	    len_len,
	    max_len_len,
	)?;
	
	let field_rlc = self.rlc.compute_rlc(
	    layouter,
	    range,
	    &field_cells,
	    field_len,
	    max_field_len,
	)?;
	
	let rlp_field_rlc = self.rlc.compute_rlc(
	    layouter,
	    range,
	    rlp_field,
	    rlp_len,
	    max_rlp_field_len,
	)?;

	let one = layouter.assign_region(
	    || "one",
	    |mut region| {
		let one = region.assign_advice(
		    || "one",
		    self.rlc.val,
		    0,
		    || Value::known(F::from(1))
		)?;
		region.constrain_constant(one.cell(), F::from(1))?;
		Ok(one)
	    }
	)?;

	let concat_check = self.rlc.constrain_rlc_concat(
	    layouter,
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
	    min_field_len,
	    max_field_len,
	};
	Ok(parsed_rlp_field)
    }
    
    pub fn decompose_rlp_array(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	rlp_array: &Vec<AssignedCell<F, F>>,
	min_field_lens: Vec<usize>,
	max_field_lens: Vec<usize>,
	max_array_len: usize,
	num_fields: usize,
    ) -> Result<RlpArrayTrace<F>, Error> {
	let max_array_bytes = (log2(max_array_len) + 2) / 3;
	let max_len_len = {
	    if max_array_bytes > 55 {
		max_array_bytes
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
	//

	let prefix = rlp_array[0].clone();

	let using_simple_floor_planner = true;
	let mut first_pass = true;	
	let (len_cells, len_len, all_fields_len, rlp_len) = layouter.assign_region(
	    || "assign witness cells",
	    |mut region| {
		if first_pass && using_simple_floor_planner {
		    first_pass = false;
		}
		let mut aux = Context::new(
		    region,
		    ContextParams {
			num_advice: range.gate.num_advice,
			using_simple_floor_planner,
			first_pass,
		    },
		);
		let ctx = &mut aux;

		let prefix_parsed = self.parse_rlp_array_prefix(
		    ctx,
		    range,
		    &prefix
		)?;
		
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

		let (_, _, rlp_len, _) = range.gate.inner_product(
		    ctx,
		    &vec![Constant(F::from(1)), Constant(F::from(1)), Constant(F::from(1))],
		    &vec![Constant(F::from(1)), Existing(&len_len), Existing(&all_fields_len)],
		)?;

		let mut field_cells_vec = Vec::new();
		let mut field_len_vec = Vec::new();

		let mut prefix_idxs = Vec::new();
		let prefix_idx = range.gate.add(ctx, &Constant(F::from(1)), &Existing(&len_len))?;
		prefix_idxs.push(prefix_idx);

		for idx in 0..num_fields {
		    let prefix = range.gate.select_from_idx(
			ctx,
			rlp_array,
			prefix_idxs[idx]
		    )?;

		    // TODO: Need to do selection
		    
		    let field_trace = self.decompose_rlp_field(
			layouter,
			range,
			rlp_array,
			min_field_lens[idx],
			max_field_lens[idx]
		    )?;	
		}

		let stats = range.finalize(ctx)?;
		Ok((len_cells, len_len, all_fields_len, rlp_len))
	    }
	)?;


	todo!();

	let parsed_rlp_array = RlpArrayTrace {
	    
	};	
	Ok(parsed_rlp_array)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RlpTestCircuit<F> {
    inputs: Vec<u8>,
    min_len: usize,
    max_len: usize,
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
	    Vertical,
	    1,
	    0,
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

	let using_simple_floor_planner = true;
	let mut first_pass = true;	   
	let inputs_assigned = layouter.assign_region(
	    || "load_inputs",
	    |mut region| {
		if first_pass && using_simple_floor_planner {
		    first_pass = false;
		}
		
		let mut aux = Context::new(
		    region,
		    ContextParams {
			num_advice: config.range.gate.num_advice,
			using_simple_floor_planner,
			first_pass,
		    },
		);
		let ctx = &mut aux;
		
		let inputs_assigned = config.range.gate.assign_region_smart(
		    ctx,
		    self.inputs.iter().map(|x| Witness(Value::known(F::from(*x as u64)))).collect(),
		    vec![],
		    vec![],
		    vec![]
		)?;
		let stats = config.range.finalize(ctx)?;
		Ok(inputs_assigned)
	    }
	)?;
	
	let rlp_field_trace = config.decompose_rlp_field(
	    &mut layouter,
	    &config.range,
	    &inputs_assigned,
	    self.min_len,
	    self.max_len,
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
    pub fn test_mock_rlp_field() {
	let k = 18;
	let input_bytes: Vec<u8> = Vec::from_hex("a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000").unwrap();

	let circuit = RlpTestCircuit::<Fr> {
	    inputs: input_bytes,
	    min_len: 0,
	    max_len: 34,
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
	let input_bytes: Vec<u8> = Vec::from_hex("a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df00000000000000000000000000000000000000000000000000000000").unwrap();

	let circuit = RlpTestCircuit::<Fr> {
	    inputs: input_bytes,
	    min_len: 0,
	    max_len: 60,
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
	let input_bytes: Vec<u8> = Vec::from_hex("813adb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df00000000000000000000000000000000000000000000000000000000").unwrap();

	let circuit = RlpTestCircuit::<Fr> {
	    inputs: input_bytes,
	    min_len: 0,
	    max_len: 60,
	    _marker: PhantomData
	};
	let prover_try = MockProver::run(k, &circuit, vec![]);
	let prover = prover_try.unwrap();
	prover.assert_satisfied();
	assert_eq!(prover.verify(), Ok(()));
    }
}
