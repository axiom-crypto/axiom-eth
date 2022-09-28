use std::marker::PhantomData;
use halo2_ecc::{
    gates::{
	Context, ContextParams,
	GateInstructions,
	QuantumCell::{Constant, Existing, Witness},
	range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
	RangeInstructions},
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
    RlcChip, RlcTrace
};

#[derive(Clone, Debug)]
pub struct RlpFieldPrefixParsed<F: Field> {
    is_valid: AssignedCell<F, F>,
    is_literal: AssignedCell<F, F>,
    is_big: AssignedCell<F, F>,
    
    next_len: AssignedCell<F, F>,
    prefix: AssignedCell<F, F>,
}

#[derive(Clone, Debug)]
pub struct RlpArrayPrefixParsed<F: Field> {
    is_valid: AssignedCell<F, F>,
    is_empty: AssignedCell<F, F>,
    is_big: AssignedCell<F, F>,
    
    next_len: AssignedCell<F, F>,
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
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	prefix: &AssignedCell<F, F>,
    ) -> Result<RlpFieldPrefixParsed<F>, Error> {
	let using_simple_floor_planner = true;
	let mut first_pass = true;
	let parsed_field_prefix = layouter.assign_region(
	    || "RLP field prefix",
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
		
		let stats = range.finalize(ctx)?;
		println!("RLP field prefix stats: {:?}", stats);
		Ok(RlpFieldPrefixParsed {
		    is_valid,
		    is_literal,
		    is_big,
		    next_len,
		    prefix: prefix.clone(),
		})
	    }
	)?;
	Ok(parsed_field_prefix)
    }
    
    pub fn parse_rlp_array_prefix(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	prefix: &AssignedCell<F, F>,
    ) -> Result<RlpArrayPrefixParsed<F>, Error> {	
	let using_simple_floor_planner = true;
	let mut first_pass = true;
	let parsed_array_prefix = layouter.assign_region(
	    || "RLP array prefix",
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
		
		let stats = range.finalize(ctx)?;
		println!("RLP array prefix stats: {:?}", stats);
		Ok(RlpArrayPrefixParsed {
		    is_valid,
		    is_empty,
		    is_big,
		    next_len,
		    prefix: prefix.clone(),
		})
	    }
	)?;
	Ok(parsed_array_prefix)
    }

    pub fn decompose_rlp_field(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	rlp_field: &Vec<AssignedCell<F, F>>,
	min_field_len: usize,
	max_field_len: usize,
    ) -> Result<RlpFieldTrace<F>, Error> {
	assert_eq!(rlp_field.len(), max_field_len);
	
	let using_simple_floor_planner = true;
	let mut first_pass = true;
	let parsed_rlp_field = layouter.assign_region(
	    || "RLP array prefix",
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

		let prefix = rlp_field[0].clone();
		

		let stats = range.finalize(ctx)?;
		println!("RLP field stats: {:?}", stats);
		todo!();
//		Ok(RlpFieldTrace {
//		    rlp_trace,
//		    prefix,
//		    len_trace,
//		    field_trace,
//		    min_field_len,
//		    max_field_len,
//		})		
	    }
	)?;
	Ok(parsed_rlp_field)
    }
    
    pub fn decompose_rlp_array(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
    ) -> Result<RlpArrayTrace<F>, Error> {
	todo!();
    }
}

#[cfg(test)]
mod tests {

    #[test]
    pub fn test_mock_rlp() {

    }
}
