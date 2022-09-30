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

pub fn compute_rlc<F: Field>(msg: &Vec<u8>, r: F) -> F {
    let mut coeff = r;
    let mut rlc = F::from(msg[0] as u64);
    for val in msg[1..].iter() {
	rlc = rlc + F::from(*val as u64) * coeff;
	coeff = coeff * r;
    }
    rlc
}

pub fn compute_rlc_acc<F: Field>(msg: &Vec<u8>, r: F) -> F {
    let mut rlc = F::from(msg[0] as u64);
    for val in msg[1..].iter() {
	rlc = rlc * r + F::from(*val as u64);
    }
    rlc
}

pub fn log2(x: usize) -> usize {
    let mut log = 0;
    let mut y = x;
    while y > 0 {
	y = y / 2;
	log = log + 1;
    }
    return log;
}

#[derive(Clone, Debug)]
pub struct RlcTrace<F: Field> {
    pub rlc_val: AssignedCell<F, F>,
    pub rlc_len: AssignedCell<F, F>,
    pub max_len: usize,
}

#[derive(Clone, Debug)]
pub struct RlcChip<F> {
    pub val: Column<Advice>,
    rlc: Column<Advice>,
    q_rlc: Selector,
    q_mul: Selector,
    cons: Column<Fixed>,
    gamma: Challenge,

    _marker: PhantomData<F>
}

impl<F: Field> RlcChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
	let q_rlc = meta.selector();
	let q_mul = meta.selector();
	let cons = meta.fixed_column();
	let val = meta.advice_column();
	let rlc = meta.advice_column_in(SecondPhase);
	let [gamma] = [(); 1].map(|_| meta.challenge_usable_after(FirstPhase));

	meta.enable_equality(val);
	meta.enable_equality(rlc);
	meta.enable_equality(cons);
	meta.enable_constant(cons);
	
	meta.create_gate("RLC computation", |meta| {
	    let sel = meta.query_selector(q_rlc);
	    let val = meta.query_advice(val, Rotation::cur());
	    let rlc_curr = meta.query_advice(rlc, Rotation::cur());
	    let rlc_prev = meta.query_advice(rlc, Rotation::prev());
	    let [gamma] = [gamma].map(|challenge| meta.query_challenge(challenge));
	    
	    vec![sel * (rlc_prev * gamma + val - rlc_curr)]
	});

	meta.create_gate("RLC mul", |meta| {
	    let sel = meta.query_selector(q_mul);
	    let a = meta.query_advice(rlc, Rotation::cur());
	    let b = meta.query_advice(rlc, Rotation(1));
	    let c = meta.query_advice(rlc, Rotation(2));
	    let d = meta.query_advice(rlc, Rotation(3));

	    vec![sel * (a + b * c - d)]
	});

	let config = Self {
	    val,
	    rlc,
	    q_rlc,
	    q_mul,
	    cons,
	    gamma,
	    _marker: PhantomData
	};

	config
    }

    // assumes 0 <= len <= max_len
    pub fn compute_rlc(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	input: &Vec<AssignedCell<F, F>>,
	len: AssignedCell<F, F>,
	max_len: usize,
    ) -> Result<RlcTrace<F>, Error> {
	assert!(input.len() == max_len);

	let gamma = layouter.get_challenge(self.gamma);
	let rlc_cells = layouter.assign_region(
	    || "RLC array",
	    |mut region| {
		let mut rlc_cells = Vec::with_capacity(max_len);
		let mut running_rlc = Value::known(F::from(0));
		for (idx, val) in input.iter().enumerate() {
		    let val_assigned = val.copy_advice(
			|| "RLC input",
			&mut region,
			self.val,
			idx,
		    )?;

		    running_rlc = running_rlc * gamma + val.value();
		    let rlc_assigned = region.assign_advice(
			|| "RLC compute",
			self.rlc,
			idx,
			|| running_rlc
		    )?;
		    rlc_cells.push(rlc_assigned.clone());

		    if idx == 0 {
			region.constrain_equal(rlc_assigned.cell(), val_assigned.cell())?;
		    } else {
			self.q_rlc.enable(&mut region, idx)?;
		    }
		}
		Ok(rlc_cells)
	    }
	)?;

	let using_simple_floor_planner = true;
	let mut first_pass = true;	
	let (idx, is_zero) = layouter.assign_region(
	    || "idx val",
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

		let is_zero = range.is_zero(ctx, &len)?;
		let len_minus_one = range.gate.sub(ctx, &Existing(&len), &Constant(F::from(1)))?;
		let idx = range.gate.select(
		    ctx,
		    &Constant(F::from(0)),
		    &Existing(&len_minus_one),
		    &Existing(&is_zero)
		)?;
		let stats = range.finalize(ctx)?;
		println!("stats: {:?}", stats);
		Ok((idx, is_zero))
	    }
	)?;
	
	let rlc_val_pre = self.select_from_cells(layouter, range, &rlc_cells, &idx)?;

	// | rlc_val | is_zero | rlc_val_pre | rlc_val_pre |
	let rlc_val = layouter.assign_region(
	    || "idx val",
	    |mut region| {		
		let rlc_val = region.assign_advice(
		    || "rlc_val",
		    self.rlc,
		    0,
		    || rlc_val_pre.value().copied() * (Value::known(F::from(1)) - is_zero.value())
		)?;
		is_zero.copy_advice(
		    || "is_zero_copy",
		    &mut region,
		    self.rlc,		    
		    1
		)?;
		rlc_val_pre.copy_advice(
		    || "rlc_val_pre_copy",
		    &mut region,
		    self.rlc,
		    2
		)?;
		rlc_val_pre.copy_advice(
		    || "rlc_val_pre_copy 2",
		    &mut region,
		    self.rlc,
		    3
		)?;
		self.q_mul.enable(&mut region, 0)?;
		Ok(rlc_val)
	    }
	)?;
	
	let rlc_trace = RlcTrace {
	    rlc_val: rlc_val,
	    rlc_len: len,
	    max_len: max_len,
	};
	Ok(rlc_trace)
    }

    pub fn select_from_cells(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	cells: &Vec<AssignedCell<F, F>>,
	idx: &AssignedCell<F, F>,	
    ) -> Result<AssignedCell<F, F>, Error> {
	let using_simple_floor_planner = true;
	let mut first_pass = true;
	let ind_vec = layouter.assign_region(
	    || "select_from_cells",
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
		let ind_vec = range.gate.idx_to_indicator(ctx, &Existing(&idx), cells.len())?;
		let stats = range.finalize(ctx)?;
		println!("stats: {:?}", stats);
		Ok(ind_vec)
	    }	    
	)?;

	let res = layouter.assign_region(
	    || "dot product",
	    |mut region| {
		let mut acc_vec = Vec::with_capacity(cells.len());
		for (idx, (cell, ind)) in cells.iter().zip(ind_vec.iter()).enumerate() {
		    if idx == 0 {
			let zero = region.assign_advice(
			    || "zero",
			    self.rlc,
			    0,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			acc_vec.push(zero);
		    }
		    cell.copy_advice(|| "cell copy", &mut region, self.rlc, 3 * idx + 1)?;
		    ind.copy_advice(|| "ind copy", &mut region, self.rlc, 3 * idx + 2)?;
		    let acc_new = region.assign_advice(|| "acc", self.rlc, 3 * idx + 3,
						       || acc_vec[acc_vec.len() - 1].value()
						       .zip(cell.value()).zip(ind.value())
						       .map(|((x, y), z)| (*x) + (*y) * (*z)))?;
		    acc_vec.push(acc_new);			
		}
		Ok(acc_vec[acc_vec.len() - 1].clone())
	    }
	)?;
	Ok(res)
    }
    
    // Define the dynamic RLC: RLC(a, l) = \sum_{i = 0}^{l - 1} a_i r^{l - 1 - i}
    // * We have that:
    //     RLC(a || b, l_a + l_b) = RLC(a, l_a) * r^{l_a} + RLC(b, l_b).
    // * Prop: For sequences b^1, \ldots, b^k with l(b^i) = l_i and
    //     RLC(a, l) = RLC(b^1, l_1) * r^{l_1 + ... + l_{k - 1}}
    //                 + RLC(b^2, l_2) * r^{l_2 + ... + l_{k - 1}}
    //                 ... + RLC(b^k, l_k), and
    //     l = l_1 + ... + l_k, 
    //   then a = b^1 || ... || b^k.
    // * Pf: View both sides as polynomials in r.
    //
    // Assumes:
    // * each tuple of the input is (RLC(a, l), l) for some sequence a_i of length l
    // * all rlc_len values have been range checked
    pub fn constrain_rlc_concat(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	rlc_and_len_inputs: &Vec<(AssignedCell<F, F>, AssignedCell<F, F>)>,
	max_lens: &Vec<usize>,
	concat: (AssignedCell<F, F>, AssignedCell<F, F>),
	max_len: usize,
	rlc_cache: &Vec<AssignedCell<F, F>>,
    ) -> Result<(), Error> {
	assert!(rlc_cache.len() >= log2(max_len));
	assert!(rlc_cache.len() >= log2(*max_lens.iter().max().unwrap()));
	
	let using_simple_floor_planner = true;
	let mut first_pass = true;	
	let res = layouter.assign_region(
	    || "len check",
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

		let (_, _, len_sum, _) = range.gate.inner_product(
		    ctx,
		    &rlc_and_len_inputs.iter().map(|(a, b)| Constant(F::from(1))).collect(),
		    &rlc_and_len_inputs.iter().map(|(a, b)| Existing(&b)).collect(),
		)?;

		range.gate.assert_equal(
		    ctx,
		    &Existing(&len_sum),
		    &Existing(&concat.1)
		)?;

		let stats = range.finalize(ctx)?;
		println!("stats: {:?}", stats);
		Ok(())
	    }
	)?;

	let mut gamma_pows = Vec::new();
	for (idx, (rlc, len)) in rlc_and_len_inputs.iter().enumerate() {
	    let gamma_pow = self.rlc_pow(
		layouter,
		range,
		len.clone(),
		log2(max_lens[idx]),
		&rlc_cache
	    )?;
	    gamma_pows.push(gamma_pow);
	}
	
	let rlc_concat = layouter.assign_region(
	    || "rlc_concat",
	    |mut region| {
		let mut intermed = Vec::new();
		for idx in 0..rlc_and_len_inputs.len() {
		    let rlc = rlc_and_len_inputs[idx].0.clone();
		    let gamma_pow = gamma_pows[idx].clone();

		    if idx == 0 {
			let zero = region.assign_advice(
			    || "zero",
			    self.rlc,
			    0,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			let rlc_copy = rlc.copy_advice(
			    || "rlc_copy",
			    &mut region,
			    self.rlc,
			    1
			)?;
			let gamma_pow_copy = gamma_pow.copy_advice(
			    || "gamma_pow_copy",
			    &mut region,
			    self.rlc,
			    2
			)?;
			let prod = region.assign_advice(
			    || "prod",
			    self.rlc,
			    3,
			    || rlc.value().zip(gamma_pow.value()).map(|(a, b)| (*a) * (*b))
			)?;
			self.q_mul.enable(&mut region, 0)?;
			intermed.push(prod);
		    } else {
			let rlc_copy = rlc.copy_advice(
			    || "rlc_copy",
			    &mut region,
			    self.rlc,
			    4 * idx
			)?;
			let prev_prod_copy = intermed[intermed.len() - 1].copy_advice(
			    || "prev_prod_copy",
			    &mut region,
			    self.rlc,
			    4 * idx + 1
			)?;
			let gamma_pow_copy = gamma_pow.copy_advice(
			    || "gamma_pow_copy",
			    &mut region,
			    self.rlc,
			    4 * idx + 2
			)?;
			let prod = region.assign_advice(
			    || "prod",
			    self.rlc,
			    4 * idx + 3,
			    || rlc.value().zip(gamma_pow.value())
				.zip(prev_prod_copy.value())
				.map(|((a, b), c)| (*a) + (*b) * (*c))
			)?;
			self.q_mul.enable(&mut region, 4 * idx)?;
			intermed.push(prod);
		    }		    
		}

		let zero = region.assign_advice(
		    || "zero",
		    self.rlc,
		    4 * rlc_and_len_inputs.len(),
		    || Value::known(F::from(0))
		)?;
		region.constrain_constant(zero.cell(), F::from(0))?;
		let zero2 = zero.copy_advice(
		    || "zero2",
		    &mut region,
		    self.rlc,
		    4 * rlc_and_len_inputs.len() + 1,
		)?;
		let compare = concat.0.copy_advice(
		    || "concat_copy",
		    &mut region,
		    self.rlc,
		    4 * rlc_and_len_inputs.len() + 2,
		)?;
		self.q_mul.enable(&mut region, 4 * rlc_and_len_inputs.len() - 1)?;
		Ok(())		    
	    }
	)?;
	Ok(())
    }
    
    pub fn load_rlc_cache(
	&self,
	layouter: &mut impl Layouter<F>,
	cache_bits: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
	let gamma = layouter.get_challenge(self.gamma);

	let cache = layouter.assign_region(
	    || "gamma cache",
	    |mut region| {
		let mut cache = Vec::new();
		for idx in 0..cache_bits {
		    // rlc:   | 1 | g | 0 | g | g | g^2 
		    // val:   |   | 0 |   |
		    // q_rlc: |   | 1 |   | 
		    // q_mul: |   |   | 1 | 
		    if idx == 0 {
			let one = region.assign_advice(
			    || "one",
			    self.rlc,
			    0,
			    || Value::known(F::from(1))
			)?;
			region.constrain_constant(one.cell(), F::from(1))?;
			let zero = region.assign_advice(
			    || "zero",
			    self.val,
			    1,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			let cache0 = region.assign_advice(
			    || "gamma",
			    self.rlc,
			    1,
			    || gamma
			)?;
			self.q_rlc.enable(&mut region, 1)?;
			cache.push(cache0);
		    } else {
			let zero = region.assign_advice(
			    || "zero",
			    self.rlc,
			    4 * idx - 2,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			let next = cache[cache.len() - 1].copy_advice(
			    || "prev copy",
			    &mut region,
			    self.rlc,
			    4 * idx - 1
			)?;
			let next2 = cache[cache.len() - 1].copy_advice(
			    || "prev copy",
			    &mut region,
			    self.rlc,
			    4 * idx
			)?;
			region.constrain_equal(next.cell(), cache[cache.len() - 1].cell())?;
			region.constrain_equal(next2.cell(), cache[cache.len() - 1].cell())?;
			let next3 = region.assign_advice(
			    || "gamma next",
			    self.rlc,
			    4 * idx + 1,
			    || cache[cache.len() - 1].value().map(|x| (*x) * (*x))
			)?;
			self.q_mul.enable(&mut region, 4 * idx - 2)?;
			cache.push(next3);
		    }
		}
		Ok(cache)
	    }
	)?;
	Ok(cache)
    }
    
    pub fn rlc_pow(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	pow: AssignedCell<F, F>,
	pow_bits: usize,
	rlc_cache: &Vec<AssignedCell<F, F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
	assert!(pow_bits <= rlc_cache.len());
	
	let using_simple_floor_planner = true;
	let mut first_pass = true;
	let bits = layouter.assign_region(
	    || "num_to_bits",
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

		let bits = range.num_to_bits(
		    ctx,
		    &pow,
		    pow_bits,
		)?;
		let stats = range.finalize(ctx)?;
		println!("stats: {:?}", stats);
		Ok(bits)
	    }
	)?;
	
	// multi-exp of bits and rlc_cache
	let dot = layouter.assign_region(
	    || "bit product",
	    |mut region| {
		let mut prod_cells = Vec::new();
		for idx in 0..pow_bits {
		    // prod = bit * x + (1 - bit)
		    // | 1   | bit  | x | 1 + bit * x | bit | prod | 1 | bit + prod |
		    let one = region.assign_advice(
			|| "one",
			self.rlc,
			8 * idx,
			|| Value::known(F::from(1))
		    )?;
		    region.constrain_constant(one.cell(), F::from(1))?;
		    let bit_copy = bits[idx].copy_advice(
			|| "bit_copy",
			&mut region,
			self.rlc,
			8 * idx + 1
		    )?;
		    let cache_copy = rlc_cache[idx].copy_advice(
			|| "cache_copy",
			&mut region,
			self.rlc,
			8 * idx + 2
		    )?;
		    let eq_check = region.assign_advice(
			|| "eq",
			self.rlc,
			8 * idx + 3,
			|| bits[idx].value().zip(rlc_cache[idx].value()).map(|(a, b)| F::from(1) + (*a) * (*b))
		    )?;
		    self.q_mul.enable(&mut region, 8 * idx)?;

		    let bit_copy2 = bits[idx].copy_advice(
			|| "bit_copy",
			&mut region,
			self.rlc,
			8 * idx + 4
		    )?;
		    let prod = region.assign_advice(
			|| "eq",
			self.rlc,
			8 * idx + 5,
			|| bits[idx].value().zip(rlc_cache[idx].value()).map(|(a, b)| F::from(1) + (*a) * (*b) - (*a))
		    )?;
		    let one2 = region.assign_advice(
			|| "one",
			self.rlc,
			8 * idx + 6,
			|| Value::known(F::from(1))
		    )?;
		    region.constrain_constant(one2.cell(), F::from(1))?;
		    eq_check.copy_advice(
			|| "eq2",
			&mut region,
			self.rlc,
			8 * idx + 7
		    )?;
		    self.q_mul.enable(&mut region, 8 * idx + 4)?;

		    prod_cells.push(prod);		    
		}

		let mut intermed = Vec::new();
		for idx in 0..(pow_bits - 1) {
		    if idx == 0 {
			let zero = region.assign_advice(
			    || "zero",
			    self.rlc,
			    8 * pow_bits,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			prod_cells[0].copy_advice(
			    || "cache0",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 1
			)?;
			prod_cells[1].copy_advice(
			    || "cache1",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 2
			)?;
			let prod1 = region.assign_advice(
			    || "prod1",
			    self.rlc,
			    8 * pow_bits + 3,
			    || prod_cells[0].value().zip(prod_cells[1].value()).map(|(a, b)| (*a) * (*b))
			)?;
			self.q_mul.enable(&mut region, 8 * pow_bits)?;
			intermed.push(prod1);
		    } else {
			let zero = region.assign_advice(
			    || "zero",
			    self.rlc,
			    8 * pow_bits + 4 * idx,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			prod_cells[idx + 1].copy_advice(
			    || "cache",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 4 * idx + 1,
			)?;
			intermed[intermed.len() - 1].copy_advice(
			    || "intermed",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 4 * idx + 2,
			)?;
			let prod = region.assign_advice(
			    || "prod",
			    self.rlc,
			    8 * pow_bits + 4 * idx + 3,
			    || prod_cells[idx + 1].value().zip(intermed[intermed.len() - 1].value()).map(|(a, b)| (*a) * (*b))
			)?;
			self.q_mul.enable(&mut region, 8 * pow_bits + 4 * idx)?;
			intermed.push(prod);			
		    }
		}
		Ok(intermed[intermed.len() - 1].clone())
	    }
	)?;
	
	Ok(dot)
    }
}

#[derive(Clone, Debug)]
pub struct TestConfig<F: Field> {
    rlc: RlcChip<F>,
    range: RangeConfig<F>,
}

impl<F: Field> TestConfig<F> {
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
}

#[derive(Clone, Debug, Default)]
pub struct TestCircuit<F> {
    inputs: Vec<u8>,
    len: usize,
    max_len: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = TestConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
	Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
	TestConfig::configure(
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
	let (inputs_assigned, len_assigned) = layouter.assign_region(
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
		let len_assigned = config.range.gate.assign_region_smart(
		    ctx,
		    vec![Witness(Value::known(F::from(self.len as u64)))],
		    vec![],
		    vec![],
		    vec![]
		)?;
		let stats = config.range.finalize(ctx)?;
		Ok((inputs_assigned, len_assigned[0].clone()))
	    }
	)?;
	
	let rlc_trace = config.rlc.compute_rlc(
	    &mut layouter,
	    &config.range,
	    &inputs_assigned,
	    len_assigned,
	    self.max_len,
	)?;

	let gamma = layouter.get_challenge(config.rlc.gamma);
	let real_rlc = gamma.map(|g| compute_rlc_acc(&self.inputs[..self.len].to_vec(), g));
	println!("rlc_val {:?}", rlc_trace.rlc_val.value());
	println!("real_rlc {:?}", real_rlc);
	rlc_trace.rlc_val.value().zip(real_rlc).assert_if_known(|(a, b)| *a == b);
	Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use halo2_proofs::{
	dev::{MockProver},
	halo2curves::bn256::Fr,
    };
    use crate::rlp::rlc::{
	log2, TestCircuit
    };
    	    
    #[test]
    pub fn test_mock_rlc() {
	let k = 18;
	let input_bytes = vec![
	    1, 2, 3, 4, 5, 6, 7, 8,
	    1, 2, 3, 4, 5, 6, 7, 8,
	    1, 2, 3, 4, 5, 6, 7, 8,
	    1, 2, 3, 4, 5, 6, 7, 8,
	    0, 0, 0, 0, 0, 0, 0, 0
	];
	let max_len = input_bytes.len();
	let max_len_bits = log2(max_len);
	let len = 32;
	
	let circuit = TestCircuit::<Fr> {
	    inputs: input_bytes,
	    len,
	    max_len,
	    _marker: PhantomData
	};
	let prover = MockProver::run(k, &circuit, vec![]).unwrap();
	assert_eq!(prover.verify(), Ok(()));
    }
    
    #[test]
    pub fn test_rlc() {
	
    }
}
