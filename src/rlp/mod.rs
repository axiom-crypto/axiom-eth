use std::marker::PhantomData;
use halo2_ecc::{
    gates::{
	Context, ContextParams,
	GateInstructions,
	QuantumCell::Witness,
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

#[derive(Clone, Debug)]
pub struct RlcTrace<F: Field> {
    rlc_trace: Vec<AssignedCell<F, F>>,
    rlc_max_val: AssignedCell<F, F>,
    rlc_val: AssignedCell<F, F>,
    rlc_len: AssignedCell<F, F>,
    max_len: usize,
}

#[derive(Clone, Debug)]
pub struct RlcChip<F> {
    val: Column<Advice>,
    rlc: Column<Advice>,
    q_rlc: Selector,
    q_mul: Selector,
    cons: Column<Fixed>,
    gamma: Challenge,

    _marker: PhantomData<F>
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

    pub fn compute_rlc(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	input: &Vec<AssignedCell<F, F>>,
	len: AssignedCell<F, F>,
	max_len: usize,
	rlc_cache: &Vec<AssignedCell<F, F>>,
    ) -> Result<RlcTrace<F>, Error> {
	assert!(input.len() == max_len);

	let gamma = layouter.get_challenge(self.gamma);
	let assigned = layouter.assign_region(
	    || "RLC array",
	    |mut region| {
		let mut rlc_cells = Vec::new();
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
		Ok((rlc_cells.clone(), rlc_cells[max_len - 1].clone()))
	    }
	)?;
	let rlc_max_val = assigned.1;

	let pow_diff = layouter.assign_region(
	    || "RLC power diff",
	    |mut region| {
		// | len | 1 | diff | max_len |
		let len_assigned = len.copy_advice(
		    || "len copy",
		    &mut region,
		    self.rlc,
		    0
		)?;
		let one = region.assign_advice(
		    || "one",
		    self.rlc,
		    1,
		    || Value::known(F::from(1))
		)?;
		region.constrain_constant(one.cell(), F::from(1))?;
		let diff = region.assign_advice(
		    || "diff",
		    self.rlc,
		    2,
		    || len.value().map(|x| F::from(max_len as u64) - x)
		)?;
		let ml = region.assign_advice(
		    || "ml",
		    self.rlc,
		    3,
		    || Value::known(F::from(max_len as u64))
		)?;
		region.constrain_constant(ml.cell(), F::from(max_len as u64))?;
		self.q_mul.enable(&mut region, 0)?;
		Ok(diff)
	    }
	)?;
	
	let rlc_pow = self.rlc_pow(
	    layouter,
	    range,
	    pow_diff,
	    log2(max_len + 1),
	    rlc_cache
	)?;

	let rlc_val = layouter.assign_region(
	    || "RLC pow diff check",
	    |mut region| {
		// | 0 | rlc_val | rlc_pow | rlc_max_val |
		let zero = region.assign_advice(
		    || "zero",
		    self.rlc,
		    0,
		    || Value::known(F::from(0))
		)?;
		region.constrain_constant(zero.cell(), F::from(0))?;
		let rlc_val = region.assign_advice(
		    || "rlc_val",
		    self.rlc,
		    1,
		    || rlc_max_val.value().zip(rlc_pow.value()).map(|(x, y)| (*x) * (*y).invert().unwrap())
		)?;
		let rlc_pow_copy = rlc_pow.copy_advice(
		    || "rlc_pow_copy",
		    &mut region,
		    self.rlc,
		    2
		)?;
		let rlc_max_val_copy = rlc_max_val.copy_advice(
		    || "rlc_max_val_copy",
		    &mut region,
		    self.rlc,
		    3
		)?;
		self.q_mul.enable(&mut region, 0)?;
		Ok(rlc_val)
	    }
	)?;
	
	let rlc_trace = RlcTrace {
	    rlc_trace: assigned.0,
	    rlc_max_val: rlc_max_val,
	    rlc_val: rlc_val,
	    rlc_len: len,
	    max_len: max_len,
	};
	Ok(rlc_trace)
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

	let rlc_cache = config.rlc.load_rlc_cache(
	    &mut layouter,
	    log2(self.max_len),
	)?;
	
	let rlc_trace = config.rlc.compute_rlc(
	    &mut layouter,
	    &config.range,
	    &inputs_assigned,
	    len_assigned,
	    self.max_len,
	    &rlc_cache
	)?;

	let gamma = layouter.get_challenge(config.rlc.gamma);
	let real_rlc = gamma.map(|g| compute_rlc_acc(&self.inputs[..self.len].to_vec(), g));
	println!("rlc_val {:?}", rlc_trace.rlc_val.value());
	println!("real_rlc {:?}", real_rlc);	
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
    use crate::rlp::{
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
    pub fn test_rlp_rlc() {
	
    }
}
