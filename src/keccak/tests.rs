use std::marker::PhantomData;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};

use eth_types::Field;
use keccak256::plain::Keccak;
use zkevm_circuits::{
    keccak_circuit::{
	keccak_bit::{KeccakBitCircuit, KeccakBitConfig, multi_keccak},
	util::{compose_rlc}
    },
    table::KeccakTable
};

pub fn compute_keccak(msg: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::default();
    keccak.update(msg);
    keccak.digest()
}

pub fn compute_rlc<F: Field>(msg: &Vec<u8>, r: F) -> F {
    let mut coeff = r;
    let mut rlc = F::from(msg[0] as u64);
    for val in msg[1..].iter() {
	rlc = rlc + F::from(*val as u64) * coeff;
	coeff = coeff * r;
    }
    rlc
}

#[derive(Clone, Debug)]
pub struct TestConfig<F> {
    a: Column<Advice>,
    b: Column<Advice>,
    keccak_in_rlc: Column<Advice>,
    keccak_out_rlc: Column<Advice>,
    keccak_in_len: Column<Advice>,
    q: Column<Fixed>,
    keccak_config: KeccakBitConfig<F>,
    _marker: PhantomData<F>
}

impl<F: Field> TestConfig<F> {
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
	let a = meta.advice_column();
	let b = meta.advice_column();
	let keccak_in_rlc = meta.advice_column();
	let keccak_out_rlc = meta.advice_column();
	let keccak_in_len = meta.advice_column();
	let q = meta.fixed_column();
	let keccak_config = KeccakBitCircuit::configure(meta);

	let config = Self {
	    a,
	    b,
	    keccak_in_rlc,
	    keccak_out_rlc,
	    keccak_in_len,
	    q,
	    keccak_config,
	    _marker: PhantomData,
	};

	// Lookup in Keccak table
	meta.lookup_any("keccak lookup", |meta| {
	    let input_rlc = meta.query_advice(config.keccak_config.keccak_table.input_rlc, Rotation::cur());
	    let output_rlc = meta.query_advice(config.keccak_config.keccak_table.output_rlc, Rotation::cur());
	    
	    let in_rlc = meta.query_advice(keccak_in_rlc, Rotation::cur());
	    let out_rlc = meta.query_advice(keccak_out_rlc, Rotation::cur());
	    let sel = meta.query_fixed(q, Rotation::cur());

	    vec![(sel.clone() * in_rlc, input_rlc),
		 (sel.clone() * out_rlc, output_rlc)]
	});

	// RLC prep
	meta.create_gate("RLC input gate", |meta| {
	    // TODO: Reverse the order of the inputs once bug(?) in keccak_bit is fixed
	    let inputs = vec![
		meta.query_advice(a, Rotation(2)),
		meta.query_advice(a, Rotation(1)),
		meta.query_advice(a, Rotation(0)),
	    ];
	    let sel = meta.query_fixed(q, Rotation::cur());
	    let in_rlc = meta.query_advice(keccak_in_rlc, Rotation::cur());
	    vec![sel * (compose_rlc::expr(&inputs, F::from(123456)) - in_rlc)]
	});
	meta.create_gate("RLC output gate", |meta| {
	    let mut outputs = Vec::new();
	    for idx in 0..32 {
		outputs.push(meta.query_advice(b, Rotation(idx)));
	    }
	    let sel = meta.query_fixed(q, Rotation::cur());
	    let out_rlc = meta.query_advice(keccak_out_rlc, Rotation::cur());
	    vec![sel * (compose_rlc::expr(&outputs, F::from(123456)) - out_rlc)]
	});
	
	config
    }
}

#[derive(Default)]
pub struct TestCircuit<'a, F: Field> {
    inputs: &'a [Vec<u8>], 
    size: usize,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> Circuit<F> for TestCircuit<'_, F> {
    type Config = TestConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
	Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
	TestConfig::configure(meta)
    }

    fn synthesize(
	&self,
	config: Self::Config,
	mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
	config.keccak_config.load(&mut layouter)?;
	let r = F::from(123456);
	let witness = multi_keccak(self.inputs, r);
	config.keccak_config.assign(&mut layouter, &witness)?;
	
	
	layouter.assign_region(
	    || "RLC verify",
	    |mut region| {
		for (idx, input) in self.inputs[0].iter().enumerate() {
		    region.assign_advice(
			|| "input RLC",
			config.a,
			idx,
			|| Value::known(F::from(*input as u64))
		    )?;
		}
		// TODO: Remove this once zkevm keccak_bit bug is fixed
		let reversed = self.inputs[0].clone().into_iter().rev().collect();
		let input_rlc = compute_rlc(&reversed, F::from(123456));
//		println!("input_rlc {:?}", input_rlc);
		region.assign_advice(
		    || "input RLC value",
		    config.keccak_in_rlc,
		    0,
		    || Value::known(input_rlc)
		)?;
		
		let outputs = compute_keccak(&self.inputs[0]);
		for (idx, output) in outputs.iter().enumerate() {
		    region.assign_advice(
			|| "output RLC",
			config.b,
			idx,
			|| Value::known(F::from(*output as u64))
		    )?;
		}
		let output_rlc = compute_rlc(&outputs, F::from(123456));
		println!("outputs    {:?}", outputs);
		println!("output_rlc {:?}", output_rlc);
		region.assign_advice(
		    || "output RLC value",
		    config.keccak_out_rlc,
		    0,
		    || Value::known(output_rlc)
		)?;

		region.assign_fixed(
		    || "selector",
		    config.q,
		    0,
		    || Value::known(F::from(1))
		)?;
		region.assign_advice(
		    || "input len",
		    config.keccak_in_len,
		    0,
		    || Value::known(F::from(3))
		)?;
		Ok(())
	    }
	)?;
	
	Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    #[test]
    pub fn test_keccak_packed_multi() {
	let k = 9;
	let inputs = vec![vec![1, 2, 3]];
	let mut circuit = TestCircuit {
	    inputs: &inputs,
	    size: 2usize.pow(k),
	    _marker: PhantomData,
	};
	
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        let verify_result = prover.verify();
        if verify_result.is_ok() != true {
            if let Some(errors) = verify_result.err() {
                for error in errors.iter() {
                    println!("{}", error);
                }
            }
            panic!();
        }
    }
}
