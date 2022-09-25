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

#[derive(Clone, Debug)]
pub struct KeccakChip<F> {
    keccak_in_rlc: Column<Advice>,
    keccak_out_rlc: Column<Advice>,
    keccak_in_len: Column<Advice>,
    q_keccak: Column<Fixed>,

    keccak_inputs: Vec<Vec<u8>>,
    keccak_config: KeccakBitConfig<F>,
    _marker: PhantomData<F>
}

impl<F: Field> KeccakChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
	let keccak_in_rlc = meta.advice_column();
	let keccak_out_rlc = meta.advice_column();
	let keccak_in_len = meta.advice_column();
	let q_keccak = meta.fixed_column();
	let keccak_config = KeccakBitCircuit::configure(meta);

	meta.enable_equality(keccak_in_rlc);
	meta.enable_equality(keccak_in_len);
	meta.enable_equality(keccak_out_rlc);
	
	let config = Self {
	    keccak_in_rlc,
	    keccak_out_rlc,
	    keccak_in_len,
	    q_keccak,
	    keccak_inputs: Vec::new(),
	    keccak_config,
	    _marker: PhantomData,
	};

	// Lookup in Keccak table
	meta.lookup_any("keccak lookup", |meta| {
	    let input_rlc = meta.query_advice(config.keccak_config.keccak_table.input_rlc, Rotation::cur());
	    let output_rlc = meta.query_advice(config.keccak_config.keccak_table.output_rlc, Rotation::cur());
	    
	    let in_rlc = meta.query_advice(keccak_in_rlc, Rotation::cur());
	    let out_rlc = meta.query_advice(keccak_out_rlc, Rotation::cur());
	    let sel = meta.query_fixed(q_keccak, Rotation::cur());

	    vec![(sel.clone() * in_rlc, input_rlc),
		 (sel.clone() * out_rlc, output_rlc)]
	});
	
	config
    }

    pub fn copy_keccak_pair(
	&mut self,
	layouter: &mut impl Layouter<F>,
	input_rlc: AssignedCell<F, F>,
	output_rlc: AssignedCell<F, F>,
	input_bytes: &Vec<u8>,
    ) -> Result<(), Error> {
	layouter.assign_region(
	    || "keccak pair",
	    |mut region| {
		region.assign_fixed(
		    || "keccak lookup selector",
		    self.q_keccak,
		    0,
		    || Value::known(F::from(1))
		)?;

		// pending https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/799,
		// input_rlc is in reverse order
		input_rlc.copy_advice(
		    || "input_rlc",
		    &mut region,
		    self.keccak_in_rlc,
		    0
		)?;
		output_rlc.copy_advice(
		    || "output_rlc",
		    &mut region,
		    self.keccak_out_rlc,
		    0
		)?;
		Ok(())
	    }
	)?;
	self.keccak_inputs.push(input_bytes.clone());
	
	Ok(())
    }

    // Call this at the end of synthesize
    pub fn load_and_witness_keccak(
	&self,
	layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
	self.keccak_config.load(layouter)?;
	// TODO: Replace with actual RLC
	let r = F::from(123456);
	let witness = multi_keccak(&self.keccak_inputs, r);
	self.keccak_config.assign(layouter, &witness)?;
	Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
