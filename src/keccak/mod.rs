use std::marker::PhantomData;
use num_bigint::BigUint;
use halo2_base::utils::fe_to_biguint;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error, Expression,
	    FirstPhase, Fixed, Instance, SecondPhase, Selector},
    poly::Rotation,
};

use eth_types::Field;
use keccak256::plain::Keccak;
use zkevm_circuits::{
    keccak_circuit::{
	keccak_packed_multi::{KeccakPackedCircuit, KeccakPackedConfig, multi_keccak},
	util::{compose_rlc}
    },
    table::KeccakTable
};

use crate::rlp::{
    rlc::compute_rlc,
};

pub fn compute_keccak<F: Field>(msg: &Vec<Value<F>>) -> Vec<Value<F>> {    
    let bytes: Value<Vec<F>> = Value::from_iter(msg.iter().map(|s| *s));
    let bytes_vec: Value<Vec<u8>> = bytes.map(|x| x.iter().map(|b| u8::try_from(fe_to_biguint(b)).unwrap()).collect());
    let res = bytes_vec.map(|v| {
	let mut keccak = Keccak::default();
	keccak.update(&v);
	keccak.digest()
    });
    let res_vals: Value<Vec<F>> = res.map(|x| x.iter().map(|y| F::from(*y as u64)).collect());
    res_vals.transpose_vec(32)
}

#[derive(Clone, Debug)]
pub struct KeccakChip<F> {
    keccak_in_rlc: Column<Advice>,
    keccak_out_rlc: Column<Advice>,
    keccak_in_len: Column<Advice>,
    q_keccak: Column<Fixed>,
    gamma: Challenge,

    keccak_inputs: Vec<Vec<Value<F>>>,
    keccak_config: KeccakPackedConfig<F>,
    _marker: PhantomData<F>
}

impl<F: Field> KeccakChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, gamma: Challenge) -> Self {
	let keccak_in_rlc = meta.advice_column_in(SecondPhase);
	let keccak_out_rlc = meta.advice_column_in(SecondPhase);
	let keccak_in_len = meta.advice_column();
	let q_keccak = meta.fixed_column();

	meta.enable_equality(keccak_in_rlc);
	meta.enable_equality(keccak_in_len);
	meta.enable_equality(keccak_out_rlc);

	let keccak_config = KeccakPackedConfig::configure(meta, gamma);
	
	let config = Self {
	    keccak_in_rlc,
	    keccak_out_rlc,
	    keccak_in_len,
	    q_keccak,
	    gamma,
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
	inputs: &Vec<Value<F>>,
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
		input_rlc.copy_advice(|| "input_rlc", &mut region, self.keccak_in_rlc, 0)?;
		output_rlc.copy_advice(|| "output_rlc", &mut region, self.keccak_out_rlc, 0)?;
		Ok(())
	    }
	)?;
	self.keccak_inputs.push(inputs.clone());
	
	Ok(())
    }

    // Call this at the end of synthesize
    pub fn load_and_witness_keccak(
	&self,
	layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
	self.keccak_config.load(layouter)?;
	let gamma: Value<F> = layouter.get_challenge(self.gamma);
	let witness = multi_keccak(&self.keccak_inputs, gamma);
	self.keccak_config.assign(layouter, &witness)?;
	Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TestConfig<F> {
    a: Column<Advice>,
    b: Column<Advice>,
    q: Column<Fixed>,
    keccak_in_rlc: Column<Advice>,
    keccak_out_rlc: Column<Advice>,
    keccak_in_len: Column<Advice>,
    chip: KeccakChip<F>,
}

impl<F: Field> TestConfig<F> {
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
	let a = meta.advice_column();
	let b = meta.advice_column();
	let keccak_in_rlc = meta.advice_column_in(SecondPhase);
	let keccak_out_rlc = meta.advice_column_in(SecondPhase);
	let keccak_in_len = meta.advice_column();
	let q = meta.fixed_column();
	let gamma = meta.challenge_usable_after(FirstPhase);
	let keccak_config = KeccakChip::configure(meta, gamma);

	let config = Self {
	    a,
	    b,
	    q,
	    keccak_in_rlc,
	    keccak_out_rlc,
	    keccak_in_len,
	    chip: keccak_config,
	};

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
	    let g = meta.query_challenge(gamma);
	    vec![sel * (compose_rlc::expr(&inputs, g) - in_rlc)]
	});
	meta.create_gate("RLC output gate", |meta| {
	    let mut outputs = Vec::new();
	    for idx in 0..32 {
		outputs.push(meta.query_advice(b, Rotation(idx)));
	    }
	    let sel = meta.query_fixed(q, Rotation::cur());
	    let out_rlc = meta.query_advice(keccak_out_rlc, Rotation::cur());
	    let g = meta.query_challenge(gamma);
	    vec![sel * (compose_rlc::expr(&outputs, g) - out_rlc)]
	});
	
	config
    }
}

#[derive(Default)]
pub struct TestCircuit<F: Field> {
    inputs: Vec<Vec<Value<F>>>,
    size: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
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
	let gamma = layouter.get_challenge(config.chip.gamma);
	layouter.assign_region(
	    || "RLC verify",
	    |mut region| {
		for (idx, input) in self.inputs[0].iter().enumerate() {
		    region.assign_advice(
			|| "input RLC",
			config.a,
			idx,
			|| *input
		    )?;
		}
		// TODO: Remove this once zkevm keccak_bit bug is fixed
		let reversed = self.inputs[0].clone().into_iter().rev().collect();
		let input_rlc = compute_rlc(&reversed, gamma);
		region.assign_advice(
		    || "input RLC value",
		    config.keccak_in_rlc,
		    0,
		    || input_rlc
		)?;
		
		let outputs = compute_keccak(&self.inputs[0]);
		for (idx, output) in outputs.iter().enumerate() {
		    region.assign_advice(
			|| "output RLC",
			config.b,
			idx,
			|| *output
		    )?;
		}
		let output_rlc = compute_rlc(&outputs, gamma);
		println!("output_rlc {:?}", output_rlc);
		region.assign_advice(
		    || "output RLC value",
		    config.keccak_out_rlc,
		    0,
		    || output_rlc
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

	config.chip.load_and_witness_keccak(&mut layouter)?;
	Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
	transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
    };

    #[test]
    pub fn test_mock_keccak() {
	let k = 9;
	let inputs = vec![vec![Value::known(Fr::from(1)),
			       Value::known(Fr::from(2)),
			       Value::known(Fr::from(3))]];
	let mut circuit = TestCircuit::<Fr> {
	    inputs,
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

    #[test]
    pub fn test_keccak() -> Result<(), Error> {
	let k = 9;
	let inputs = vec![vec![Value::known(Fr::from(1)),
			       Value::known(Fr::from(2)),
			       Value::known(Fr::from(3))]];
	let inputs_none = vec![vec![Value::unknown(); 3]];

	let mut rng = rand::thread_rng();
	let params = ParamsKZG::<Bn256>::setup(k, &mut rng);

	let mut circuit = TestCircuit::<Fr> {
	    inputs: inputs_none,
	    size: 2usize.pow(k),
	    _marker: PhantomData,
	};
	println!("vk gen started");
	let vk = keygen_vk(&params, &circuit)?;
	println!("vk gen done");
        let pk = keygen_pk(&params, vk, &circuit)?;
	println!("pk gen done");
	println!("");
	println!("==============STARTING PROOF GEN===================");

	let mut proof_circuit = TestCircuit::<Fr> {
	    inputs: inputs,
	    size: 2usize.pow(k),
	    _marker: PhantomData,
	};

	let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
	create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            TestCircuit<Fr>,
        >(&params, &pk, &[proof_circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
	println!("proof gen done");
	let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
		.is_ok());
	println!("verify done");
	Ok(())
    }
}
