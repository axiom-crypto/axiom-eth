use std::{marker::PhantomData, rc::Rc};
use num_bigint::BigUint;
use halo2_base::{
    AssignedValue, Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
    utils::fe_to_biguint
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error, Expression,
	    FirstPhase, Fixed, Instance, SecondPhase, Selector},};
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
    rlc::{compute_rlc, compute_rlc_acc},
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
    q_keccak: Column<Fixed>,
    gamma: Challenge,
    context_id: Rc<String>,
    challenge_id: Rc<String>,

    keccak_config: KeccakPackedConfig<F>,
    _marker: PhantomData<F>
}

impl<F: Field> KeccakChip<F> {
    pub fn configure(
	meta: &mut ConstraintSystem<F>,
	gamma: Challenge,
	context_id: String,
	challenge_id: String,
    ) -> Self {
	let keccak_in_rlc = meta.advice_column_in(SecondPhase);
	let keccak_out_rlc = meta.advice_column_in(SecondPhase);
	let q_keccak = meta.fixed_column();

	meta.enable_equality(keccak_in_rlc);
	meta.enable_equality(keccak_out_rlc);

	let keccak_config = KeccakPackedConfig::configure(meta, gamma);
	
	let config = Self {
	    keccak_in_rlc,
	    keccak_out_rlc,
	    q_keccak,
	    gamma,
	    context_id: Rc::new(context_id),
	    challenge_id: Rc::new(challenge_id),
	    keccak_config,
	    _marker: PhantomData,
	};

	    pub fn compute_keccak(
	&self,
	ctx: &mut Context<'_, F>,
	input_rlc: AssignedValue<F>,
	inputs: &Vec<Value<F>>,
    ) -> Result<(AssignedValue<F>, Vec<Value<F>>), Error> {
	let gamma = ctx.challenge_get(&self.challenge_id);
	let keccak_val = compute_keccak(inputs);
	let out_rlc_val = compute_rlc(&keccak_val, *gamma);

	println!("keccak_val {:?}", keccak_val);
	println!("out_rlc_val {:?}", out_rlc_val);

	let row_idx = ctx.advice_rows_get(&self.context_id)[0];
	let input_rlc_copy = ctx.assign_cell(
	    Existing(&input_rlc),
	    self.keccak_in_rlc,
	    &self.context_id,
	    0,
	    row_idx,
	    1u8
	)?;
	println!("input_rlc_copy {:?}", input_rlc_copy);
	let output_rlc = ctx.assign_cell(
	    Witness(out_rlc_val),
	    self.keccak_out_rlc,
	    &self.context_id,
	    0,
	    row_idx,
	    1u8
	)?;
	println!("output_rlc {:?}", output_rlc);
	let sel = ctx.region.assign_fixed(
	    || "",
	    self.q_keccak,
	    row_idx,
	    || Value::known(F::one())
	)?;
	println!("sel {:?}", sel);
	ctx.advice_rows_get_mut(&self.context_id)[0] += 1;

	println!("inputs {:?}", inputs);
	Ok((output_rlc, keccak_val))
    }

    // Call this at the end of synthesize
    pub fn load_and_witness_keccak(
	&self,
	layouter: &mut impl Layouter<F>,
	keccak_inputs: &Vec<Vec<Value<F>>>,
    ) -> Result<(), Error> {
	self.keccak_config.load(layouter)?;
	let gamma: Value<F> = layouter.get_challenge(self.gamma);
	println!("keccak_inputs {:?}", keccak_inputs);
	println!("gamma {:?}", gamma);
	let witness = multi_keccak(keccak_inputs, gamma);
	println!("witness {:?}", witness);
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
    chip: KeccakChip<F>,
}

impl<F: Field> TestConfig<F> {
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
	let a = meta.advice_column();
	let b = meta.advice_column();
	let keccak_in_rlc = meta.advice_column_in(SecondPhase);
	let keccak_out_rlc = meta.advice_column_in(SecondPhase);
	let q = meta.fixed_column();
	let gamma = meta.challenge_usable_after(FirstPhase);

	meta.enable_equality(a);
	meta.enable_equality(b);
	meta.enable_equality(keccak_in_rlc);
	meta.enable_equality(keccak_out_rlc);
	
	let keccak_config = KeccakChip::configure(
	    meta,
	    gamma,
	    "keccak".to_string(),
	    "gamma".to_string()
	);

	let config = Self {
	    a,
	    b,
	    q,
	    keccak_in_rlc,
	    keccak_out_rlc,
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
	let input_rlc = layouter.assign_region(
	    || "load inputs",
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
		let assigned = region.assign_advice(
		    || "input RLC value",
		    config.keccak_in_rlc,
		    0,
		    || input_rlc
		)?;
		let input_rlc_val = AssignedValue::new(
		    assigned.cell(),
		    input_rlc,
		    Rc::new("keccak".to_string()),
		    0,
		    0,
		    1u8,
		);
		Ok(input_rlc_val)
	    }
	)?;
	
        let using_simple_floor_planner = true;
        let mut first_pass = true;
        layouter.assign_region(
            || "load_inputs",
            |mut region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                }
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![
                            ("keccak".to_string(), 1),
                        ],
                    },
                );
                let ctx = &mut aux;
                ctx.challenge.insert("gamma".to_string(), gamma);

		println!("input_rlc {:?}", input_rlc);
		println!("inputs {:?}", self.inputs[0].clone());

		let (out_rlc, out_val) = config.chip.compute_keccak(
		    ctx,
		    input_rlc.clone(),
		    &self.inputs[0].clone()
		)?; 
		Ok(())
	    }
	)?;
	config.chip.load_and_witness_keccak(&mut layouter,
					    &vec![self.inputs[0].clone()])?;
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
}