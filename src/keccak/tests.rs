use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::{utils::fe_to_biguint, ContextParams};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::commitment::{Params, ParamsProver},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use std::marker::PhantomData;

#[derive(Default)]
pub struct KeccakCircuit<F: FieldExt> {
    lanes: [u64; 25],
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Circuit<F> for KeccakCircuit<F> {
    type Config = KeccakBitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        KeccakBitConfig::configure(meta, "keccak".to_string())
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let using_simple_floor_planner = true;
        let mut first_pass = true;
        layouter.assign_region(
            || "keccak",
            |region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = Context::new(
                    region,
                    ContextParams { num_advice: vec![(config.context_id.as_ref().clone(), 1)] },
                );
                let ctx = &mut aux;

                let mut lanes = config.assign_row(
                    ctx,
                    self.lanes.map(|x| Witness(Value::known(F::from(x)))),
                    0,
                )?;
                let mut row_offset = 1;
                for round in 0..24 {
                    lanes = config.keccak_f1600_round(ctx, &lanes, round, row_offset)?;
                    row_offset += 37;
                }
                for lane in &lanes {
                    println!("{:?}", lane.value().map(|v| fe_to_biguint(v)));
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
pub fn test_keccak() {
    let k = 10;
    let circuit =
        KeccakCircuit { lanes: (0..25).collect_vec().try_into().unwrap(), _marker: PhantomData };

    let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn bench_keccak() -> Result<(), Box<dyn std::error::Error>> {
    const K: u32 = 10;

    let mut rng = rand::thread_rng();
    let params_time = start_timer!(|| "Params construction");
    let path = format!("./params/kzg_bn254_{}.params", K);
    let fd = std::fs::File::open(path.as_str());
    let params = if let Ok(mut f) = fd {
        println!("Found existing params file. Reading params...");
        ParamsKZG::<Bn256>::read(&mut f).unwrap()
    } else {
        println!("Creating new params file...");
        let mut f = std::fs::File::create(path.as_str())?;
        let params = ParamsKZG::<Bn256>::setup(K, &mut rng);
        params.write(&mut f).unwrap();
        params
    };
    end_timer!(params_time);

    let circuit =
        KeccakCircuit { lanes: (0..25).collect_vec().try_into().unwrap(), _marker: PhantomData };

    let vk_time = start_timer!(|| "Generating vkey");
    let vk = keygen_vk(&params, &circuit)?;
    end_timer!(vk_time);

    let pk_time = start_timer!(|| "Generating pkey");
    let pk = keygen_pk(&params, vk, &circuit)?;
    end_timer!(pk_time);

    // create a proof
    let proof_time = start_timer!(|| "Proving time");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)?;
    let proof = transcript.finalize();
    end_timer!(proof_time);

    let verify_time = start_timer!(|| "Verify time");
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
    .is_ok());
    end_timer!(verify_time);

    Ok(())
}
