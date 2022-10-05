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
use num_bigint::BigUint;
use std::marker::PhantomData;

pub struct KeccakCircuit {
    input: Vec<u64>,
}

impl Default for KeccakCircuit {
    fn default() -> Self {
        Self { input: vec![] }
    }
}

impl<F: FieldExt> Circuit<F> for KeccakCircuit {
    type Config = KeccakChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { input: vec![0; self.input.len()] }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let config = KeccakChip::configure(meta, "keccak".to_string(), 1088, 256, 64, 1);
        println!("blinding factors: {}", meta.blinding_factors());
        config
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

                let input_bits = self
                    .input
                    .iter()
                    .map(|&b| {
                        assert!(b == 0 || b == 1);
                        Witness(Value::known(F::from(b)))
                    })
                    .collect_vec();
                let output_bits = config.keccak(ctx, input_bits)?;
                if value_to_option(output_bits[0].value()).is_some() {
                    println!(
                        "{:?}",
                        output_bits
                            .iter()
                            .rev()
                            .fold(BigUint::from(0u64), |acc, cell| acc * BigUint::from(2u64)
                                + fe_to_biguint(value_to_option(cell.value()).unwrap()))
                            .to_bytes_le()
                    );
                }
                let (fixed_rows, total_fixed) =
                    ctx.assign_and_constrain_constants(&config.constants)?;
                let advice_rows = ctx.advice_rows["keccak"].iter();
                println!(
                    "maximum rows used by an advice column: {}",
                    advice_rows.clone().max().or(Some(&0)).unwrap(),
                );
                println!(
                    "minimum rows used by an advice column: {}",
                    advice_rows.clone().min().or(Some(&usize::MAX)).unwrap(),
                );
                let total_cells = advice_rows.sum::<usize>();
                println!("total cells used: {}", total_cells);
                println!("total fixed cells: {}", total_fixed);

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
pub fn test_keccak() {
    let k = 10;
    let circuit = KeccakCircuit::default();

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

    let circuit = KeccakCircuit::default();

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

#[cfg(feature = "dev-graph")]
#[test]
fn plot_keccak() {
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Keccak Layout", ("sans-serif", 60)).unwrap();

    let circuit = KeccakCircuit::default();
    halo2_proofs::dev::CircuitLayout::default().render::<Fr, KeccakCircuit, _>(8, &circuit, &root).unwrap();
}
