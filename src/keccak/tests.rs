use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::flex_gate::GateStrategy,
    utils::{fe_to_biguint, value_to_option},
    ContextParams,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::commitment::{Params, ParamsProver},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use num_bigint::BigUint;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

pub struct KeccakCircuit {
    input: Vec<Vec<u8>>,
    k: usize,
}

impl Default for KeccakCircuit {
    fn default() -> Self {
        Self { input: vec![vec![]], k: 20 }
    }
}

impl<F: FieldExt> Circuit<F> for KeccakCircuit {
    type Config = KeccakChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { input: vec![vec![0; self.input[0].len()]; self.input.len()], k: self.k }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params_str = std::fs::read_to_string("configs/keccak.config").unwrap();
        let params: KeccakCircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
        let gate =
            FlexGateConfig::configure(meta, GateStrategy::Vertical, &[1], 0, "default".to_string());
        let config = KeccakChip::configure(
            meta,
            gate,
            "keccak".to_string(),
            1088,
            256,
            params.num_rot,
            params.num_xor,
            params.num_xorandn,
            params.num_fixed,
        );
        println!("blinding factors: {}", meta.blinding_factors());
        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let witness_time = start_timer!(|| "time witness gen");
        config.load_lookup_table(&mut layouter)?;
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
                    ContextParams {
                        num_advice: vec![
                            ("default".to_string(), config.gate.num_advice),
                            ("keccak_rot".to_string(), config.rotation.len()),
                            ("keccak_xor".to_string(), config.xor_values.len() / 3),
                            ("keccak_xorandn".to_string(), config.xorandn_values.len() / 4),
                        ],
                    },
                );
                let ctx = &mut aux;

                dbg!(self.input.len());
                for nibbles in self.input.iter() {
                    let input_nibbles = config
                        .gate
                        .assign_region(
                            ctx,
                            nibbles
                                .iter()
                                .map(|&b| Witness(Value::known(F::from(b as u64))))
                                .collect_vec(),
                            vec![],
                            None,
                        )
                        .unwrap();
                    let output_bits = config.keccak(ctx, input_nibbles)?;
                    /*if value_to_option(output_bits[0].value()).is_some() {
                        println!(
                            "{:?}",
                            output_bits
                                .iter()
                                .rev()
                                .fold(BigUint::from(0u64), |acc, cell| acc
                                    * BigUint::from(1u64 << super::LOOKUP_BITS)
                                    + fe_to_biguint(value_to_option(cell.value()).unwrap()))
                                .to_bytes_le()
                        );
                    }*/
                }
                let (_fixed_rows, total_fixed) =
                    ctx.assign_and_constrain_constants(&config.constants)?;
                #[cfg(feature = "display")]
                {
                    println!(
                        "{:#?}",
                        ctx.advice_rows
                            .iter()
                            .map(|(key, val)| (key, val.iter().sum::<usize>()))
                            .collect_vec()
                    );
                    println!("total fixed cells: {}", total_fixed);
                    println!("[op count] {:#?}", ctx.op_count);

                    let total_rot = ctx.advice_rows["keccak_rot"].iter().sum::<usize>();
                    println!("Optimal rot #: {}", (total_rot + (1 << self.k) - 1) >> self.k);
                    let total_xor = ctx.advice_rows["keccak_xor"].iter().sum::<usize>();
                    println!("Optimal xor #: {}", (total_xor + (1 << self.k) - 1) >> self.k,);
                    let total_xorandn = ctx.advice_rows["keccak_xorandn"].iter().sum::<usize>();
                    println!(
                        "Optimal xorandn #: {}",
                        (total_xorandn + (1 << self.k) - 1) >> self.k
                    );
                }
                Ok(())
            },
        )?;
        end_timer!(witness_time);

        Ok(())
    }
}

#[test]
pub fn test_keccak() {
    let params_str = std::fs::read_to_string("configs/keccak.config").unwrap();
    let params: KeccakCircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
    let k = params.degree;
    /*
    // Padded test
    let mut input = vec![1];
    input.append(&mut vec![0; 1088 / 4 - 2]);
    input.push(1 << 3);
    let circuit = KeccakCircuit { input };
    */
    // let input = vec![vec![]];
    let input = (0..params.num_keccak_f)
        .map(|_| {
            let input_bytes: Vec<u8> = (0..128).map(|_| rand::random::<u8>()).collect();
            input_bytes.into_iter().flat_map(|x| [x % 16, x / 16].into_iter()).collect()
        })
        .collect();
    let circuit = KeccakCircuit { input, k: k as usize };

    let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn bench_keccak() -> Result<(), Box<dyn std::error::Error>> {
    let mut folder = std::path::PathBuf::new();
    folder.push("configs/bench_keccak.config");
    let bench_params_file = std::fs::File::open(folder.as_path())?;
    folder.pop();
    folder.pop();

    folder.push("data");
    folder.push("keccak_bench.csv");
    dbg!(&folder);
    let mut fs_results = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    write!(fs_results, "degree,num_advice,num_rot,num_xor,num_xorandn,num_fixed,num_keccak,proof_time,proof_size,verify_time\n")?;

    let mut params_folder = std::path::PathBuf::new();
    params_folder.push("./params");
    if !params_folder.is_dir() {
        std::fs::create_dir(params_folder.as_path())?;
    }

    let bench_params_reader = std::io::BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: KeccakCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );
        let mut rng = rand::thread_rng();

        {
            folder.pop();
            folder.push("configs/keccak.config");
            let mut f = std::fs::File::create(folder.as_path())?;
            write!(f, "{}", serde_json::to_string(&bench_params).unwrap())?;
            folder.pop();
            folder.pop();
            folder.push("data");
        }
        let params_time = start_timer!(|| "Params construction");
        let params = {
            params_folder.push(format!("kzg_bn254_{}.srs", bench_params.degree));
            let fd = std::fs::File::open(params_folder.as_path());
            let params = if let Ok(mut f) = fd {
                println!("Found existing params file. Reading params...");
                ParamsKZG::<Bn256>::read(&mut f).unwrap()
            } else {
                println!("Creating new params file...");
                let mut f = std::fs::File::create(params_folder.as_path())?;
                let params = ParamsKZG::<Bn256>::setup(bench_params.degree, &mut rng);
                params.write(&mut f).unwrap();
                params
            };
            params_folder.pop();
            params
        };
        end_timer!(params_time);

        let input = (0..bench_params.num_keccak_f)
            .map(|_| {
                let input_bytes: Vec<u8> = (0..128).map(|_| rand::random::<u8>()).collect();
                input_bytes.into_iter().flat_map(|x| [x % 16, x / 16].into_iter()).collect()
            })
            .collect();
        let proof_circuit = KeccakCircuit { input, k: bench_params.degree as usize };

        let circuit = <KeccakCircuit as Circuit<Fr>>::without_witnesses(&proof_circuit);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        // create a proof
        let proof_time = start_timer!(|| "SHPLONK");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[proof_circuit], &[&[]], rng, &mut transcript)?;
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

        let proof_size = {
            folder.push("keccak_circuit_proof.data");
            let mut fd = std::fs::File::create(folder.as_path()).unwrap();
            folder.pop();
            fd.write_all(&proof).unwrap();
            fd.metadata().unwrap().len()
        };

        write!(
            fs_results,
            "{},{},{},{},{},{},{},{:?},{},{:?}\n",
            bench_params.degree,
            bench_params.num_rot * 3 + bench_params.num_xor * 3 + bench_params.num_xorandn * 4,
            bench_params.num_rot,
            bench_params.num_xor,
            bench_params.num_xorandn,
            bench_params.num_fixed,
            bench_params.num_keccak_f,
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
        /*
        let circuit = KeccakCircuit::default();
        let proof_time = start_timer!(|| "GWC");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], OsRng::default(), &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);
        */
    }
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
    halo2_proofs::dev::CircuitLayout::default()
        .render::<Fr, KeccakCircuit, _>(8, &circuit, &root)
        .unwrap();
}
