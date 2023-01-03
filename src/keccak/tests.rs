#![allow(unused_imports)]
use super::*;
use crate::{
    halo2_proofs::{
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
    },
    rlp::rlc::RlcConfig,
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        range::{RangeConfig, RangeStrategy},
    },
    utils::{fe_to_biguint, fs::gen_srs, value_to_option, ScalarField},
    ContextParams, SKIP_FIRST_PASS,
};
use itertools::{assert_equal, Itertools};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    env::{set_var, var},
    io::{BufRead, Write},
};
use zkevm_keccak::keccak_packed_multi::get_keccak_capacity;

#[derive(Clone, Debug)]
pub struct TestKeccakConfig<F: Field> {
    range: RangeConfig<F>,
    rlc: RlcConfig<F>,
    keccak: KeccakConfig<F>,
}

#[derive(Clone, Debug)]
pub struct KeccakCircuit {
    inputs: Vec<Vec<u8>>,
}

impl<F: Field> Circuit<F> for KeccakCircuit {
    type Config = TestKeccakConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { inputs: self.inputs.iter().map(|input| vec![0u8; input.len()]).collect() }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let num_advice: usize =
            var("NUM_ADVICE").unwrap_or_else(|_| "1".to_string()).parse().unwrap();
        let num_advice1: usize =
            var("NUM_ADVICE1").unwrap_or_else(|_| "1".to_string()).parse().unwrap();
        let degree: usize =
            var("KECCAK_DEGREE").unwrap_or_else(|_| "14".to_string()).parse().unwrap();
        let num_rlc_columns: usize =
            var("NUM_RLC").unwrap_or_else(|_| "1".to_string()).parse().unwrap();
        let mut range = RangeConfig::configure(
            meta,
            RangeStrategy::Vertical,
            &[num_advice, num_advice1],
            &[1, 1],
            1,
            8,
            0,
            degree,
        );
        let rlc = RlcConfig::configure(meta, num_rlc_columns, 1);
        log::info!("unusable rows before keccak: {}", meta.minimum_rows());
        let keccak = KeccakConfig::new(meta, rlc.gamma);
        println!("unusable rows after keccak: {}", meta.minimum_rows());

        let num_rows = (1 << degree) - meta.minimum_rows();
        range.gate.max_rows = num_rows;

        TestKeccakConfig { range, rlc, keccak }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let witness_time = start_timer!(|| "time witness gen");

        config.range.load_lookup_table(&mut layouter).expect("load range lookup table");
        config.keccak.load_aux_tables(&mut layouter).expect("load keccak lookup tables");
        let mut first_pass = SKIP_FIRST_PASS;
        layouter
            .assign_region(
                || "keccak",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            num_context_ids: 2,
                            max_rows: config.range.gate.max_rows,
                            fixed_columns: config.range.gate.constants.clone(),
                        },
                    );
                    let ctx = &mut aux;

                    let mut rlc_chip = RlcChip::new(config.rlc.clone(), Value::unknown());
                    let mut keccak_chip = KeccakChip::new(config.keccak.clone());

                    for (_idx, input) in self.inputs.iter().enumerate() {
                        let bytes = input.to_vec();
                        let bytes_assigned = config.range.gate.assign_witnesses(
                            ctx,
                            bytes.iter().map(|byte| Value::known(F::from(*byte as u64))),
                        );
                        // append some extra bytes to test variable length (don't do this for bench since it'll mess up the capacity)
                        // let zero = config.range.gate.load_zero(ctx);
                        // bytes_assigned.append(&mut vec![zero; _idx]);

                        let len = config
                            .range
                            .gate
                            .load_witness(ctx, Value::known(F::from(input.len() as u64)));

                        let _hash = keccak_chip.keccak_var_len(
                            ctx,
                            &config.range,
                            bytes_assigned,
                            Some(bytes),
                            len,
                            0,
                        );
                    }
                    keccak_chip.assign_phase0(&mut ctx.region);
                    config.range.finalize(ctx);
                    // END OF FIRST PHASE
                    ctx.next_phase();

                    // SECOND PHASE
                    rlc_chip.get_challenge(ctx);
                    let (fixed_len_rlcs, var_len_rlcs) =
                        keccak_chip.compute_all_rlcs(ctx, &mut rlc_chip, config.range.gate());
                    keccak_chip.assign_phase1(
                        ctx,
                        &config.range,
                        rlc_chip.gamma,
                        &fixed_len_rlcs,
                        &var_len_rlcs,
                    );
                    config.range.finalize(ctx);

                    #[cfg(feature = "display")]
                    {
                        ctx.print_stats(&["Range", "RLC"]);
                    }
                    Ok(())
                },
            )
            .unwrap();
        end_timer!(witness_time);

        Ok(())
    }
}

/// Cmdline: NUM_ADVICE=1 KECCAK_ROWS=25 KECCAK_DEGREE=14 RUST_LOG=info cargo test -- --nocapture test_keccak
#[test]
pub fn test_keccak() {
    let _ = env_logger::builder().is_test(true).try_init();

    let k: u32 = var("KECCAK_DEGREE").unwrap_or_else(|_| "14".to_string()).parse().unwrap();
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    let circuit = KeccakCircuit { inputs };

    let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[derive(Serialize, Deserialize)]
pub struct KeccakBenchConfig {
    degree: usize,
    range_advice: Vec<usize>,
    num_rlc: usize,
    keccak_advice: usize, // this is hand recorded from log::info
    unusable_rows: usize,
    rows_per_round: usize,
}

#[test]
fn bench_keccak() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut folder = std::path::PathBuf::new();
    folder.push("configs/bench_keccak.config");
    let bench_params_file = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();
    folder.pop();

    folder.push("data");
    folder.push("keccak_bench.csv");
    dbg!(&folder);
    let mut fs_results = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    writeln!(
            fs_results,
            "degree,advice_columns,unusable_rows,rows_per_round,keccak_f/s,num_keccak_f,proof_time,proof_size,verify_time"
        )
        .unwrap();

    let bench_params_reader = std::io::BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: KeccakBenchConfig = serde_json::from_str(line.unwrap().as_str()).unwrap();
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );
        let k = bench_params.degree as u32;
        set_var("KECCAK_DEGREE", k.to_string());
        set_var("NUM_ADVICE", bench_params.range_advice[0].to_string());
        set_var("NUM_ADVICE1", bench_params.range_advice[1].to_string());
        set_var("NUM_RLC", bench_params.num_rlc.to_string());

        let num_rows = (1 << k) - bench_params.unusable_rows;
        set_var("UNUSABLE_ROWS", bench_params.unusable_rows.to_string());
        set_var("KECCAK_ROWS", bench_params.rows_per_round.to_string());
        let capacity = get_keccak_capacity(num_rows);
        println!("Performing {capacity} keccak_f permutations");

        // the inputs can be different lengths, but they must be known _fixed_ lengths
        // use as many keccak_f as possible
        let circuit = KeccakCircuit { inputs: vec![vec![0; 135]; capacity] };

        // MockProver::<Fr>::run(k, &circuit, vec![]).unwrap().assert_satisfied();

        let params = gen_srs(k);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();

        let inputs = (0..capacity)
            .map(|_| (0..135).map(|_| rand::random::<u8>()).collect_vec())
            .collect_vec();
        let proof_circuit = KeccakCircuit { inputs };

        // create a proof
        let proof_time = start_timer!(|| "Create proof SHPLONK");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            KeccakCircuit,
        >(&params, &pk, &[proof_circuit], &[&[]], OsRng, &mut transcript)
        .unwrap();
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .unwrap();
        end_timer!(verify_time);

        let proof_size = {
            folder.push("keccak_circuit_proof.data");
            let mut fd = std::fs::File::create(folder.as_path()).unwrap();
            folder.pop();
            fd.write_all(&proof).unwrap();
            fd.metadata().unwrap().len()
        };

        writeln!(
            fs_results,
            "{},{},{},{},{:.2},{},{:.2}s,{},{:?}",
            bench_params.degree,
            bench_params.range_advice.iter().sum::<usize>() + bench_params.keccak_advice + 2,
            bench_params.unusable_rows,
            bench_params.rows_per_round,
            f64::from(capacity as u32) / proof_time.time.elapsed().as_secs_f64(),
            capacity,
            proof_time.time.elapsed().as_secs_f64(),
            proof_size,
            verify_time.time.elapsed()
        )
        .unwrap();
    }
}
