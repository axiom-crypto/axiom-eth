use super::*;
use crate::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::commitment::ParamsProver,
    poly::kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    utils::{fs::gen_srs, ScalarField},
    Context, ContextParams, SKIP_FIRST_PASS,
};
use hex::FromHex;
use rand_core::OsRng;
use std::{
    fs::File,
    io::{BufReader, Write},
    marker::PhantomData,
};

#[derive(Clone, Debug)]
pub struct MPTCircuit<F> {
    inputs: MPTFixedKeyInput,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for MPTCircuit<F> {
    type Config = MPTConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params: EthConfigParams =
            serde_json::from_reader(File::open("configs/tests/mpt.json").unwrap()).unwrap();

        MPTConfig::configure(meta, params, 0)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let witness_gen = start_timer!(|| "witness gen");

        config.rlp.range.load_lookup_table(&mut layouter).expect("load range lookup tables");
        config.keccak.load_aux_tables(&mut layouter).expect("load keccak lookup tables");
        let gamma = layouter.get_challenge(config.rlp.rlc.gamma);

        let mut first_pass = SKIP_FIRST_PASS;
        layouter
            .assign_region(
                || "MPT Fixed Test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let mut chip = MPTChip::new(config, gamma);
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            num_context_ids: 2,
                            max_rows: chip.gate().max_rows,
                            fixed_columns: chip.gate().constants.clone(),
                        },
                    );
                    let ctx = &mut aux;

                    let mpt_proof = self.inputs.assign(ctx, chip.gate());
                    let mpt_witness = chip.parse_mpt_inclusion_fixed_key_phase0(
                        ctx,
                        mpt_proof,
                        32,
                        self.inputs.value_max_byte_len,
                        self.inputs.max_depth,
                    );

                    chip.keccak.assign_phase0(&mut ctx.region);
                    chip.range().finalize(ctx);
                    // END OF FIRST PHASE
                    ctx.next_phase();

                    // SECOND PHASE
                    chip.get_challenge(ctx);
                    chip.keccak.assign_phase1(ctx, &mut chip.rlp.rlc, &chip.rlp.range);
                    chip.parse_mpt_inclusion_fixed_key_phase1(ctx, mpt_witness);
                    chip.range().finalize(ctx);

                    #[cfg(feature = "display")]
                    {
                        ctx.print_stats(&["Range", "RLC"]);
                    }
                    Ok(())
                },
            )
            .unwrap();
        end_timer!(witness_gen);
        Ok(())
    }
}

impl<F: ScalarField> Default for MPTCircuit<F> {
    fn default() -> Self {
        /*let block: serde_json::Value =
        serde_json::from_reader(File::open("scripts/input_gen/block.json").unwrap()).unwrap();*/

        let pf_str = std::fs::read_to_string("scripts/input_gen/acct_storage_pf.json").unwrap();
        let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
        // let acct_pf = pf["accountProof"].clone();
        let storage_pf = pf["storageProof"][0].clone();
        // println!("acct_pf {:?}", acct_pf);
        // println!("storage_root {:?}", pf["storageHash"]);
        // println!("storage_pf {:?}", storage_pf);

        let key_bytes_str: String = serde_json::from_value(storage_pf["key"].clone()).unwrap();
        let path = ethers_core::utils::keccak256(Vec::from_hex(key_bytes_str).unwrap());
        let value_bytes_str: String = serde_json::from_value(storage_pf["value"].clone()).unwrap();
        let value = ::rlp::encode(&Vec::from_hex(&value_bytes_str[2..]).unwrap()).to_vec();
        let root_hash_str: String = serde_json::from_value(pf["storageHash"].clone()).unwrap();
        let pf_strs: Vec<String> = serde_json::from_value(storage_pf["proof"].clone()).unwrap();

        let value_max_byte_len = 33;
        let max_depth = 8;
        let proof = pf_strs.into_iter().map(|pf| Vec::from_hex(&pf[2..]).unwrap()).collect();

        MPTCircuit {
            inputs: MPTFixedKeyInput {
                path: H256(path),
                value,
                root_hash: H256::from_slice(&Vec::from_hex(&root_hash_str[2..]).unwrap()),
                proof,
                value_max_byte_len,
                max_depth,
            },
            _marker: PhantomData,
        }
    }
}

#[test]
pub fn test_mock_mpt_inclusion_fixed() {
    let params: EthConfigParams =
        serde_json::from_reader(File::open("configs/tests/mpt.json").unwrap()).unwrap();
    let k = params.degree;

    let circuit = MPTCircuit::<Fr>::default();
    // println!("MPTCircuit {:?}", circuit);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn bench_mpt_inclusion_fixed() -> Result<(), Box<dyn std::error::Error>> {
    let bench_params_file = File::open("configs/bench/mpt.json").unwrap();
    std::fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/mpt.csv").unwrap();
    writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,proof_time,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    let bench_params: Vec<EthConfigParams> = serde_json::from_reader(bench_params_reader).unwrap();
    for bench_params in bench_params {
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );

        {
            let mut f = File::create("configs/tests/mpt.json")?;
            write!(f, "{}", serde_json::to_string(&bench_params).unwrap())?;
        }
        let params = gen_srs(bench_params.degree);
        let circuit = MPTCircuit::<Fr>::default();
        let vk = keygen_vk(&params, &circuit)?;
        let pk = keygen_pk(&params, vk, &circuit)?;

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
        >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .unwrap();
        end_timer!(verify_time);

        let keccak_advice =
            std::env::var("KECCAK_ADVICE_COLUMNS").unwrap().parse::<usize>().unwrap();
        writeln!(
            fs_results,
            "{},{},{},{:?},{:?},{},{:.2}s,{:?}",
            bench_params.degree,
            bench_params.num_rlc_columns
                + bench_params.num_range_advice.iter().sum::<usize>()
                + bench_params.num_lookup_advice.iter().sum::<usize>()
                + keccak_advice,
            bench_params.num_rlc_columns,
            bench_params.num_range_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            proof_time.time.elapsed().as_secs_f64(),
            verify_time.time.elapsed()
        )
        .unwrap();
    }
    Ok(())
}
