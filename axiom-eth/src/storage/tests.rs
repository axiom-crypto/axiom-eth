use super::*;
use crate::util::EthConfigParams;
use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
};
use ark_std::{end_timer, start_timer};
use ethers_core::utils::keccak256;
use halo2_base::utils::fs::gen_srs;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::env::var;
use std::{
    env::set_var,
    fs::File,
    io::{BufReader, Write},
};
use test_log::test;

fn get_test_circuit(network: Network, num_slots: usize) -> EthBlockStorageCircuit {
    assert!(num_slots <= 10);
    let infura_id = var("INFURA_ID").expect("INFURA_ID environmental variable not set");
    let provider_url = match network {
        Network::Mainnet => format!("{MAINNET_PROVIDER_URL}{infura_id}"),
        Network::Goerli => format!("{GOERLI_PROVIDER_URL}{infura_id}"),
    };
    let provider = Provider::<Http>::try_from(provider_url.as_str())
        .expect("could not instantiate HTTP Provider");
    let addr;
    let block_number;
    match network {
        Network::Mainnet => {
            // cryptopunks
            addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>().unwrap();
            block_number = 16356350;
            //block_number = 0xf929e6;
        }
        Network::Goerli => {
            addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>().unwrap();
            block_number = 0x713d54;
        }
    }
    // For only occupied slots:
    let slot_nums = vec![0u64, 1u64, 2u64, 3u64, 6u64, 8u64];
    let mut slots = (0..4)
        .map(|x| {
            let mut bytes = [0u8; 64];
            bytes[31] = x;
            bytes[63] = 10;
            H256::from_slice(&keccak256(bytes))
        })
        .collect::<Vec<_>>();
    slots.extend(slot_nums.iter().map(|x| H256::from_low_u64_be(*x)));
    slots.truncate(num_slots);
    // let slots: Vec<_> = (0..num_slots).map(|x| H256::from_low_u64_be(x as u64)).collect();
    slots.truncate(num_slots);
    EthBlockStorageCircuit::from_provider(&provider, block_number, addr, slots, 8, 8, network)
}

#[test]
pub fn test_mock_single_eip1186() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/storage.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_circuit(Network::Mainnet, 1);
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BenchParams(EthConfigParams, usize); // (params, num_slots)

#[test]
pub fn bench_eip1186() -> Result<(), Box<dyn std::error::Error>> {
    let bench_params_file = File::open("configs/bench/storage.json").unwrap();
    std::fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/storage.csv").unwrap();
    writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,proof_time,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    let bench_params: Vec<BenchParams> = serde_json::from_reader(bench_params_reader).unwrap();
    for bench_params in bench_params {
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.0.degree
        );

        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&bench_params.0).unwrap());
        let input = get_test_circuit(Network::Mainnet, bench_params.1);
        let instance = input.instance();
        let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);

        let params = gen_srs(bench_params.0.degree);
        let vk = keygen_vk(&params, &circuit)?;
        let pk = keygen_pk(&params, vk, &circuit)?;
        let break_points = circuit.circuit.break_points.take();

        // create a proof
        let proof_time = start_timer!(|| "create proof SHPLONK");
        let phase0_time = start_timer!(|| "phase 0 synthesize");
        let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
        end_timer!(phase0_time);
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[&instance]], OsRng, &mut transcript)?;
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
        >(verifier_params, pk.get_vk(), strategy, &[&[&instance]], &mut transcript)
        .unwrap();
        end_timer!(verify_time);

        let keccak_advice = std::env::var("KECCAK_ADVICE_COLUMNS")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<usize>()
            .unwrap();
        let bench_params: EthConfigParams =
            serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap();
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

#[test]
#[cfg(feature = "evm")]
pub fn bench_evm_eip1186() -> Result<(), Box<dyn std::error::Error>> {
    use crate::util::circuit::custom_gen_evm_verifier_shplonk;
    use halo2_base::gates::builder::CircuitBuilderStage;
    use snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk, write_calldata},
        gen_pk,
        halo2::{
            aggregation::{AggregationCircuit, AggregationConfigParams},
            gen_snark_shplonk,
        },
        CircuitExt, SHPLONK,
    };
    use std::{fs, path::Path};
    let bench_params_file = File::open("configs/bench/storage.json").unwrap();
    let evm_params_file = File::open("configs/bench/storage_evm.json").unwrap();
    std::fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/storage.csv").unwrap();
    writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,storage_proof_time,evm_proof_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    let bench_params: Vec<BenchParams> = serde_json::from_reader(bench_params_reader).unwrap();
    let evm_params_reader = BufReader::new(evm_params_file);
    let evm_params: Vec<AggregationConfigParams> =
        serde_json::from_reader(evm_params_reader).unwrap();
    for (bench_params, evm_params) in bench_params.iter().zip(evm_params.iter()) {
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.0.degree
        );

        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&bench_params.0).unwrap());

        let (storage_snark, storage_proof_time) = {
            let k = bench_params.0.degree;
            let input = get_test_circuit(Network::Mainnet, bench_params.1);
            let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);
            let params = gen_srs(k);
            let pk = gen_pk(&params, &circuit, None);
            let break_points = circuit.circuit.break_points.take();
            let storage_proof_time = start_timer!(|| "Storage Proof SHPLONK");
            let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
            let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
            end_timer!(storage_proof_time);
            (snark, storage_proof_time)
        };

        let k = evm_params.degree;
        let params = gen_srs(k);
        set_var("LOOKUP_BITS", evm_params.lookup_bits.to_string());
        let evm_circuit = AggregationCircuit::public::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            None,
            evm_params.lookup_bits,
            &params,
            vec![storage_snark.clone()],
            false,
        );
        evm_circuit.config(k, Some(10));
        let pk = gen_pk(&params, &evm_circuit, None);
        let break_points = evm_circuit.break_points();

        let instances = evm_circuit.instances();
        let evm_proof_time = start_timer!(|| "EVM Proof SHPLONK");
        let pf_circuit = AggregationCircuit::public::<SHPLONK>(
            CircuitBuilderStage::Prover,
            Some(break_points),
            evm_params.lookup_bits,
            &params,
            vec![storage_snark],
            false,
        );
        let proof = gen_evm_proof_shplonk(&params, &pk, pf_circuit, instances.clone());
        end_timer!(evm_proof_time);
        fs::create_dir_all("data/storage").unwrap();
        write_calldata(&instances, &proof, Path::new("data/storage/test.calldata")).unwrap();

        let deployment_code = custom_gen_evm_verifier_shplonk(
            &params,
            pk.get_vk(),
            &evm_circuit,
            Some(Path::new("data/storage/test.yul")),
        );

        // this verifies proof in EVM and outputs gas cost (if successful)
        evm_verify(deployment_code, instances, proof);

        let keccak_advice = std::env::var("KECCAK_ADVICE_COLUMNS")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<usize>()
            .unwrap();
        let bench_params: EthConfigParams =
            serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap();
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
            storage_proof_time.time.elapsed().as_secs_f64(),
            evm_proof_time.time.elapsed()
        )
        .unwrap();
    }
    Ok(())
}
