use super::*;
use crate::halo2_proofs::{
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
};
use crate::providers::{
    get_block_access_list_num, get_block_receipts, get_block_rlp_from_num,
    get_block_rlp_unrestricted, get_block_transaction_len, get_block_transactions, get_blocks,
    setup_provider,
};
use crate::util::EthConfigParams;
use ark_std::{end_timer, start_timer};
use halo2_base::utils::fs::gen_srs;
use hex::FromHex;
use rand_core::OsRng;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::CircuitExt;
use std::env::var;
use std::{
    env::set_var,
    fs::File,
    io::{BufReader, Write},
};
use test_log::test;

// mod field;
// mod field_blocks;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TxProviderInput {
    pub idxs: Vec<usize>,
    pub block_number: usize,
}

fn get_test_circuit(
    network: Network,
    idxs: Vec<usize>,
    block_number: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> EthBlockTransactionCircuit {
    assert!(idxs.len() <= 10);
    let provider = setup_provider(network);

    EthBlockTransactionCircuit::from_provider(
        &provider,
        idxs,
        block_number.try_into().unwrap(),
        6,
        network,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
        constrain_len,
    )
}

pub fn test_valid_input_json(
    path: String,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    let file_inputs: TxProviderInput =
        serde_json::from_reader(File::open(path).expect("path does not exist")).unwrap();
    let idxs = file_inputs.idxs;
    let block_number = file_inputs.block_number;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_circuit(
        Network::Mainnet,
        idxs,
        block_number,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
        constrain_len,
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

pub fn test_valid_input_direct(
    idxs: Vec<usize>,
    block_number: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_circuit(
        Network::Mainnet,
        idxs,
        block_number,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
        constrain_len,
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

// #[test]
// pub fn test_mock_single_tx() -> Result<(), Box<dyn std::error::Error>> {
//     let params = EthConfigParams::from_path("configs/tests/transaction.json");
//     let file_inputs = serde_json::from_reader(File::open("test_data/").expect("path does not exist")).unwrap();
//     let idxs = file_inputs.idxs;
//     let block_num = file_inputs.block_num;
//     set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
//     let k = params.degree;

//     let input = get_test_circuit(Network::Mainnet, );
//     let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
//     MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
//     Ok(())
// }

#[test]
pub fn find_good_block256() -> Result<(), Box<dyn std::error::Error>> {
    let provider = setup_provider(Network::Mainnet);
    for block_number in 5000000..6000000 {
        let num_tx = get_block_transaction_len(&provider, block_number.try_into().unwrap());
        if num_tx > 256 {
            println!("Desired Block: {block_number:?}");
        }
    }
    Ok(())
}

#[test]
pub fn find_access_lists() -> Result<(), Box<dyn std::error::Error>> {
    let provider = setup_provider(Network::Mainnet);
    let mut trend = Vec::new();

    let mut data_file = File::create("data.txt").expect("creation failed");
    for i in 0..100 {
        let cnt = get_block_access_list_num(&provider, 17578525 - i);
        trend.push((17578525 - i, cnt));
        data_file.write_all((cnt.to_string() + "\n").as_bytes()).expect("write failed");
    }
    Ok(())
}

#[test]
pub fn find_transaction_lens() -> Result<(), Box<dyn std::error::Error>> {
    let provider = setup_provider(Network::Mainnet);
    let mut trend = Vec::new();

    let mut data_file = File::create("data.txt").expect("creation failed");
    for i in 0..100 {
        let transactions = get_block_transactions(&provider, 17578525 - i);
        for j in 0..transactions.len() {
            let transaction = transactions[j].clone();
            trend.push((17578525 - i, transaction.input.len()));
            let _len = match transaction.access_list {
                Some(a_list) => {
                    let mut s = RlpStream::new();
                    s.append(&a_list);
                    let rlp_bytes: Vec<u8> = s.out().freeze().into();
                    rlp_bytes.len()
                }
                None => 0,
            };
            let len = transaction.input.len();
            data_file
                .write_all(
                    (len.to_string()
                        + ", "
                        + &j.to_string()
                        + ", "
                        + &(17578525 - i).to_string()
                        + ", "
                        + "\n")
                        .as_bytes(),
                )
                .expect("write failed");
        }
    }
    Ok(())
}

#[test]
pub fn find_receipt_lens() -> Result<(), Box<dyn std::error::Error>> {
    let provider = setup_provider(Network::Mainnet);

    let mut data_file = File::create("data.txt").expect("creation failed");
    for i in 0..100 {
        let receipts = get_block_receipts(&provider, 17578525 - i);
        for j in 0..receipts.len() {
            let receipt = receipts[j].clone();
            let _len = {
                let mut s = RlpStream::new();
                s.append_list(&receipt.logs);
                let rlp_bytes: Vec<u8> = s.out().freeze().into();
                rlp_bytes.len()
            };
            //let len = transaction.input.len();
            let len = receipts[j].logs.len();
            for i in 0..receipt.logs.len() {
                let len = receipt.logs[i].data.len();
                data_file
                    .write_all(
                        (len.to_string()
                            + ", "
                            + &j.to_string()
                            + ", "
                            + &(17578525 - i).to_string()
                            + ", "
                            + "\n")
                            .as_bytes(),
                    )
                    .expect("write failed");
            }
        }
    }
    Ok(())
}

#[test]
pub fn test_mock_single_tx_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_json(
        "src/transaction/tests/data/single_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        false,
    );
}

#[test]
pub fn test_mock_multi_tx_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_json(
        "src/transaction/tests/data/multi_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        false,
    );
}

#[test]
pub fn test_mock_zero_tx_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_json(
        "src/transaction/tests/data/zero_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        false,
    );
}

#[test]
pub fn test_mock_single_tx_new() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_json(
        "src/transaction/tests/data/single_tx_pos_test_new.json".to_string(),
        256,
        512,
        [true, true, true],
        false,
    );
}

#[test]
pub fn test_mock_multi_tx_new() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_json(
        "src/transaction/tests/data/multi_tx_pos_test_new.json".to_string(),
        256,
        512,
        [true, false, true],
        false,
    );
}

#[test]
pub fn stress_test() -> Result<(), Box<dyn std::error::Error>> {
    let tx_num: usize = serde_json::from_reader(
        File::open("src/transaction/tests/data/stress_test.json").expect("path does not exist"),
    )
    .unwrap();
    let mut idxs = Vec::new();
    for i in 0..tx_num {
        idxs.push(i);
    }
    return test_valid_input_direct(idxs, 5000008, 256, 0, [true, false, false], false);
}

#[test]
pub fn test_invalid_block_header() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    let file_inputs: TxProviderInput = serde_json::from_reader(
        File::open("src/transaction/test_data/multi_tx_pos_test_legacy.json")
            .expect("path does not exist"),
    )
    .unwrap();
    let idxs = file_inputs.idxs;
    let block_number = file_inputs.block_number;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let mut input =
        get_test_circuit(Network::Mainnet, idxs, block_number, 256, 0, [true, false, false], false);
    let provider = setup_provider(Network::Mainnet);
    let new_block_header = get_block_rlp_from_num(&provider, 1000000);
    input.inputs.block_header = new_block_header;
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    let prover = MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap();
    match prover.verify() {
        Ok(_) => panic!("Should not have verified"),
        Err(_) => Ok(()),
    }
}

#[test]
pub fn test_valid_root_wrong_block_header() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    let file_inputs: TxProviderInput = serde_json::from_reader(
        File::open("src/transaction/tests/data/multi_tx_pos_test_legacy.json")
            .expect("path does not exist"),
    )
    .unwrap();
    let idxs = file_inputs.idxs;
    let block_number = file_inputs.block_number;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let mut input =
        get_test_circuit(Network::Mainnet, idxs, block_number, 256, 0, [true, false, false], false);
    let provider = setup_provider(Network::Mainnet);
    let blocks = get_blocks(&provider, vec![block_number as u64 + 1]).unwrap();
    let block = blocks[0].clone();
    match block {
        None => Ok(()),
        Some(mut _block) => {
            _block.transactions_root = input.inputs.txs.transaction_pfs[0].2.root_hash;
            let new_block_header = get_block_rlp_unrestricted(&_block);
            input.inputs.block_header = new_block_header;
            let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
            MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
            Ok(())
        }
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    Vec::from_hex(s).unwrap()
}

// Tests if the key = rlp(idx) is correctly constrained
#[test]
pub fn test_invalid_key() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let confused_pairs = vec![(1, 256), (256, 1), (1, 0), (0, 1), (0, 256), (256, 0)];
    let block_number = 5000050;
    let k = params.degree;
    for i in 0..6 {
        let idxs = vec![confused_pairs[i].0];
        let mut input = get_test_circuit(
            Network::Mainnet,
            idxs,
            block_number,
            256,
            0,
            [true, false, false],
            false,
        );
        input.inputs.txs.transaction_pfs[0].0 = confused_pairs[i].1;
        let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
        let prover = MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap();
        match prover.verify() {
            Ok(_) => panic!("Should not have verified"),
            Err(_) => {}
        };
    }
    Ok(())
}

#[test]
pub fn test_mock_single_tx_len_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_json(
        "src/transaction/tests/data/single_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        true,
    );
}

#[test]
pub fn test_mock_multi_tx_len_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_json(
        "src/transaction/tests/data/multi_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        true,
    );
}

#[test]
pub fn test_mock_zero_len_new() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_direct([].into(), 1000, 256, 512, [true, false, true], true);
}

#[test]
pub fn test_mock_zero_len_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_direct([].into(), 1000, 256, 512, [true, false, false], true);
}

#[test]
pub fn test_mock_one_len_new() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_direct([].into(), 3482144, 256, 512, [true, false, true], true);
}

#[test]
pub fn test_mock_one_len_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_direct([0].into(), 3482144, 256, 512, [true, false, false], true);
}

#[test]
pub fn test_mock_nonzero_len_new() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_direct([].into(), 5000008, 256, 512, [true, false, true], true);
}

#[test]
pub fn test_mock_nonzero_len_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_valid_input_direct([].into(), 5000008, 256, 512, [true, false, false], true);
}

#[derive(Serialize, Deserialize)]
struct BenchParams(EthConfigParams, usize); // (params, num_slots)

/*
#[test]
pub fn bench_tx() -> Result<(), Box<dyn std::error::Error>> {
    let bench_params_file = File::open("configs/bench/transaction.json").unwrap();
    std::fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/transaction.csv").unwrap();
    writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,proof_time,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    let bench_params: Vec<BenchParams> = serde_json::from_reader(bench_params_reader).unwrap();
    for bench_params in bench_params {
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.0.degree
        );

        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&bench_params.0).unwrap());
        let input = get_test_circuit(
            Network::Mainnet,
            vec![0, bench_params.1],
            5000008,
            256,
            0,
            [true, false, false],
            false,
        );
        let instance = input.instances()[0].clone();
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
pub fn bench_evm_tx() -> Result<(), Box<dyn std::error::Error>> {
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
    let bench_params_file = File::open("configs/bench/transaction.json").unwrap();
    let evm_params_file = File::open("configs/bench/transaction_evm.json").unwrap();
    std::fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/transaction.csv").unwrap();
    writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,transaction_proof_time,evm_proof_time")?;

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
            let input = get_test_circuit(
                Network::Mainnet,
                vec![256, bench_params.1],
                5000050,
                256,
                0,
                [true, false, false],
                false,
            );
            let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);
            let params = gen_srs(k);
            let pk = gen_pk(&params, &circuit, None);
            let break_points = circuit.circuit.break_points.take();
            let storage_proof_time = start_timer!(|| "Transaction Proof SHPLONK");
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
        fs::create_dir_all("data/transaction").unwrap();
        write_calldata(&instances, &proof, Path::new("data/transaction/test.calldata")).unwrap();

        let deployment_code = custom_gen_evm_verifier_shplonk(
            &params,
            pk.get_vk(),
            &evm_circuit,
            Some(Path::new("data/transaction/test.yul")),
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
*/
