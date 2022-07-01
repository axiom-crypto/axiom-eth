#![cfg(feature = "providers")]
use crate::providers::block::get_block_rlp_from_num;
use crate::providers::setup_provider;
use crate::rlc::circuit::RlcCircuitParams;
use crate::rlc::tests::get_rlc_params;
use crate::utils::eth_circuit::{create_circuit, EthCircuitInstructions, EthCircuitParams};

use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::gates::circuit::{BaseCircuitParams, CircuitBuilderStage};
use halo2_base::halo2_proofs::dev::MockProver;

use ethers_providers::{JsonRpcClient, Provider};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::{fs::File, io::Write};
use test_log::test;

pub mod field;

#[derive(Clone, Debug)]
pub struct EthBlockTransactionCircuit<F> {
    pub inputs: EthBlockTransactionsInput, // public and private inputs
    pub params: EthTransactionChipParams,
    _marker: PhantomData<F>,
}

impl<F> EthBlockTransactionCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        idxs: Vec<usize>,
        block_number: u32,
        transaction_pf_max_depth: usize,
        network: Chain,
        max_data_byte_len: usize,
        max_access_list_len: usize,
        enable_types: [bool; 3],
        constrain_len: bool,
    ) -> Self {
        use crate::providers::transaction::get_block_transaction_input;

        let inputs = get_block_transaction_input(
            provider,
            idxs,
            block_number,
            transaction_pf_max_depth,
            max_data_byte_len,
            max_access_list_len,
            enable_types,
            constrain_len,
        );
        let params = EthTransactionChipParams {
            max_data_byte_len,
            max_access_list_len,
            enable_types,
            network: Some(network),
        };
        Self { inputs, params, _marker: PhantomData }
    }
}

impl<F: Field> EthCircuitInstructions<F> for EthBlockTransactionCircuit<F> {
    type FirstPhasePayload = (EthBlockTransactionsWitness<F>, EthTransactionChipParams);
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let ctx = builder.base.main(FIRST_PHASE);
        let chip = EthTransactionChip::new(mpt, self.params);
        let input = self.inputs.clone().assign(ctx, chip.network().unwrap());
        let witness = chip.parse_transaction_proofs_from_block_phase0(builder, input);
        (witness, self.params)
    }
    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        (witness, chip_params): Self::FirstPhasePayload,
    ) {
        let chip = EthTransactionChip::new(mpt, chip_params);
        chip.parse_transaction_proofs_from_block_phase1(builder, witness);
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TxProviderInput {
    pub idxs: Vec<usize>,
    pub block_number: usize,
}

fn get_test_circuit(
    network: Chain,
    idxs: Vec<usize>,
    block_number: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> EthBlockTransactionCircuit<Fr> {
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
) {
    let file_inputs: TxProviderInput =
        serde_json::from_reader(File::open(path).expect("path does not exist")).unwrap();
    let idxs = file_inputs.idxs;
    let block_number = file_inputs.block_number;
    test_valid_input_direct(
        idxs,
        block_number,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
        constrain_len,
    );
}

pub fn test_valid_input_direct(
    idxs: Vec<usize>,
    block_number: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) {
    let params = get_rlc_params("configs/tests/transaction.json");
    let k = params.base.k as u32;

    let input = get_test_circuit(
        Chain::Mainnet,
        idxs,
        block_number,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
        constrain_len,
    );
    let mut circuit = create_circuit(CircuitBuilderStage::Mock, params, input);
    circuit.mock_fulfill_keccak_promises(None);
    circuit.calculate_params();
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test]
pub fn test_mock_single_tx_legacy() {
    test_valid_input_json(
        "src/transaction/tests/data/single_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        false,
    );
}

#[test]
pub fn test_mock_multi_tx_legacy() {
    test_valid_input_json(
        "src/transaction/tests/data/multi_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        false,
    );
}

#[test]
pub fn test_mock_zero_tx_legacy() {
    test_valid_input_json(
        "src/transaction/tests/data/zero_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        false,
    );
}

#[test]
pub fn test_mock_single_tx_new() {
    test_valid_input_json(
        "src/transaction/tests/data/single_tx_pos_test_new.json".to_string(),
        256,
        512,
        [true, true, true],
        false,
    );
}

#[test]
pub fn test_mock_multi_tx_new() {
    test_valid_input_json(
        "src/transaction/tests/data/multi_tx_pos_test_new.json".to_string(),
        256,
        512,
        [true, false, true],
        false,
    );
}

#[test]
pub fn stress_test() {
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
pub fn test_invalid_block_header() {
    let params = get_rlc_params("configs/tests/transaction.json");
    let file_inputs: TxProviderInput = serde_json::from_reader(
        File::open("src/transaction/tests/data/multi_tx_pos_test_legacy.json")
            .expect("path does not exist"),
    )
    .unwrap();
    let idxs = file_inputs.idxs;
    let block_number = file_inputs.block_number;
    let k = params.base.k as u32;

    let mut input =
        get_test_circuit(Chain::Mainnet, idxs, block_number, 256, 0, [true, false, false], false);
    let provider = setup_provider(Chain::Mainnet);
    let new_block_header = get_block_rlp_from_num(&provider, 1000000);
    input.inputs.block_header = new_block_header;
    let mut circuit = create_circuit(CircuitBuilderStage::Mock, params, input);
    circuit.mock_fulfill_keccak_promises(None);
    circuit.calculate_params();
    let instances = circuit.instances();
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    assert!(prover.verify().is_err());
}

/* // ignore for now because an assert fails
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
    let k = params.degree;

    let mut input =
        get_test_circuit(Chain::Mainnet, idxs, block_number, 256, 0, [true, false, false], false);
    let provider = setup_provider(Chain::Mainnet);
    let blocks = get_blocks(&provider, vec![block_number as u64 + 1]).unwrap();
    let block = blocks[0].clone();
    match block {
        None => Ok(()),
        Some(mut _block) => {
            _block.transactions_root = input.inputs.tx_proofs[0].proof.root_hash;
            let new_block_header = get_block_rlp(&_block); // panics because block hash fails
            input.inputs.block_header = new_block_header;
            let circuit = input.create_circuit(RlcThreadBuilder::mock(), params, None);
            MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
            Ok(())
        }
    }
}
*/

// Tests if the key = rlp(idx) is correctly constrained
#[test]
pub fn test_invalid_key() {
    let params = get_rlc_params("configs/tests/transaction.json");
    let confused_pairs = [(1, 256), (256, 1), (1, 0), (0, 1), (0, 256), (256, 0)];
    let block_number = 5000050;
    let k = params.base.k as u32;
    for (idx, tx_index) in confused_pairs {
        let idxs = vec![idx];
        let mut input = get_test_circuit(
            Chain::Mainnet,
            idxs,
            block_number,
            256,
            0,
            [true, false, false],
            false,
        );
        input.inputs.tx_proofs[0].tx_index = tx_index;
        let mut circuit = create_circuit(CircuitBuilderStage::Mock, params.clone(), input);
        circuit.mock_fulfill_keccak_promises(None);
        circuit.calculate_params();
        let instances = circuit.instances();
        let prover = MockProver::run(k, &circuit, instances).unwrap();
        assert!(prover.verify().is_err(), "Should not have verified");
    }
}

#[test]
pub fn test_mock_single_tx_len_legacy() {
    test_valid_input_json(
        "src/transaction/tests/data/single_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        true,
    );
}

#[test]
pub fn test_mock_multi_tx_len_legacy() {
    test_valid_input_json(
        "src/transaction/tests/data/multi_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
        true,
    );
}

#[test]
pub fn test_mock_zero_len_new() {
    test_valid_input_direct([].into(), 1000, 256, 512, [true, false, true], true);
}

#[test]
pub fn test_mock_zero_len_legacy() {
    test_valid_input_direct([].into(), 1000, 256, 512, [true, false, false], true);
}

#[test]
pub fn test_mock_one_len_new() {
    test_valid_input_direct([].into(), 3482144, 256, 512, [true, false, true], true);
}

#[test]
pub fn test_mock_one_len_legacy() {
    test_valid_input_direct([0].into(), 3482144, 256, 512, [true, false, false], true);
}

#[test]
pub fn test_mock_nonzero_len_new() {
    test_valid_input_direct([].into(), 5000008, 256, 512, [true, false, true], true);
}

#[test]
pub fn test_mock_nonzero_len_legacy() {
    test_valid_input_direct([].into(), 5000008, 256, 512, [true, false, false], true);
}

#[derive(Serialize, Deserialize)]
struct BenchParams(RlcCircuitParams, usize); // (params, num_slots)

#[test]
#[ignore = "bench"]
pub fn bench_tx() -> Result<(), Box<dyn std::error::Error>> {
    let bench_params_file = File::create("configs/bench/transaction.json").unwrap();
    std::fs::create_dir_all("data/transaction")?;
    let mut fs_results = File::create("data/bench/transaction.csv").unwrap();
    writeln!(fs_results, "degree,num_slots,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,proof_time,verify_time")?;

    let mut all_bench_params = vec![];
    let bench_k_num = vec![(15, 1), (17, 10), (18, 32)];
    for (k, num_slots) in bench_k_num {
        println!("---------------------- degree = {k} ------------------------------",);
        let input = get_test_circuit(
            Chain::Mainnet,
            (0..num_slots).collect(),
            5000008,
            256,
            0,
            [true, false, true],
            false,
        );
        let mut dummy_params = EthCircuitParams::default().rlc;
        dummy_params.base.k = k;
        let mut circuit = create_circuit(CircuitBuilderStage::Keygen, dummy_params, input.clone());
        circuit.mock_fulfill_keccak_promises(None);
        circuit.calculate_params();

        let params = gen_srs(k as u32);
        let vk = keygen_vk(&params, &circuit)?;
        let pk = keygen_pk(&params, vk, &circuit)?;
        let bench_params = circuit.params().rlc;
        let break_points = circuit.break_points();

        // create a proof
        let proof_time = start_timer!(|| "create proof SHPLONK");
        let phase0_time = start_timer!(|| "phase 0 synthesize");
        let circuit = create_circuit(CircuitBuilderStage::Prover, bench_params.clone(), input)
            .use_break_points(break_points);
        circuit.mock_fulfill_keccak_promises(None);
        let instances = circuit.instances();
        end_timer!(phase0_time);
        assert_eq!(instances.len(), 1);
        let proof = gen_proof_with_instances(&params, &pk, circuit, &[&instances[0]]);
        end_timer!(proof_time);

        let verify_time = start_timer!(|| "Verify time");
        check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instances[0]], true);
        end_timer!(verify_time);

        let RlcCircuitParams {
            base:
                BaseCircuitParams {
                    k,
                    num_advice_per_phase,
                    num_fixed,
                    num_lookup_advice_per_phase,
                    ..
                },
            num_rlc_columns,
        } = bench_params.clone();
        writeln!(
            fs_results,
            "{},{},{},{},{:?},{:?},{},{:.2}s,{:?}",
            k,
            num_slots,
            num_rlc_columns
                + num_advice_per_phase.iter().sum::<usize>()
                + num_lookup_advice_per_phase.iter().sum::<usize>(),
            num_rlc_columns,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_fixed,
            proof_time.time.elapsed().as_secs_f64(),
            verify_time.time.elapsed()
        )
        .unwrap();
        all_bench_params.push(BenchParams(bench_params, num_slots));
    }
    serde_json::to_writer_pretty(bench_params_file, &all_bench_params).unwrap();
    Ok(())
}
