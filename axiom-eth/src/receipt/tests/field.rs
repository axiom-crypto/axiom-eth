#![cfg(feature = "providers")]
use super::*;
use crate::block_header::get_block_header_rlp_max_lens;
use crate::providers::setup_provider;
use ethers_core::types::H256;

use halo2_base::halo2_proofs::dev::MockProver;

use ethers_providers::{JsonRpcClient, Provider};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use std::fs::File;
use test_log::test;

//pub mod field;

#[derive(Clone, Debug)]
pub struct EthBlockReceiptFieldCircuit<F> {
    pub inputs: EthBlockReceiptInput, // public and private inputs
    pub field_idx: usize,
    pub log_idx: usize,
    pub params: EthReceiptChipParams,
    _marker: PhantomData<F>,
}

impl<F> EthBlockReceiptFieldCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        tx_hash: H256,
        field_idx: usize,
        log_idx: usize,
        receipt_pf_max_depth: usize,
        network: Chain,
        max_data_byte_len: usize,
        max_log_num: usize,
        topic_num_bounds: (usize, usize),
    ) -> Self {
        use crate::providers::receipt::get_block_receipt_input;

        let inputs = get_block_receipt_input(
            provider,
            tx_hash,
            receipt_pf_max_depth,
            max_data_byte_len,
            max_log_num,
            topic_num_bounds,
        );
        let params = EthReceiptChipParams {
            max_data_byte_len,
            max_log_num,
            topic_num_bounds,
            network: Some(network),
        };
        Self { inputs, field_idx, log_idx, params, _marker: PhantomData }
    }
}

impl<F: Field> EthCircuitInstructions<F> for EthBlockReceiptFieldCircuit<F> {
    type FirstPhasePayload = (EthBlockHeaderWitness<F>, EthReceiptWitness<F>, EthReceiptChipParams);
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let ctx = builder.base.main(FIRST_PHASE);
        let chip = EthReceiptChip::new(mpt, self.params);
        let max_header_len = get_block_header_rlp_max_lens(chip.network().unwrap()).0;
        let field_idx = ctx.load_witness(F::from(self.field_idx as u64));
        let log_idx = ctx.load_witness(F::from(self.log_idx as u64));
        let block_header = assign_vec(ctx, self.inputs.block_header.clone(), max_header_len);
        let block_witness = chip.block_header_chip().decompose_block_header_phase0(
            ctx,
            mpt.keccak(),
            &block_header,
        );
        let receipts_root = &block_witness.get_receipts_root().field_cells;
        let tx_idx = ctx.load_witness(F::from(self.inputs.receipt.idx as u64));
        let proof = self.inputs.receipt.proof.clone().assign(ctx);
        let rc_input = EthReceiptInputAssigned { tx_idx, proof };
        // check MPT root of transaction_witness is block_witness.transaction_root
        let receipt_witness = {
            let witness = chip.parse_receipt_proof_phase0(ctx, rc_input);
            // check MPT root is transactions_root
            for (pf_byte, byte) in
                witness.mpt_witness.root_hash_bytes.iter().zip_eq(receipts_root.iter())
            {
                ctx.constrain_equal(pf_byte, byte);
            }
            witness
        };

        let field_witness = chip.extract_receipt_field(ctx, &receipt_witness, field_idx);
        let log_witness = chip.extract_receipt_log(ctx, &receipt_witness, log_idx);
        println!("FIELD_LEN: {:?}", field_witness.value_len);
        println!("FIELD_BYTES: {:?}", &field_witness.value_bytes[0..16]);
        println!("LOG_LEN: {:?}", log_witness.log_len);
        println!("LOG_BYTES: {:?}", &log_witness.log_bytes[0..16]);
        (block_witness, receipt_witness, self.params)
    }

    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        (block_witness, receipt_witness, chip_params): Self::FirstPhasePayload,
    ) {
        let chip = EthReceiptChip::new(mpt, chip_params);
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        let _receipt_trace = chip.parse_receipt_proof_phase1((ctx_gate, ctx_rlc), receipt_witness);
        let _block_trace = chip
            .block_header_chip()
            .decompose_block_header_phase1((ctx_gate, ctx_rlc), block_witness);
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptFieldProviderInput {
    pub tx_hash: H256,
    pub field_idx: usize,
    pub log_idx: usize,
}

fn get_test_circuit(
    network: Chain,
    tx_hash: H256,
    field_idx: usize,
    log_idx: usize,
    max_data_byte_len: usize,
    max_log_num: usize,
    topic_num_bounds: (usize, usize),
) -> EthBlockReceiptFieldCircuit<Fr> {
    let provider = setup_provider(network);

    EthBlockReceiptFieldCircuit::from_provider(
        &provider,
        tx_hash,
        field_idx,
        log_idx,
        6,
        network,
        max_data_byte_len,
        max_log_num,
        topic_num_bounds,
    )
}

pub fn test_valid_input_json(
    path: String,
    max_data_byte_len: usize,
    max_log_num: usize,
    topic_num_bounds: (usize, usize),
) {
    let file_inputs: ReceiptFieldProviderInput =
        serde_json::from_reader(File::open(path).expect("path does not exist")).unwrap();
    let tx_hash = file_inputs.tx_hash;
    let field_idx = file_inputs.field_idx;
    let log_idx = file_inputs.log_idx;
    test_valid_input_direct(
        tx_hash,
        field_idx,
        log_idx,
        max_data_byte_len,
        max_log_num,
        topic_num_bounds,
    );
}

pub fn test_valid_input_direct(
    tx_hash: H256,
    field_idx: usize,
    log_idx: usize,
    max_data_byte_len: usize,
    max_log_num: usize,
    topic_num_bounds: (usize, usize),
) {
    let params = get_rlc_params("configs/tests/transaction.json");
    let k = params.base.k as u32;

    let input = get_test_circuit(
        Chain::Mainnet,
        tx_hash,
        field_idx,
        log_idx,
        max_data_byte_len,
        max_log_num,
        topic_num_bounds,
    );
    let mut circuit = create_circuit(CircuitBuilderStage::Mock, params, input);
    circuit.mock_fulfill_keccak_promises(None);
    circuit.calculate_params();
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test]
pub fn test_mock_single_rc_field_legacy() {
    test_valid_input_json(
        "src/receipt/tests/data/field/single_rc_pos_test_legacy.json".to_string(),
        256,
        8,
        (0, 4),
    );
}

#[test]
pub fn test_mock_single_rc_field_new() {
    test_valid_input_json(
        "src/receipt/tests/data/field/single_rc_pos_test_new.json".to_string(),
        256,
        8,
        (0, 4),
    );
}
