#![cfg(feature = "providers")]
use crate::utils::assign_vec;

use super::*;
use ethers_core::types::Chain;
use halo2_base::halo2_proofs::dev::MockProver;
use serde::{Deserialize, Serialize};
use std::fs::File;
use test_log::test;

#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
/// Contains block information, a single `EthTransactionInput` for a transaction we want to prove in the block,
/// and a `constrain_len` flag that decides whether the number of transactions in the block should be proved as well.
/// In most cases, constrain_len will be set to `false` and len_proof to `None` when this is used.
pub struct EthBlockTransactionFieldInput {
    pub block_number: u32,
    pub block_hash: H256, // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,

    pub tx_input: EthTransactionFieldInput,
    pub constrain_len: bool,
    // Inclusion and noninclusion proof pair of neighboring indices
    pub len_proof: Option<EthTransactionLenProof>,
}

#[derive(Clone, Debug)]
/// Assigned version of `EthTransactionFieldInput`
pub struct EthTransactionFieldInputAssigned<F: Field> {
    pub transaction: EthTransactionInputAssigned<F>,
    pub field_idx: AssignedValue<F>,
}

#[derive(Clone, Debug)]
/// Assigned version of `EthBlockTransactionFieldInput`
pub struct EthBlockTransactionFieldInputAssigned<F: Field> {
    // block_hash: AssignedH256<F>, // H256 as (u128, u128)
    pub block_header: Vec<AssignedValue<F>>,
    pub single_field: EthTransactionFieldInputAssigned<F>,
}

impl EthTransactionFieldInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTransactionFieldInputAssigned<F> {
        let transaction = EthTransactionInputAssigned {
            transaction_index: ctx.load_witness(F::from(self.transaction_index as u64)),
            proof: self.proof.assign(ctx),
        };
        let field_idx = ctx.load_witness(F::from(self.field_idx as u64));
        EthTransactionFieldInputAssigned { transaction, field_idx }
    }
}

impl EthBlockTransactionFieldInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
        network: Chain,
    ) -> EthBlockTransactionFieldInputAssigned<F> {
        let max_len = get_block_header_rlp_max_lens(network).0;
        let block_header = assign_vec(ctx, self.block_header, max_len);
        EthBlockTransactionFieldInputAssigned {
            block_header,
            single_field: self.tx_input.assign(ctx),
        }
    }
}

#[derive(Clone)]
pub struct EthBlockTransactionFieldCircuit<F> {
    pub inputs: EthBlockTransactionFieldInput, // public and private inputs
    pub params: EthTransactionChipParams,
    _marker: PhantomData<F>,
}

impl<F> EthBlockTransactionFieldCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        idxs: Vec<(usize, usize)>, // (tx_idx, field_idx)
        block_number: u32,
        transaction_pf_max_depth: usize,
        network: Chain,
        max_data_byte_len: usize,
        max_access_list_len: usize,
        enable_types: [bool; 3],
        constrain_len: bool,
    ) -> Self {
        use crate::providers::transaction::get_block_transaction_input;

        let tx_idx = idxs.clone().into_iter().map(|p| p.0).collect_vec();
        let inputs = get_block_transaction_input(
            provider,
            tx_idx,
            block_number,
            transaction_pf_max_depth,
            max_data_byte_len,
            max_access_list_len,
            enable_types,
            constrain_len,
        );
        let tx_inputs = inputs
            .tx_proofs
            .into_iter()
            .zip(idxs)
            .map(|(tx_proof, (_, field_idx))| EthTransactionFieldInput {
                transaction_index: tx_proof.tx_index,
                proof: tx_proof.proof,
                field_idx,
            })
            .collect_vec();
        let inputs = EthBlockTransactionFieldInput {
            block_number: inputs.block_number,
            block_hash: inputs.block_hash,
            block_header: inputs.block_header,
            tx_input: tx_inputs[0].clone(),
            constrain_len: false,
            len_proof: None,
        };
        let params = EthTransactionChipParams {
            max_data_byte_len,
            max_access_list_len,
            enable_types,
            network: Some(network),
        };
        Self { inputs, params, _marker: PhantomData }
    }
}

impl<F: Field> EthCircuitInstructions<F> for EthBlockTransactionFieldCircuit<F> {
    type FirstPhasePayload =
        (EthBlockHeaderWitness<F>, EthTransactionWitness<F>, EthTransactionChipParams);
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let chip = EthTransactionChip::new(mpt, self.params);
        let ctx = builder.base.main(FIRST_PHASE);
        let input = self.inputs.clone().assign(ctx, chip.network().unwrap());
        let (block_witness, tx_witness) = chip.parse_transaction_proof_from_block_phase0(
            ctx,
            &input.block_header,
            input.single_field.transaction,
        );
        let _ = chip.extract_field(ctx, tx_witness.clone(), input.single_field.field_idx);
        (block_witness, tx_witness, self.params)
    }
    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        (block_witness, tx_witness, chip_params): Self::FirstPhasePayload,
    ) {
        let chip = EthTransactionChip::new(mpt, chip_params);
        chip.parse_transaction_proof_from_block_phase1(
            builder.rlc_ctx_pair(),
            block_witness,
            tx_witness,
        );
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TxFieldProviderInput {
    pub idxs: Vec<(usize, usize)>,
    pub block_number: usize,
}

fn get_test_field_circuit(
    network: Chain,
    idxs: Vec<(usize, usize)>,
    block_number: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> EthBlockTransactionFieldCircuit<Fr> {
    assert!(idxs.len() == 1);
    let provider = setup_provider(network);

    EthBlockTransactionFieldCircuit::from_provider(
        &provider,
        idxs,
        block_number.try_into().unwrap(),
        6,
        network,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
        false,
    )
}

pub fn test_field_valid_input_json(
    path: String,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) {
    let file_inputs: TxFieldProviderInput =
        serde_json::from_reader(File::open(path).expect("path does not exist")).unwrap();
    let idxs = file_inputs.idxs;
    let block_number = file_inputs.block_number;
    test_field_valid_input_direct(
        idxs,
        block_number,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
    );
}

pub fn test_field_valid_input_direct(
    idxs: Vec<(usize, usize)>,
    block_number: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) {
    let params = get_rlc_params("configs/tests/transaction.json");
    let k = params.base.k as u32;

    let input = get_test_field_circuit(
        Chain::Mainnet,
        idxs,
        block_number,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
    );
    let mut circuit = create_circuit(CircuitBuilderStage::Mock, params, input);
    circuit.mock_fulfill_keccak_promises(None);
    circuit.calculate_params();
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test]
pub fn test_mock_single_field_legacy() {
    test_field_valid_input_direct(vec![(257, 0 /*nonce*/)], 5000008, 256, 0, [true, false, false]);
}

#[test]
pub fn test_mock_single_field_legacy_json() {
    test_field_valid_input_json(
        "src/transaction/tests/data/field/single_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
    );
}

#[test]
pub fn test_mock_single_field_new_json() {
    test_field_valid_input_json(
        "src/transaction/tests/data/field/single_tx_pos_test_new.json".to_string(),
        256,
        512,
        [true, false, true],
    );
}
