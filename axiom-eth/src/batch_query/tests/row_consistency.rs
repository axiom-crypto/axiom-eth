use crate::{
    batch_query::{
        hash::{poseidon_tree_root, PoseidonWords},
        response::{
            native::{
                get_account_response, get_block_response, get_full_account_response,
                get_full_storage_response, get_storage_response,
            },
            row_consistency::{
                RowConsistencyCircuit, ROW_ACCT_POSEIDON_INDEX, ROW_BLOCK_POSEIDON_INDEX,
                ROW_STORAGE_POSEIDON_INDEX,
            },
        },
        tests::storage::get_full_storage_inputs_nouns,
    },
    Network,
};
use halo2_base::{gates::builder::CircuitBuilderStage, halo2_proofs::dev::MockProver};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::{halo2::POSEIDON_SPEC, NativeLoader};
use test_log::test;

fn test_mock_row_consistency_nouns_gen(k: u32, num_rows: usize) {
    let network = Network::Mainnet;
    assert!(num_rows.is_power_of_two());
    let responses = get_full_storage_inputs_nouns(num_rows);

    // compute expected roots
    let mut poseidon = Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());
    let mut block_responses: Vec<PoseidonWords<_>> = vec![];
    let mut full_acct_responses: Vec<PoseidonWords<_>> = vec![];
    let mut full_st_responses: Vec<PoseidonWords<_>> = vec![];
    for responses in &responses {
        let (block_res, _) = get_block_response(&mut poseidon, responses.block.clone(), network);
        let (acct_res, _) = get_account_response(&mut poseidon, &responses.storage);
        let block_res = (block_res.0, responses.block.number.unwrap().as_u32());
        let full_acct_res = get_full_account_response(&mut poseidon, block_res, acct_res.clone());
        let acct_res = (acct_res.0, responses.storage.addr);
        let (storage_res, _) = get_storage_response(&mut poseidon, &responses.storage);
        let full_st_res =
            get_full_storage_response(&mut poseidon, block_res, acct_res, storage_res);
        block_responses.push(block_res.0.into());
        full_acct_responses.push(full_acct_res.0.into());
        full_st_responses.push(full_st_res.0.into());
    }
    let block_root = poseidon_tree_root(&mut poseidon, block_responses, &[]);
    let full_acct_root = poseidon_tree_root(&mut poseidon, full_acct_responses, &[]);
    let full_st_root = poseidon_tree_root(&mut poseidon, full_st_responses, &[]);
    //

    let input = RowConsistencyCircuit::new(
        responses,
        vec![true; num_rows],
        vec![true; num_rows],
        vec![true; num_rows],
        network,
    );
    let circuit = input.create_circuit(CircuitBuilderStage::Mock, None, k);

    let instance = circuit.instance();
    assert_eq!(instance[ROW_BLOCK_POSEIDON_INDEX], block_root);
    assert_eq!(instance[ROW_ACCT_POSEIDON_INDEX], full_acct_root);
    assert_eq!(instance[ROW_STORAGE_POSEIDON_INDEX], full_st_root);
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
}

#[test]
fn test_mock_row_consistency_nouns() {
    test_mock_row_consistency_nouns_gen(19, 128);
}
