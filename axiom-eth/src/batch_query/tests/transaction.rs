use crate::{
    batch_query::{
        response::{block_header::BLOCK_BATCH_DEPTH, transaction::MultiTransactionCircuit},
        scheduler::circuit_types::BlockVerifyVsMmrCircuitType,
    },
    providers::get_block_transaction_input,
    rlp::builder::RlcThreadBuilder,
    transaction::{
        EthBlockTransactionFieldInput, EthTransactionFieldInput, TRANSACTION_PROOF_MAX_DEPTH,
    },
    util::EthConfigParams,
    EthPreCircuit, Network,
};
use ethers_core::types::H256;
use halo2_base::halo2_proofs::dev::MockProver;
use itertools::Itertools;

use std::{env::set_var, fs::File, str::FromStr};
use test_log::test;

use super::setup_provider;

fn test_mock_transaction_queries(
    block_numbers: Vec<u32>,
    queries: Vec<(usize, usize)>,
    mmr: Vec<H256>,
    mmr_list_len: usize,
    mmr_proofs: Vec<Vec<H256>>,
    network: Network,
) {
    let params = EthConfigParams::from_path("configs/tests/transaction_query.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let mut inputs = Vec::new();
    assert_eq!(block_numbers.len(), queries.len());
    for i in 0..block_numbers.len() {
        let input = get_block_transaction_input(
            &setup_provider(),
            vec![queries[i].0],
            block_numbers[i],
            TRANSACTION_PROOF_MAX_DEPTH,
            768,
            0, // no support for access list
            [true, false, true],
            false,
        );
        // let tx_input = input
        //     .tx_input
        //     .transaction_pfs
        //     .iter()
        //     .zip(queries.iter())
        //     .map(|(pf, query)| (pf.clone(), query.1.clone()))
        //     .collect();
        let tx_input = EthTransactionFieldInput {
            transaction_index: queries[i].0,
            proof: input.txs.transaction_pfs[0].2.clone(),
            field_idx: queries[i].0,
        };
        let input = EthBlockTransactionFieldInput {
            block_number: input.block_number,
            block_hash: input.block_hash,
            block_header: input.block_header,
            tx_input,
            constrain_len: input.constrain_len,
            len_proof: input.len_proof,
        };
        inputs.push(input);
    }
    let input = MultiTransactionCircuit::resize_from(
        inputs,
        2,
        network,
        mmr,
        mmr_list_len,
        mmr_proofs,
        768,
        0,
        [true, false, true],
    );

    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    let instance = circuit.instance();
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
}

#[test]
fn test_mock_transaction_queries_slot0() {
    let queries = vec![(0, 4)];
    // note that block response is not checked in any way in the circuit, in particular the poseidon and keccak parts don't even need to be consistent!
    let block_number = 12_985_438;
    let merkle_proof = [
        "0xebd5fc0be32c2298e2ee18dac2db5b1508a64741ba7186dd59229ec0620d9d64",
        "0x9139f12e0f47241172143fc5d0b0245b5ffbcdf9130da9efb14c155f6036697e",
        "0x97f5d40bc9a10e06b5eef7609a3e364f30ab10675d22fbc3304179a381b39b18",
        "0xc8c07e6c877f0cd60903d376c1aa911f47c96d3967d989101ed8b873cf6e38de",
        "0x96cf53edbe3be783378433c518939a7e0b4e657edb6558b1f6e14edc0a125a18",
        "0xfa3448a664e9406ffdc3b53e24f06fcf6b576621f854e421385bd1603ea257ee",
        "0x9dffc8cb737d72da73df5e333bb7716cfec51e4b761281c6c7ff4db55689911c",
        "0xef3fb7b7274810ec5bc63e7c248ea7dfe26d95abcd8bcb8d97b1f5fb617b8dc8",
        "0x6a4d92e38592f280afc95efe5dd178a37c155bfad49759db7a066d597bc804d3",
        "0x7db79de6d79e2ff264f4d171243f5038b575b380d31b052dda979e28fae7fc08",
        "0x3106ece6d5a3c317f17c9313e7d0a3cd73649662301f50fdcedc67254b3fe153",
        "0x902c8cf11e8d5cf14137e632061a52574515a2254fbd3b70cfc85a45f9dbcb4a",
        "0xc48c7fe69133ac6f0c2200e600a3c15fe1832577156bc8851a7538403eafadfa",
        "0x4434e3730dbe222cb8b98703748da1f07f05564c64ea66fe4765484ea982f5d6",
        "0x69d2bc461de5dba21f741bf757d60ec8a92c3f29e417cb99fa76459bc3e86278",
        "0xe18396e487f6c0bcd73a2d4c4c8c3583be7edefe59f20b2ce67c7f363b8a856a",
        "0xa10b0dd9e041c793d0dbdf615bee9e18c3f6e3b191469bbb8cc9912d5d228050",
        "0xa51d50eb9feaaf85b7ddacb99f71886135f1c4f59de3e788a5e29a485d5fdce5",
        "0xa46b70512bfe0b85498e28ae8187cfadff9e58680b84ddcde450cd880ea489b1",
        "0x33552dfc75e340bca3c698e4fb486ae540d07cf2a845465575cff24d866a161a",
        "0x0fec590ac8394abe8477b828bf31b470d95772b3f331ff5be34ba0a899975a17",
    ]
    .into_iter()
    .map(|s| H256::from_str(s).unwrap())
    .collect_vec();

    let schema: BlockVerifyVsMmrCircuitType =
        serde_json::from_reader(File::open("configs/tests/batch_query/schema.block.json").unwrap())
            .unwrap();
    let arity: usize = schema.arities.iter().sum();
    let _len = 1 << arity;
    let mmr_list_len = 16_525_312;
    let mmr = vec![H256::zero(); BLOCK_BATCH_DEPTH]
        .into_iter()
        .chain(MMR_16525312.iter().map(|s| H256::from_str(s).unwrap()))
        .collect();
    let block_numbers = vec![block_number];
    test_mock_transaction_queries(
        block_numbers,
        queries,
        mmr,
        mmr_list_len,
        vec![merkle_proof],
        Network::Mainnet,
    );
}

const MMR_16525312: &[&str] = &[
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0xe81cc62bb288e100856ea7d40af72b844e9dcb9ff8ebed659a475e2635cd4e18",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0xb169c87af2d231bc71f910481d6d8315a6fc4edfab212ee003d206b9643339c0",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x43062e083f5f40510f30723d9cebb51c4ae67c35d86c5b791a043bae317350e3",
    "0x6cddc980f4c3b403d99080c32b3f0a6205e39560b9021d5f233c04d96c23381e",
    "0x6a42052cabd8d66a584b8823c6aadf64dd2755321210c66a2b7acd1da5bdeacf",
    "0xebf08ca711cbab09109bb51277c545ee43073d8fa8b46c0cbbedd46ce85e73be",
    "0x477c055e69de14e3bbfe2af0389e6c3ac28ffb5b0cc8fa26b543ac47857fd646",
    "0xf47e6584af17667881494720b50dd063d0900b288438df7a37e2e91440aedd23",
];
