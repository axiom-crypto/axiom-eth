use super::setup_provider;
use crate::{
    batch_query::{
        response::{
            account::MultiAccountCircuit,
            block_header::{MultiBlockCircuit, BLOCK_BATCH_DEPTH},
            native::FullStorageQuery,
            row_consistency::RowConsistencyCircuit,
            storage::MultiStorageCircuit,
        },
        scheduler::{
            circuit_types::{
                BlockVerifyVsMmrCircuitType, ExponentialSchema, FinalAssemblyCircuitType,
            },
            router::BatchQueryScheduler,
            tasks::{BlockVerifyVsMmrTask, FinalAssemblyTask, ResponseInput, ResponseTask, Task},
        },
        tests::storage::get_full_storage_queries_nouns_single_block,
    },
    providers::{get_blocks, get_full_storage_queries},
    storage::{
        EthBlockStorageInput, {ACCOUNT_PROOF_MAX_DEPTH, STORAGE_PROOF_MAX_DEPTH},
    },
    util::{
        get_merkle_mountain_range,
        scheduler::{Scheduler, Task as _},
    },
    Network,
};
use ethers_core::{
    types::{Address, H256},
    utils::keccak256,
};
use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::bit_length};
use itertools::Itertools;
use std::{fs::File, path::PathBuf, str::FromStr};
use test_log::test;

fn test_scheduler(network: Network) -> BatchQueryScheduler {
    BatchQueryScheduler::new(
        network,
        false,
        false,
        PathBuf::from("configs/tests/batch_query"),
        PathBuf::from("data/tests/batch_query"),
    )
}

#[test]
fn test_scheduler_account() {
    let schema: ExponentialSchema = serde_json::from_reader(
        File::open("configs/tests/batch_query/schema.account.json").unwrap(),
    )
    .unwrap();
    let len = 1 << schema.total_arity;
    let queries = [
        (17143006, "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B"),
        (17143000, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
        (15000000, "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
        (15411056, "0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6"),
    ]
    .map(|(num, address)| (num, address.parse().unwrap()))
    .to_vec();
    let block_responses = queries.iter().map(|_| (Fr::zero(), 0)).collect();
    let not_empty = vec![true; queries.len()];

    let scheduler = test_scheduler(Network::Mainnet);
    let input =
        MultiAccountCircuit::from_provider(&setup_provider(), block_responses, queries, not_empty);
    let input = MultiAccountCircuit::resize_from(
        input.block_responses,
        input.queries,
        input.not_empty,
        len,
    );
    let task = ResponseTask {
        aggregate: schema.total_arity != schema.start_arity,
        schema,
        input: ResponseInput::Account(input),
    };

    scheduler.get_snark(Task::Response(task));
}

#[test]
fn test_scheduler_storage() {
    let schema: ExponentialSchema = serde_json::from_reader(
        File::open("configs/tests/batch_query/schema.storage.json").unwrap(),
    )
    .unwrap();
    let len = 1 << schema.total_arity;
    let queries = get_full_storage_queries_nouns_single_block(len, 14985438);
    let responses: Vec<_> = get_full_storage_queries(
        &setup_provider(),
        queries,
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap()
    .into_iter()
    .map(|response| EthBlockStorageInput::from(response).storage)
    .collect();
    let not_empty = vec![true; len];

    let scheduler = test_scheduler(Network::Mainnet);
    let input = MultiStorageCircuit::new(
        vec![(Fr::zero(), 0); len],
        vec![(Fr::zero(), Address::zero()); len],
        responses,
        not_empty,
    );
    let task = ResponseTask {
        aggregate: schema.total_arity != schema.start_arity,
        schema,
        input: ResponseInput::Storage(input),
    };

    scheduler.get_snark(Task::Response(task));
}

#[test]
fn test_scheduler_row_consistency() {
    let schema: ExponentialSchema =
        serde_json::from_reader(File::open("configs/tests/batch_query/schema.row.json").unwrap())
            .unwrap();
    let len = 1 << schema.total_arity;
    let queries = get_full_storage_queries_nouns_single_block(len, 12985438);
    let responses: Vec<_> = get_full_storage_queries(
        &setup_provider(),
        queries,
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap()
    .into_iter()
    .map(EthBlockStorageInput::from)
    .collect();

    let scheduler = test_scheduler(Network::Mainnet);
    let input = RowConsistencyCircuit::new(
        responses,
        vec![true; len],
        vec![true; len],
        vec![true; len],
        Network::Mainnet,
    );
    let task = ResponseTask {
        aggregate: schema.total_arity != schema.start_arity,
        schema,
        input: ResponseInput::Row(input),
    };

    scheduler.get_snark(Task::Response(task));
}

#[test]
fn test_scheduler_verify_vs_mmr() {
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
    let len = 1 << arity;
    let mmr_list_len = 16_525_312;
    let mmr = vec![H256::zero(); BLOCK_BATCH_DEPTH]
        .into_iter()
        .chain(MMR_16525312.iter().map(|s| H256::from_str(s).unwrap()))
        .collect();
    let block_numbers = vec![block_number; len];

    let scheduler = test_scheduler(Network::Mainnet);
    let input = MultiBlockCircuit::from_provider(
        &setup_provider(),
        block_numbers,
        vec![true; len],
        Network::Mainnet,
        mmr,
        mmr_list_len,
        vec![merkle_proof; len],
    );
    let task = BlockVerifyVsMmrTask { input, arities: schema.arities };
    println!("{}", task.name());

    scheduler.get_snark(Task::BlockVerifyVsMmr(task));
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

#[test]
fn test_scheduler_final_assembly_old() {
    let block_number = 14_985_438;
    let merkle_proof = [
        "0x4ee507551ceeb4e7cd160e1d6a546f78d7dc5ea29be99e79476a52781e5422a2",
        "0xdfba2ede28a828481f99a0277f6062b3f409370c75dbbdb1f7513fdf43e114c5",
        "0xe315409409b8ad6c0502debcf846d8f4f4d648c7c7598e12306caebb6879cf4d",
        "0x319f29f57fd20fcbd67cf16d1547f2c7206fc402d11640759834574413c7c073",
        "0xd7283aa12b799f869ddb6805d6ee0a6ac70bae8af5eda1fa83d910605902d31a",
        "0xb6ababeeff584afc2ffd2a6239a8421cd36617a07fdfbaaf78e0d98ee5cdd2b2",
        "0x7738be39d3d440a968245f93f2659da6c3955306b70de635caf704a2cd248012",
        "0x9c5f767b3e6bf3e6e3716642d4beaeeb0705e4bce45411b4b130739050b85e3b",
        "0xde3605c75c7c1e971b9615d608112661d407af3ef24945e226b7f0b3694ba102",
        "0x24b2de47bd4094e61e07ee06d40f5a4f4d66999eea97037866eb06c535c70c5d",
        "0x7c8e45373e748b8ec69371841bccbc438e4308d345729e5684c1264ac243dd9d",
        "0x82779b69d134f2dac8998450a341591d53eb19d7b51d57645d6a67fafa0e4cfd",
        "0x6b47cb78db4428a19df5344391d54e1f695576595eadedc82aef81156e3f85a6",
        "0xd9e8dbccb0368b6a0b9d2886a0b1c30776684018474174d7666c08068fba49a9",
        "0xda256132c245db47f729f5d9b8742a5074ec38dd376a5b01496e179863b8e6ef",
        "0xc2cea502d15df8518ddb1834aa172cd4460c5b52d37ac0f38c3a232c1d8d19fb",
        "0x282d4ca5df280766756c3f34dbd986145b41b3ebb1bca021c6cceb9ce7214aba",
        "0xee9f461f804095981853ed2af093769936c30b686f242f67cb8b65d6e59746dd",
        "0x03bb87fd41000fc97ba8639b2439aac2a80389bcb973086d8334930e100f5765",
        "0x3267b39f880cdc657d6639cc25b454e4bf72099572682e3e95dc080c4bd1aa59",
    ]
    .into_iter()
    .map(|s| H256::from_str(s).unwrap())
    .collect_vec();
    let mmr_num_blocks = 16_525_312;
    let mmr = vec![H256::zero(); BLOCK_BATCH_DEPTH]
        .into_iter()
        .chain(MMR_16525312.iter().map(|s| H256::from_str(s).unwrap()))
        .collect();

    let circuit_type: FinalAssemblyCircuitType =
        serde_json::from_reader(File::open("configs/tests/batch_query/schema.final.json").unwrap())
            .unwrap();
    assert_eq!(circuit_type.network, Network::Mainnet);
    let total_arity = circuit_type.account_schema.total_arity;
    let len = 1 << total_arity;

    let queries = get_full_storage_queries_nouns_single_block(len, block_number);
    let input = get_full_storage_queries(
        &setup_provider(),
        queries,
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap();
    let task = Task::Final(FinalAssemblyTask {
        circuit_type,
        input,
        mmr,
        mmr_num_blocks,
        mmr_proofs: vec![merkle_proof; len],
    });
    println!("{}", task.name());

    let scheduler = test_scheduler(Network::Mainnet);
    scheduler.get_calldata(task, true);
}

#[test]
fn test_scheduler_final_assembly_recent() {
    let provider = setup_provider();

    let mmr_num_blocks = 16_525_312;
    let mut side = 777usize;
    let list_len = 888usize;
    let block_number = mmr_num_blocks + side;
    let leaves = get_blocks(&provider, (0..list_len).map(|i| (mmr_num_blocks + i) as u64))
        .unwrap()
        .into_iter()
        .map(|block| block.unwrap().hash.unwrap())
        .collect_vec();
    let mut mmr = get_merkle_mountain_range(&leaves, BLOCK_BATCH_DEPTH - 1);
    mmr.reverse();
    assert_eq!(mmr.len(), BLOCK_BATCH_DEPTH);
    mmr.extend(MMR_16525312.iter().map(|s| H256::from_str(s).unwrap()));

    let mut peak_id = bit_length(list_len as u64) - 1;
    let mut start = 0;
    while (list_len >> peak_id) & 1 == (side >> peak_id) & 1 {
        if (list_len >> peak_id) & 1 == 1 {
            start += 1 << peak_id;
            side -= 1 << peak_id;
        }
        peak_id -= 1;
    }
    let mut current_hashes = leaves[start..start + (1 << peak_id)].to_vec();
    let mut merkle_proof = vec![];
    for i in (1..=peak_id).rev() {
        merkle_proof.push(current_hashes[side ^ 1]);
        for i in 0..(1 << (i - 1)) {
            current_hashes[i] = H256(keccak256(
                [current_hashes[i * 2].as_bytes(), current_hashes[i * 2 + 1].as_bytes()].concat(),
            ));
        }
        side >>= 1;
    }

    let circuit_type: FinalAssemblyCircuitType =
        serde_json::from_reader(File::open("configs/tests/batch_query/schema.final.json").unwrap())
            .unwrap();
    assert_eq!(circuit_type.network, Network::Mainnet);
    let total_arity = circuit_type.account_schema.total_arity;
    let len = 1 << total_arity;

    let queries = get_full_storage_queries_nouns_single_block(len, block_number as u64);
    let input = get_full_storage_queries(
        &setup_provider(),
        queries,
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap();
    let task = Task::Final(FinalAssemblyTask {
        circuit_type,
        input,
        mmr,
        mmr_num_blocks: mmr_num_blocks + list_len,
        mmr_proofs: vec![merkle_proof; len],
    });
    println!("{}", task.name());

    let scheduler = test_scheduler(Network::Mainnet);
    let str = scheduler.get_calldata(task, true);
    println!("{str:?}");
}

#[test]
fn test_scheduler_final_assembly_empty_slots() {
    let block_number = 14_985_438;
    let merkle_proof = [
        "0x4ee507551ceeb4e7cd160e1d6a546f78d7dc5ea29be99e79476a52781e5422a2",
        "0xdfba2ede28a828481f99a0277f6062b3f409370c75dbbdb1f7513fdf43e114c5",
        "0xe315409409b8ad6c0502debcf846d8f4f4d648c7c7598e12306caebb6879cf4d",
        "0x319f29f57fd20fcbd67cf16d1547f2c7206fc402d11640759834574413c7c073",
        "0xd7283aa12b799f869ddb6805d6ee0a6ac70bae8af5eda1fa83d910605902d31a",
        "0xb6ababeeff584afc2ffd2a6239a8421cd36617a07fdfbaaf78e0d98ee5cdd2b2",
        "0x7738be39d3d440a968245f93f2659da6c3955306b70de635caf704a2cd248012",
        "0x9c5f767b3e6bf3e6e3716642d4beaeeb0705e4bce45411b4b130739050b85e3b",
        "0xde3605c75c7c1e971b9615d608112661d407af3ef24945e226b7f0b3694ba102",
        "0x24b2de47bd4094e61e07ee06d40f5a4f4d66999eea97037866eb06c535c70c5d",
        "0x7c8e45373e748b8ec69371841bccbc438e4308d345729e5684c1264ac243dd9d",
        "0x82779b69d134f2dac8998450a341591d53eb19d7b51d57645d6a67fafa0e4cfd",
        "0x6b47cb78db4428a19df5344391d54e1f695576595eadedc82aef81156e3f85a6",
        "0xd9e8dbccb0368b6a0b9d2886a0b1c30776684018474174d7666c08068fba49a9",
        "0xda256132c245db47f729f5d9b8742a5074ec38dd376a5b01496e179863b8e6ef",
        "0xc2cea502d15df8518ddb1834aa172cd4460c5b52d37ac0f38c3a232c1d8d19fb",
        "0x282d4ca5df280766756c3f34dbd986145b41b3ebb1bca021c6cceb9ce7214aba",
        "0xee9f461f804095981853ed2af093769936c30b686f242f67cb8b65d6e59746dd",
        "0x03bb87fd41000fc97ba8639b2439aac2a80389bcb973086d8334930e100f5765",
        "0x3267b39f880cdc657d6639cc25b454e4bf72099572682e3e95dc080c4bd1aa59",
    ]
    .into_iter()
    .map(|s| H256::from_str(s).unwrap())
    .collect_vec();
    let mmr_num_blocks = 16_525_312;
    let mmr = vec![H256::zero(); BLOCK_BATCH_DEPTH]
        .into_iter()
        .chain(MMR_16525312.iter().map(|s| H256::from_str(s).unwrap()))
        .collect();

    let circuit_type: FinalAssemblyCircuitType =
        serde_json::from_reader(File::open("configs/tests/batch_query/schema.final.json").unwrap())
            .unwrap();
    assert_eq!(circuit_type.network, Network::Mainnet);
    let total_arity = circuit_type.account_schema.total_arity;
    let len = 1 << total_arity;

    let address = Address::from_str("0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03").unwrap(); // NounsToken
    let queries = (0..len)
        .map(|_| FullStorageQuery { block_number, addr_slots: Some((address, vec![])) })
        .collect_vec();
    let input = get_full_storage_queries(
        &setup_provider(),
        queries,
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap();
    let task = Task::Final(FinalAssemblyTask {
        circuit_type,
        input,
        mmr,
        mmr_num_blocks,
        mmr_proofs: vec![merkle_proof; len],
    });
    println!("{}", task.name());

    let scheduler = test_scheduler(Network::Mainnet);
    scheduler.get_calldata(task, true);
}

#[test]
fn test_scheduler_final_assembly_empty_accounts() {
    let block_number = 14_985_438;
    let merkle_proof = [
        "0x4ee507551ceeb4e7cd160e1d6a546f78d7dc5ea29be99e79476a52781e5422a2",
        "0xdfba2ede28a828481f99a0277f6062b3f409370c75dbbdb1f7513fdf43e114c5",
        "0xe315409409b8ad6c0502debcf846d8f4f4d648c7c7598e12306caebb6879cf4d",
        "0x319f29f57fd20fcbd67cf16d1547f2c7206fc402d11640759834574413c7c073",
        "0xd7283aa12b799f869ddb6805d6ee0a6ac70bae8af5eda1fa83d910605902d31a",
        "0xb6ababeeff584afc2ffd2a6239a8421cd36617a07fdfbaaf78e0d98ee5cdd2b2",
        "0x7738be39d3d440a968245f93f2659da6c3955306b70de635caf704a2cd248012",
        "0x9c5f767b3e6bf3e6e3716642d4beaeeb0705e4bce45411b4b130739050b85e3b",
        "0xde3605c75c7c1e971b9615d608112661d407af3ef24945e226b7f0b3694ba102",
        "0x24b2de47bd4094e61e07ee06d40f5a4f4d66999eea97037866eb06c535c70c5d",
        "0x7c8e45373e748b8ec69371841bccbc438e4308d345729e5684c1264ac243dd9d",
        "0x82779b69d134f2dac8998450a341591d53eb19d7b51d57645d6a67fafa0e4cfd",
        "0x6b47cb78db4428a19df5344391d54e1f695576595eadedc82aef81156e3f85a6",
        "0xd9e8dbccb0368b6a0b9d2886a0b1c30776684018474174d7666c08068fba49a9",
        "0xda256132c245db47f729f5d9b8742a5074ec38dd376a5b01496e179863b8e6ef",
        "0xc2cea502d15df8518ddb1834aa172cd4460c5b52d37ac0f38c3a232c1d8d19fb",
        "0x282d4ca5df280766756c3f34dbd986145b41b3ebb1bca021c6cceb9ce7214aba",
        "0xee9f461f804095981853ed2af093769936c30b686f242f67cb8b65d6e59746dd",
        "0x03bb87fd41000fc97ba8639b2439aac2a80389bcb973086d8334930e100f5765",
        "0x3267b39f880cdc657d6639cc25b454e4bf72099572682e3e95dc080c4bd1aa59",
    ]
    .into_iter()
    .map(|s| H256::from_str(s).unwrap())
    .collect_vec();
    let mmr_num_blocks = 16_525_312;
    let mmr = vec![H256::zero(); BLOCK_BATCH_DEPTH]
        .into_iter()
        .chain(MMR_16525312.iter().map(|s| H256::from_str(s).unwrap()))
        .collect();

    let circuit_type: FinalAssemblyCircuitType =
        serde_json::from_reader(File::open("configs/tests/batch_query/schema.final.json").unwrap())
            .unwrap();
    assert_eq!(circuit_type.network, Network::Mainnet);
    let total_arity = circuit_type.account_schema.total_arity;
    let len = 1 << total_arity;

    let queries =
        (0..len).map(|_| FullStorageQuery { block_number, addr_slots: None }).collect_vec();
    let input = get_full_storage_queries(
        &setup_provider(),
        queries,
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap();
    let task = Task::Final(FinalAssemblyTask {
        circuit_type,
        input,
        mmr,
        mmr_num_blocks,
        mmr_proofs: vec![merkle_proof; len],
    });
    println!("{}", task.name());

    let scheduler = test_scheduler(Network::Mainnet);
    scheduler.get_calldata(task, true);
}
