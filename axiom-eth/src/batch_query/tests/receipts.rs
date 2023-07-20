use crate::{
    batch_query::response::{block_header::BLOCK_BATCH_DEPTH, receipts::MultiReceiptCircuit},
    receipt::ReceiptRequest,
    rlp::builder::RlcThreadBuilder,
    util::EthConfigParams,
    EthPreCircuit, Network,
};
use ethers_core::types::H256;
use halo2_base::halo2_proofs::dev::MockProver;
use itertools::Itertools;

use std::{env::set_var, str::FromStr};
use test_log::test;

use super::{setup_provider, setup_provider_goerli};

fn test_mock_receipt_queries(
    queries: Vec<ReceiptRequest>,
    mmr: Vec<H256>,
    mmr_proofs: Vec<Vec<H256>>,
    network: Network,
) {
    let params = EthConfigParams::from_path("configs/tests/transaction_query.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let provider = match network {
        Network::Mainnet => setup_provider(),
        _ => setup_provider_goerli(),
    };
    let input = MultiReceiptCircuit::from_provider(
        &provider,
        queries,
        network,
        mmr,
        mmr_proofs,
        128,
        6,
        (0, 4),
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    let instance = circuit.instance();
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
}

#[test]
fn test_mock_receipt_queries_1() {
    let queries = vec![ReceiptRequest {
        tx_hash: H256::from_str(
            "0x725187f197cbc28766304299191171891b72fa7ccfd1d70255c6296daf5212a7",
        )
        .unwrap(),
        field_idx: 3,
        log_idx: Some(0),
    }];
    let merkle_proof = vec![[
        "0x0c49a468469a9c0af040376aeecc1a6625ccd188005ada6202c9349e0b2b1c7e",
        "0xad2cf9b6a35ec994afd298cfda444dd3bc858bd98a72cae19d6746c4d43a378f",
        "0x3860d4943d890e2120af1e764ce10060b2a9d348f6f89e183f155dd1f1c0b3f6",
        "0x37a4e5a773a65924ec281ad1bb6f9006530d0a6d2dd557365f75628da046e4e7",
        "0x3adc9d22627ff5c298f506e0dfbb83745ba889f747f4888410aa9be05b883beb",
        "0x1fe33fae325abc07a8fe265103338699d0e0fae4b740b53a182556809bc45f13",
        "0xef7a1b2657b1e90c747536ed1edf90cdb552022841fec94fbe5735fd9b8bf113",
        "0x0f62ca6c4928d159b968e69708d7ccc3b704b8d7c4192d29d5513d3c12ea3492",
        "0x22f91717e2361a8269b8b7f2c5296ea91d93da651457ad7ffc67e8216e45d61c",
        "0x9ea188da4461fbcff96a42e44a4a6526528508b037e884e895bf9ff181a0a631",
        "0x42d225f31886410369452490a02a0d54ad311ccec6e2ea617942f3de0e63c2df",
        "0x2ea5b5d642306fb61a646a56621f8e17a5c8c29d1bc382cfc1ef5567e5ee6842",
        "0x9032d519db6cae76bd6bfba6ce210ce36d208791ee1157413ad0465be74b3770",
        "0xa7f4d56dd1fb81828199e77a205c86e2ed8d41e87d2f733c1ae171a04012bed0",
        "0xdf69cb8c19b513b888aee79d2dfaa03ef4128f5628e0dae02a3f0348a87c6e5f",
        "0x677f0ec9ecef0a39918979673c0e1286818509e8b0b24718d548927e60b38ca7",
        "0xddebf1eaa86f2500698cf1de0b1b5c8f1963991a97af381afd27d5c9e6545a49",
        "0x3643992767358e54ed59b4c36f7356be744c1c8234f383c79b970088c0e90872",
        "0x43062e083f5f40510f30723d9cebb51c4ae67c35d86c5b791a043bae317350e3",
        "0x6cddc980f4c3b403d99080c32b3f0a6205e39560b9021d5f233c04d96c23381e",
        "0x6a42052cabd8d66a584b8823c6aadf64dd2755321210c66a2b7acd1da5bdeacf",
        "0xebf08ca711cbab09109bb51277c545ee43073d8fa8b46c0cbbedd46ce85e73be",
        "0x477c055e69de14e3bbfe2af0389e6c3ac28ffb5b0cc8fa26b543ac47857fd646",
        "0xf47e6584af17667881494720b50dd063d0900b288438df7a37e2e91440aedd23",
    ]
    .into_iter()
    .map(|s| H256::from_str(s).unwrap())
    .collect_vec()];

    let historical_mmr = [
        "0xd2fcfe5ff5e4c3509468fa208708f7de5abe4894b16bfe36c4bdb465ae134bdd",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x577956894541f12e359ba6428306edbdc4e16f30eb33aea225412a4c619fbcd3",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xe553f451efe36070afa3e1bec68987919dbdb8b01153ff51b2c8ed222f95595a",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x37e7688219e9ad6573641ecda977fffa02efb76340ccd2f0726832bc9af0b0c0",
        "0xd917e847ca54394b03475e17edde6598f4ac6772f3d517eea1e9f8134a8a89c2",
        "0xbfed61dc28eb972a55ce01242ce04921e59e35bf83b5b26cbbbec7f23ddabe56",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x4755084f1c80a73395852c7ede586dddb3b8db7828e4ad2cf3259f693ac4f875",
    ];
    let mmr = vec![H256::zero(); BLOCK_BATCH_DEPTH]
        .into_iter()
        .chain(historical_mmr.iter().map(|s| H256::from_str(s).unwrap()))
        .collect();

    test_mock_receipt_queries(queries, mmr, merkle_proof, Network::Mainnet);
}