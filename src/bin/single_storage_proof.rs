use clap::Parser;
use eth_types::ToBigEndian;
use ethers_core::types::{Address, U256};
use ethers_providers::{Http, Provider};
use halo2_base::utils::fe_to_biguint;
use halo2_curves::bn256::{Fr, G1Affine};
use halo2_mpt::{
    eth::{
        aggregation::{
            evm::{gen_evm_verifier, gen_proof},
            load_aggregation_circuit_degree,
        },
        storage::EthSingleAcctStorageProof,
        EthConfigParams, Network, NETWORK,
    },
    input_gen::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
};
use num_bigint::BigUint;
use plonk_verifier::{
    loader::evm::encode_calldata,
    system::halo2::{
        aggregation::{create_snark_shplonk, gen_pk, gen_srs, AggregationCircuit},
        transcript::evm::EvmTranscript,
    },
};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long = "block-number")]
    block_number: String,
    #[arg(long = "address")]
    address: String,
    #[arg(long = "slot")]
    slot: String,
}

fn main() {
    let args = Cli::parse();
    let block_number = if args.block_number.starts_with("0x") {
        u64::from_str_radix(&args.block_number[2..], 16).expect("Enter proper hex")
    } else {
        u64::from_str_radix(&args.block_number, 10)
            .expect("Block number needs to be base 10 or in hex with 0x prefix")
    };
    let address = args.address.parse::<Address>().unwrap();
    let slot = args.slot.parse::<U256>().unwrap();

    let file = File::open("configs/storage_1.config").unwrap();
    let config: EthConfigParams = serde_json::from_reader(file).unwrap();
    let k = config.degree;
    let provider_url = match NETWORK {
        Network::Mainnet => MAINNET_PROVIDER_URL,
        Network::Goerli => GOERLI_PROVIDER_URL,
    };
    let infura_id = fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
    let provider = Provider::<Http>::try_from(format!("{}{}", provider_url, infura_id).as_str())
        .expect("could not instantiate HTTP Provider");

    let circuit = EthSingleAcctStorageProof::<Fr>::from_provider(
        &provider,
        block_number,
        address,
        slot,
        8,
        8,
        k,
    );
    let instances = circuit.instances();

    let params = gen_srs(k);
    let snark = create_snark_shplonk::<EthSingleAcctStorageProof<Fr>>(
        &params,
        vec![circuit],
        vec![instances],
        None,
    );
    let snarks = vec![snark];

    std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");
    let k = load_aggregation_circuit_degree();
    let params = gen_srs(k);
    let agg_circuit = AggregationCircuit::new(&params, snarks, true);
    let agg_instances = agg_circuit.instances();
    let pk = gen_pk(&params, &agg_circuit, "storage_agg_circuit");

    /*
    let deployment_code = gen_aggregation_evm_verifier(
        &params,
        pk.get_vk(),
        agg_circuit.num_instance(),
        AggregationCircuit::accumulator_indices(),
    );
    fs::write("./data/storage_verifier_bytecode.dat", hex::encode(&deployment_code)).unwrap();
    */

    let proof = gen_proof::<_, _, EvmTranscript<G1Affine, _, _, _>, EvmTranscript<G1Affine, _, _, _>>(
        &params,
        &pk,
        agg_circuit,
        agg_instances.clone(),
    );

    let calldata = encode_calldata(&agg_instances, &proof);

    let mut writer = BufWriter::new(
        File::create(
            format!(
                "./data/calldata_storage_{:x}_{}_{}.dat",
                block_number,
                hex::encode(address.as_bytes()),
                hex::encode(&slot.to_be_bytes())
            )
            .as_str(),
        )
        .unwrap(),
    );
    write!(writer, "{}", hex::encode(&calldata)).unwrap();
}
