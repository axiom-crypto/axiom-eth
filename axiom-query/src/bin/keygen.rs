use std::{
    env,
    fs::{self, File},
    path::PathBuf,
};

use anyhow::Context;
use axiom_eth::{
    snark_verifier_sdk::{evm::gen_evm_verifier_shplonk, halo2::aggregation::AggregationCircuit},
    utils::build_utils::keygen::read_srs_from_dir,
};
use axiom_query::keygen::{
    agg::{common::AggTreePinning, SupportedAggPinning},
    ProvingKeySerializer, SupportedPinning, SupportedRecursiveIntent,
};
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Cli {
    #[arg(long = "srs-dir")]
    pub srs_dir: PathBuf,
    #[arg(long = "data-dir")]
    pub data_dir: Option<PathBuf>,
    #[arg(long = "intent")]
    pub intent_path: PathBuf,
    /// Tag for proof tree file.
    /// Defaults to the aggregate vkey hash (Fr, big-endian) if the circuit is a universal aggregation circuit, or to the root circuit ID otherwise.
    #[arg(short, long = "tag")]
    pub tag: Option<String>,
}

fn main() -> anyhow::Result<()> {
    env_logger::try_init().unwrap();
    let cli = Cli::parse();
    let srs_dir = cli.srs_dir;
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(cargo_manifest_dir).join("data").join("playground")
    });
    fs::create_dir_all(&data_dir).context("Create data dir")?;
    // Directly deserializing from yaml doesn't work, but going to json first does??
    let intent_json: serde_json::Value =
        serde_yaml::from_reader(File::open(&cli.intent_path).with_context(|| {
            format!("Failed to open intent file {}", cli.intent_path.display())
        })?)?;
    let intent: SupportedRecursiveIntent = serde_json::from_value(intent_json)?;
    let (proof_node, pk, pinning) = intent.create_and_serialize_proving_key(&srs_dir, &data_dir)?;
    println!("Circuit id: {}", proof_node.circuit_id);

    let tag = cli.tag.unwrap_or_else(|| {
        if let Some((_, agg_vk_hash)) = pinning.agg_vk_hash_data() {
            format!("{:?}", agg_vk_hash)
        } else {
            proof_node.circuit_id.clone()
        }
    });

    let tree_path = data_dir.join(format!("{tag}.tree"));
    let f = File::create(&tree_path).with_context(|| {
        format!("Failed to create aggregation tree file {}", tree_path.display())
    })?;
    serde_json::to_writer_pretty(f, &proof_node)?;
    println!("Wrote aggregation tree to {}", tree_path.display());

    if let SupportedPinning::Agg(SupportedAggPinning::AxiomAgg2(pinning)) = pinning {
        log::debug!("Creating verifier contract");
        let num_instance = pinning.num_instance();
        let solc_path = data_dir.join(&proof_node.circuit_id).with_extension("sol");
        let k = pinning.params.agg_params.degree;
        let kzg_params = read_srs_from_dir(&srs_dir, k)?;
        gen_evm_verifier_shplonk::<AggregationCircuit>(
            &kzg_params,
            pk.get_vk(),
            num_instance,
            Some(&solc_path),
        );
        println!("Axiom Aggregation 2 snark-verifier contract written to {}", solc_path.display());
    }

    Ok(())
}
