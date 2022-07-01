use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    path::PathBuf,
};

use anyhow::Context;
use axiom_core::{keygen::RecursiveCoreIntent, types::CoreNodeType};
use axiom_eth::{
    snark_verifier_sdk::{evm::gen_evm_verifier_shplonk, halo2::aggregation::AggregationCircuit},
    utils::build_utils::keygen::read_srs_from_dir,
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
    /// Tag for the output circuit IDs files. Defaults to the root circuit ID. We auto-add the .cids extension.
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
    fs::create_dir_all(&data_dir)?;
    // Directly deserializing from yaml doesn't work, but going to json first does??
    let intent_json: serde_json::Value = serde_yaml::from_reader(
        File::open(&cli.intent_path)
            .with_context(|| format!("Failed to open file {}", cli.intent_path.display()))?,
    )?;
    let intent: RecursiveCoreIntent = serde_json::from_value(intent_json)?;
    let node_type = intent.params.node_type;
    let k = intent.k_at_depth[0];
    let mut cid_repo = BTreeMap::new();
    let (proof_node, pk, pinning) =
        intent.create_and_serialize_proving_key(&srs_dir, &data_dir, &mut cid_repo)?;
    println!("Circuit id: {}", proof_node.circuit_id);

    if matches!(node_type, CoreNodeType::Evm(_)) {
        log::debug!("Creating verifier contract");
        let num_instance: Vec<usize> = serde_json::from_value(pinning["num_instance"].clone())?;
        let solc_path = data_dir.join(format!("{}.sol", proof_node.circuit_id));
        let kzg_params = read_srs_from_dir(&srs_dir, k as u32)?;
        gen_evm_verifier_shplonk::<AggregationCircuit>(
            &kzg_params,
            pk.get_vk(),
            num_instance,
            Some(&solc_path),
        );
        println!("Verifier contract written to {}", solc_path.display());
    }

    let tag = cli.tag.unwrap_or_else(|| proof_node.circuit_id.clone());

    // Why do we need to do this? https://stackoverflow.com/questions/62977485/how-to-serialise-and-deserialise-btreemaps-with-arbitrary-key-types
    let cids: Vec<_> = cid_repo
        .into_iter()
        .map(|(key, cid)| (serde_json::to_string(&key).unwrap(), cid))
        .collect();
    let cid_path = data_dir.join(format!("{tag}.cids"));
    let f = File::create(&cid_path).with_context(|| {
        format!("Failed to create circuit IDs repository file {}", cid_path.display())
    })?;
    serde_json::to_writer_pretty(f, &cids)?;
    println!("Wrote circuit IDs repository to: {}", cid_path.display());
    Ok(())
}
