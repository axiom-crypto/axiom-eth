use super::{
    aggregation::{
        AggregationWithKeccakConfigParams, EthBlockHeaderChainAggregationCircuit,
        EthBlockHeaderChainFinalAggregationCircuit,
    },
    EthBlockHeaderChainCircuit, EthBlockHeaderChainInstance,
};
use crate::{util::EthConfigParams, Network};
use core::cmp::min;
use ethers_providers::{Http, Provider};
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::ProvingKey,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::{fs::gen_srs, PrimeField},
};
use halo2_mpt::keccak::zkevm::util::eth_types::Field;
use itertools::Itertools;
use rand::Rng;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{
        aggregation::load_verify_circuit_degree, gen_snark_gwc, gen_snark_shplonk, read_snark,
        PoseidonTranscript,
    },
    CircuitExt, NativeLoader, Snark, LIMBS,
};
use std::{borrow::Cow, env::set_var, fs::File, path::Path, vec};

/// Given
/// - a JSON-RPC provider
/// - choice of EVM network
/// - a range of block numbers
/// - a universal trusted setup,
///
/// this function will generate a ZK proof for the block header chain between blocks `start_block_number` and `end_block_number` inclusive.
///
/// If a proving key is provided, it will be used to generate the proof. Otherwise, a new proving key will be generated.
///
/// The SNARK's public instance will include a merkle mountain range up to depth `max_depth`.
///
/// This SNARK does not use aggregation: it uses a single `EthBlockHeaderChainCircle` circuit,
/// so it may not be suitable for large block ranges.
///
/// Note: we assume that `params` is the correct size for the circuit.
pub fn gen_block_header_chain_snark<'pk>(
    params: &ParamsKZG<Bn256>,
    pk: Option<&'pk ProvingKey<G1Affine>>,
    provider: &Provider<Http>,
    network: Network,
    start_block_number: u32,
    end_block_number: u32,
    max_depth: usize,
    transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
    rng: &mut (impl Rng + Send),
) -> (Snark, EthBlockHeaderChainInstance, Cow<'pk, ProvingKey<G1Affine>>) {
    let num_blocks = end_block_number - start_block_number + 1;
    let circuit = EthBlockHeaderChainCircuit::from_provider(
        provider,
        network,
        start_block_number,
        num_blocks,
        max_depth,
    );
    set_var("BLOCK_HEADER_CONFIG", format!("configs/headers/{network}_{max_depth}.json"));
    let pk = match pk {
        Some(pk) => Cow::Borrowed(pk),
        None => Cow::Owned(gen_pk(
            params,
            &circuit,
            Some(Path::new(&format!("data/headers/{network}_{max_depth}.pkey"))),
        )),
    };

    let instance_path = format!(
        "data/headers/{network}_{max_depth}_{start_block_number:06x}_{end_block_number:06x}.in"
    );
    let instance = circuit.instance.clone();
    bincode::serialize_into(File::create(instance_path).unwrap(), &instance).unwrap();

    let snark_path = format!(
        "data/headers/{network}_{max_depth}_{start_block_number:06x}_{end_block_number:06x}.snark"
    );
    (
        gen_snark_shplonk(params, &pk, circuit, transcript, rng, Some(Path::new(&snark_path))),
        instance,
        pk,
    )
}

pub fn read_block_header_chain_snark(
    network: Network,
    start_block_number: u32,
    end_block_number: u32,
    max_depth: usize,
    initial_depth: usize,
) -> Result<(Snark, EthBlockHeaderChainInstance), bincode::Error> {
    assert!(end_block_number - start_block_number < 1 << max_depth);
    let name = if max_depth == initial_depth {
        format!(
            "data/headers/{network}_{max_depth}_{start_block_number:06x}_{end_block_number:06x}"
        )
    } else {
        format!(
        "data/headers/{network}_{max_depth}_{initial_depth}_{start_block_number:06x}_{end_block_number:06x}")
    };
    let instance_path = format!("{name}.in");
    let snark_path = format!("{name}.snark");
    let instance = bincode::deserialize_from(File::open(instance_path)?)?;
    let snark = read_snark(snark_path)?;
    Ok((snark, instance))
}

impl<F: Field + PrimeField> CircuitExt<F> for EthBlockHeaderChainCircuit<F> {
    type ExtraCircuitParams = usize;
    fn extra_params(&self) -> Self::ExtraCircuitParams {
        self.max_depth
    }

    fn num_instance(max_depth: &usize) -> Vec<usize> {
        vec![Self::get_num_instance(*max_depth)]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instance.to_instance()]
    }
}

// To keep srs and pk in memory, we use this function to generate multiple instances of the same snark
pub fn gen_multiple_block_header_chain_snarks(
    provider: &Provider<Http>,
    network: Network,
    start_block_number: u32,
    end_block_number: u32,
    max_depth: usize,
    initial_depth: usize,
    transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
    rng: &mut (impl Rng + Send),
) -> Vec<(Snark, EthBlockHeaderChainInstance)> {
    // first try to just read them all from files
    let snarks = (start_block_number..=end_block_number)
        .step_by(1 << max_depth)
        .map(|start| {
            let end = min(start + (1 << max_depth) - 1, end_block_number);
            read_block_header_chain_snark(network, start, end, max_depth, initial_depth).ok()
        })
        .collect_vec();
    if snarks.iter().all(|snark| snark.is_some()) {
        return snarks.into_iter().map(|snark| snark.unwrap()).collect_vec();
    }

    // otherwise create srs and pk in order to generate missing snarks
    let k = if max_depth == initial_depth {
        set_var("BLOCK_HEADER_CONFIG", format!("configs/headers/{network}_{max_depth}.json"));
        EthConfigParams::get().degree
    } else {
        set_var(
            "VERIFY_CONFIG",
            format!("configs/headers/{network}_{max_depth}_{initial_depth}.json"),
        );
        load_verify_circuit_degree()
    };
    let params = gen_srs(k);
    let mut pk = None;
    let mut start = start_block_number;
    snarks
        .into_iter()
        .map(|snark| {
            let end = min(start + (1 << max_depth) - 1, end_block_number);
            let snark = snark.unwrap_or_else(|| {
                let (snark, instance, cow_pk) = gen_block_header_chain_snark_with_aggregation(
                    &params,
                    pk.as_ref(),
                    provider,
                    network,
                    start,
                    end,
                    max_depth,
                    initial_depth,
                    transcript,
                    rng,
                );
                if pk.is_none() {
                    pk = Some(cow_pk.into_owned());
                }
                (snark, instance)
            });
            start += 1 << max_depth;
            snark
        })
        .collect()
}

/// Given
/// - a JSON-RPC provider
/// - choice of EVM network
/// - a range of block numbers
/// - a universal trusted setup,
///
/// this function will generate a ZK proof for the block header chain between blocks `start_block_number` and `end_block_number` inclusive. The public instances are NOT finalized,
/// as the merkle mountain range is not fully computed.
///
/// If a proving key is provided, it will be used to generate the proof. Otherwise, a new proving key will be generated.
///
/// This SNARK uses recursive aggregation between depth `max_depth` and `initial_depth + 1`. At `initial_depth` it falls back to the `EthBlockHeaderChainCircle` circuit.
/// At each depth, it will try to load snarks of the previous depth from disk, and if it can't find them, it will generate them.
///
/// Note: we assume that `params` is the correct size for the circuit.
pub fn gen_block_header_chain_snark_with_aggregation<'pk>(
    params: &ParamsKZG<Bn256>,
    pk: Option<&'pk ProvingKey<G1Affine>>,
    provider: &Provider<Http>,
    network: Network,
    start_block_number: u32,
    end_block_number: u32,
    max_depth: usize,
    initial_depth: usize,
    transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
    rng: &mut (impl Rng + Send),
) -> (Snark, EthBlockHeaderChainInstance, Cow<'pk, ProvingKey<G1Affine>>) {
    if max_depth == initial_depth {
        return gen_block_header_chain_snark(
            params,
            pk,
            provider,
            network,
            start_block_number,
            end_block_number,
            initial_depth,
            transcript,
            rng,
        );
    }
    let prev_depth = max_depth - 1;
    let num_blocks = end_block_number - start_block_number + 1;
    assert!(num_blocks <= 1 << max_depth);

    // load or generate the previous depth snarks
    let mut prev_snarks = gen_multiple_block_header_chain_snarks(
        provider,
        network,
        start_block_number,
        end_block_number,
        prev_depth,
        initial_depth,
        transcript,
        rng,
    );
    assert!(prev_snarks.len() <= 2);
    if prev_snarks.len() != 2 {
        assert!(num_blocks <= 1 << prev_depth);
        // add a dummy snark
        prev_snarks.push(prev_snarks[0].clone());
    }
    let (prev_snarks, prev_instances): (Vec<_>, Vec<_>) = prev_snarks.into_iter().unzip();
    let circuit = EthBlockHeaderChainAggregationCircuit::new(
        params,
        prev_snarks,
        prev_instances.try_into().unwrap(),
        transcript,
        rng,
        num_blocks,
        max_depth,
        initial_depth,
    );

    set_var("VERIFY_CONFIG", format!("configs/headers/{network}_{max_depth}_{initial_depth}.json"));
    let name = format!("data/headers/{network}_{max_depth}_{initial_depth}");
    let pk = match pk {
        Some(pk) => Cow::Borrowed(pk),
        None => Cow::Owned(gen_pk(params, &circuit, Some(Path::new(&format!("{name}.pkey"))))),
    };

    let name = format!("{name}_{start_block_number:6x}_{end_block_number:6x}");
    let instance = circuit.chain_instance.clone();
    bincode::serialize_into(File::create(format!("{name}.in")).unwrap(), &instance).unwrap();

    let snark_path = format!("{name}.snark");
    (
        gen_snark_shplonk(params, &pk, circuit, transcript, rng, Some(Path::new(&snark_path))),
        instance,
        pk,
    )
}

impl CircuitExt<Fr> for EthBlockHeaderChainAggregationCircuit {
    type ExtraCircuitParams = (usize, usize);
    fn extra_params(&self) -> Self::ExtraCircuitParams {
        (self.max_depth, self.initial_depth)
    }

    fn num_instance((max_depth, initial_depth): &(usize, usize)) -> Vec<usize> {
        vec![4 * LIMBS + Self::get_num_instance(*max_depth, *initial_depth)]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instance()]
    }
}

/// Given
/// - a JSON-RPC provider
/// - choice of EVM network
/// - a range of block numbers
/// - a universal trusted setup,
///
/// this function will generate a ZK proof for the block header chain between blocks `start_block_number` and `end_block_number` inclusive. The public output is FINALIZED, with
/// a complete merkle mountain range.
///
/// If a proving key is provided, it will be used to generate the proof. Otherwise, a new proving key will be generated.
///
/// This SNARK uses recursive aggregation between depth `max_depth` and `initial_depth + 1`. At `initial_depth` it falls back to the `EthBlockHeaderChainCircle` circuit.
/// At each depth, it will try to load snarks of the previous depth from disk, and if it can't find them, it will generate them.
///
/// Note: we assume that `params` is the correct size for the circuit.
pub fn gen_final_block_header_chain_snark<'pk>(
    params: &ParamsKZG<Bn256>,
    pk: Option<&'pk ProvingKey<G1Affine>>,
    provider: &Provider<Http>,
    network: Network,
    start_block_number: u32,
    end_block_number: u32,
    max_depth: usize,
    initial_depth: usize,
    transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
    rng: &mut (impl Rng + Send),
) -> (Snark, Cow<'pk, ProvingKey<G1Affine>>) {
    // otherwise create srs and pk in order to generate missing snarks
    if max_depth == initial_depth {
        let (snark, _, pk) = gen_block_header_chain_snark(
            params,
            pk,
            provider,
            network,
            start_block_number,
            end_block_number,
            initial_depth,
            transcript,
            rng,
        );
        return (snark, pk);
    }
    let prev_depth = max_depth - 1;
    let num_blocks = end_block_number - start_block_number + 1;
    assert!(num_blocks <= 1 << max_depth);

    // load or generate the previous depth snarks
    let mut prev_snarks = gen_multiple_block_header_chain_snarks(
        provider,
        network,
        start_block_number,
        end_block_number,
        prev_depth,
        initial_depth,
        transcript,
        rng,
    );
    assert!(prev_snarks.len() <= 2);
    if prev_snarks.len() != 2 {
        assert!(num_blocks <= 1 << prev_depth);
        // add a dummy snark
        prev_snarks.push(prev_snarks[0].clone());
    }
    let (prev_snarks, prev_instances): (Vec<_>, Vec<_>) = prev_snarks.into_iter().unzip();
    let circuit = EthBlockHeaderChainFinalAggregationCircuit::new(
        params,
        prev_snarks,
        prev_instances.try_into().unwrap(),
        transcript,
        rng,
        num_blocks,
        max_depth,
        initial_depth,
    );
    set_var(
        "FINAL_AGGREGATION_CONFIG",
        format!("configs/headers/{network}_{max_depth}_{initial_depth}_final.json"),
    );
    let pk = match pk {
        Some(pk) => Cow::Borrowed(pk),
        None => Cow::Owned(gen_pk(
            params,
            &circuit,
            Some(Path::new(&format!(
                "data/headers/{network}_{max_depth}_{initial_depth}_final.pkey"
            ))),
        )),
    };

    let name = format!("data/headers/{network}_{max_depth}_{initial_depth}_{start_block_number:6x}_{end_block_number:6x}_final");
    let snark_path = format!("{name}.snark");
    (gen_snark_shplonk(params, &pk, circuit, transcript, rng, Some(Path::new(&snark_path))), pk)
}

impl CircuitExt<Fr> for EthBlockHeaderChainFinalAggregationCircuit {
    type ExtraCircuitParams = usize;
    fn extra_params(&self) -> Self::ExtraCircuitParams {
        self.0.max_depth
    }

    fn num_instance(max_depth: &usize) -> Vec<usize> {
        vec![4 * LIMBS + Self::get_num_instance(*max_depth)]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instance()]
    }
}

pub fn autogen_final_block_header_chain_snark(
    provider: &Provider<Http>,
    network: Network,
    start_block_number: u32,
    end_block_number: u32,
    max_depth: usize,
    initial_depth: usize,
    transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
    rng: &mut (impl Rng + Send),
) -> Snark {
    let path = format!("data/headers/{network}_{max_depth}_{initial_depth}_{start_block_number:6x}_{end_block_number:6x}_final.snark");
    let snark = read_snark(path);
    if let Ok(snark) = snark {
        return snark;
    }
    set_var(
        "FINAL_AGGREGATION_CONFIG",
        format!("configs/headers/{network}_{max_depth}_{initial_depth}_final.json"),
    );
    let k = AggregationWithKeccakConfigParams::get().aggregation.degree;
    let params = gen_srs(k);
    gen_final_block_header_chain_snark(
        &params,
        None,
        provider,
        network,
        start_block_number,
        end_block_number,
        max_depth,
        initial_depth,
        transcript,
        rng,
    )
    .0
}

#[cfg(feature = "evm")]
pub mod evm {
    use super::*;
    use snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk, write_calldata},
        gen_pk,
        halo2::aggregation::EvmVerifierAfterAggregationCircuit,
    };

    pub fn autogen_final_block_header_chain_snark_for_evm(
        provider: &Provider<Http>,
        network: Network,
        start_block_number: u32,
        end_block_number: u32,
        max_depth: usize,
        initial_depth: usize,
        generate_smart_contract: bool,
        transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
        rng: &mut (impl Rng + Send),
    ) {
        assert!(max_depth >= initial_depth);
        assert!(end_block_number - start_block_number < 1 << max_depth);

        let snark = autogen_final_block_header_chain_snark(
            provider,
            network,
            start_block_number,
            end_block_number,
            max_depth,
            initial_depth,
            transcript,
            rng,
        );

        set_var(
            "VERIFY_CONFIG",
            format!("configs/headers/{network}_{max_depth}_{initial_depth}_for_evm.json"),
        );
        let k = load_verify_circuit_degree();
        let params = gen_srs(k);

        let circuit = EvmVerifierAfterAggregationCircuit::new(&params, snark, transcript, rng);

        let pk = gen_pk(
            &params,
            &circuit,
            Some(Path::new(&format!(
                "data/headers/{network}_{max_depth}_{initial_depth}_for_evm.pkey"
            ))),
        );

        let instances = circuit.instances();
        let num_instances = instances[0].len();
        let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone(), rng);
        write_calldata(&instances, &proof, Path::new(&format!(
            "data/headers/{network}_{max_depth}_{initial_depth}_{start_block_number:6x}_{end_block_number:6x}.calldata"
        ))).expect("writing proof calldata should not fail");

        if generate_smart_contract {
            let deployment_code = gen_evm_verifier_shplonk::<EvmVerifierAfterAggregationCircuit>(
                &params,
                pk.get_vk(),
                &num_instances,
                Some(Path::new(&format!("data/headers/{network}_{max_depth}_{initial_depth}.yul"))),
            );

            evm_verify(deployment_code, instances, proof);
        }
    }
}
