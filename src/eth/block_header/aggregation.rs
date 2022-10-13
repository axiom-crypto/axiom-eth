use super::{EthBlockHeaderConfigParams, EthBlockHeaderHashCircuit};
use crate::keccak::merkle_root::MerkleRootCircuit;
use ethers_providers::{Http, Provider};
use halo2_base::utils::biguint_to_fe;
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use hex::FromHex;
use itertools::Itertools;
use num_bigint::BigUint;
use plonk_verifier::{
    loader::{evm::encode_calldata, native::NativeLoader},
    pcs::{
        kzg::{
            Bdfg21, Gwc19, Kzg, KzgAccumulator, KzgAs, KzgAsProvingKey, KzgAsVerifyingKey,
            KzgSuccinctVerifyingKey, LimbsEncoding,
        },
        AccumulationSchemeProver,
    },
    system::halo2::{
        aggregation::{
            self, aggregate, create_snark_shplonk, gen_pk, gen_srs, Halo2Loader,
            PoseidonTranscript, Snark, SnarkWitness, TargetCircuit, RATE, R_F, R_P, T,
        },
        compile,
        transcript::{
            evm::{ChallengeEvm, EvmTranscript},
            halo2::ChallengeScalar,
        },
        Config, Halo2VerifierCircuitConfig, Halo2VerifierCircuitConfigParams, BITS, LIMBS,
    },
    util::arithmetic::fe_to_limbs,
    verifier::PlonkVerifier,
};
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Keccak256};
use std::{
    fs::{self, File},
    io::{BufWriter, Cursor, Read, Write},
    marker::PhantomData,
    rc::Rc,
};

pub mod evm;

const INITIAL_DEPTH: usize = 3;
pub const FULL_DEPTH: usize = 4; // 13;

const MAINNET_PROVIDER_URL: &'static str = "https://mainnet.infura.io/v3/";
const GOERLI_PROVIDER_URL: &'static str = "https://goerli.infura.io/v3/";

#[derive(Clone)]
pub struct BlockAggregationCircuit {
    circuit: aggregation::AggregationCircuit,
    // how many times have we applied aggregation before this
    layer: usize,
}

impl BlockAggregationCircuit {
    pub fn new(params: &ParamsKZG<Bn256>, snarks: Vec<Snark>, layer: usize) -> Self {
        assert_eq!(snarks.len(), 2);

        let snarks_instance = snarks.iter().map(|snark| snark.instances()[0].clone()).collect_vec();
        let mut circuit = aggregation::AggregationCircuit::new(params, snarks, true);
        circuit.instances.drain(4 * LIMBS..);

        let start_idx = if layer == 0 { 0 } else { 4 * LIMBS };
        // parent hash of older snark
        circuit.instances.extend_from_slice(&snarks_instance[0][start_idx..start_idx + 2]);
        // latest hash of newer snark
        circuit.instances.extend_from_slice(&snarks_instance[1][start_idx + 2..start_idx + 4]);
        // append the left merkle leaves and then right merkle leaves for 2^{layer + 1} leaves (each as two u128)
        circuit.instances.extend_from_slice(&snarks_instance[0][start_idx + 4..]);
        circuit.instances.extend_from_slice(&snarks_instance[1][start_idx + 4..]);

        Self { circuit, layer }
    }
}

impl Circuit<Fr> for BlockAggregationCircuit {
    type Config = Halo2VerifierCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { circuit: self.circuit.without_witnesses(), layer: self.layer }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = std::env::var("VERIFY_CONFIG").expect("export VERIFY_CONFIG with config path");
        let params_str =
            fs::read_to_string(path.as_str()).expect(format!("{} should exist", path).as_str());
        let params: Halo2VerifierCircuitConfigParams =
            serde_json::from_str(params_str.as_str()).unwrap();

        Self::Config::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let config_instance = config.instance.clone();

        // starting index of left instances that aren't accumulators
        let start_left = if self.layer == 0 { 4 * LIMBS } else { 8 * LIMBS };
        // start right is after left instances: parent hash, last hash, 2^layer merkle leaves
        let start_right = start_left
            + 4
            + (1 << (self.layer + 1))
            + (if self.layer == 0 { 0 } else { 4 * LIMBS });

        // left last hash == right parent hash
        let all_instances = self.circuit.synthesize_proof(
            config,
            &mut layouter,
            vec![(start_left + 2, start_right), (start_left + 3, start_right + 1)],
        )?;

        let mut instances = Vec::with_capacity(4 * LIMBS + 4 + (1 << (self.layer + 2)));
        instances.extend_from_slice(&all_instances[..4 * LIMBS]);
        instances.extend_from_slice(&all_instances[start_left..start_left + 2]);
        instances.extend_from_slice(&all_instances[start_right + 2..start_right + 4]);
        instances.extend_from_slice(
            &all_instances[start_left + 4..start_left + 4 + (1 << (self.layer + 1))],
        );
        instances.extend_from_slice(&all_instances[start_right + 4..]);

        Ok({
            // TODO: use less instances by following Scroll's strategy of keeping only last bit of y coordinate
            let mut layouter = layouter.namespace(|| "expose");
            for (i, assigned_instance) in instances.iter().enumerate() {
                layouter.constrain_instance(
                    assigned_instance.cell().clone(),
                    config_instance,
                    i,
                )?;
            }
        })
    }
}

pub fn load_aggregation_circuit_degree() -> u32 {
    let path = std::env::var("VERIFY_CONFIG").expect("export VERIFY_CONFIG with config path");
    let params_str = std::fs::read_to_string(path.as_str())
        .expect(format!("{} file should exist", path).as_str());
    let params: plonk_verifier::system::halo2::Halo2VerifierCircuitConfigParams =
        serde_json::from_str(params_str.as_str()).unwrap();
    params.degree
}

pub fn create_block_agg_snarks(
    params: &ParamsKZG<Bn256>,
    snarks: Vec<Snark>,
    layer: usize,
    last_block_number: u64,
) -> Vec<Snark> {
    assert_eq!(snarks.len(), 1 << (FULL_DEPTH - INITIAL_DEPTH - layer));
    assert!(snarks.len() != 0 && snarks.len() != 1);

    let name = format!("block_agg_{}_{}", INITIAL_DEPTH + layer + 1, layer);
    std::env::set_var("VERIFY_CONFIG", format!("./configs/block_agg_{}.config", layer));

    let mut pk = None;
    let mut new_snarks = Vec::with_capacity(snarks.len() / 2);
    let mut block_number =
        last_block_number - (1 << FULL_DEPTH) + (1 << (INITIAL_DEPTH + layer + 1));

    for snark_pair in snarks.into_iter().chunks(2).into_iter() {
        let agg = BlockAggregationCircuit::new(params, snark_pair.collect_vec(), layer);
        if pk.is_none() {
            pk = Some(gen_pk(params, &agg, name.as_str()));
        }
        let pk = pk.as_ref().unwrap();

        // copy from create_snark_shplonk
        let config = Config::kzg()
            .set_zk(true)
            .with_num_proof(1)
            .with_accumulator_indices(aggregation::AggregationCircuit::accumulator_indices())
            .with_num_instance(agg.circuit.num_instance());
        let protocol = compile(params, pk.get_vk(), config);

        let instance = agg.circuit.instances();
        let instance1: Vec<&[Fr]> = vec![&instance[0]];
        let instance2: &[&[Fr]] = &instance1[..];

        let proof = {
            let path = format!(
                "./data/proof_{:06x}_{}_{}.dat",
                block_number,
                1 << (INITIAL_DEPTH + layer + 1),
                layer
            );
            match File::open(path.as_str()) {
                Ok(mut file) => {
                    let mut buf = vec![];
                    file.read_to_end(&mut buf).unwrap();
                    buf
                }
                Err(_) => {
                    let mut transcript =
                        PoseidonTranscript::<NativeLoader, Vec<u8>, _>::init(Vec::new());
                    create_proof::<
                        KZGCommitmentScheme<_>,
                        ProverSHPLONK<_>,
                        ChallengeScalar<_>,
                        _,
                        _,
                        _,
                    >(
                        &params,
                        pk,
                        &[agg],
                        &[instance2],
                        &mut ChaCha20Rng::from_entropy(),
                        &mut transcript,
                    )
                    .unwrap();
                    let proof = transcript.finalize();
                    let mut file = File::create(path.as_str()).unwrap();
                    file.write_all(&proof).unwrap();
                    proof
                }
            }
        };

        let instance_path = format!(
            "./data/instances_{:06x}_{}_{}.dat",
            block_number,
            1 << (INITIAL_DEPTH + layer + 1),
            layer
        );
        aggregation::write_instances(&vec![instance.clone()], instance_path.as_str());

        new_snarks.push(Snark::new(protocol, instance, proof));

        block_number += 1 << (INITIAL_DEPTH + layer + 1);
    }
    new_snarks
}

pub fn create_initial_block_header_snarks(
    params: &ParamsKZG<Bn256>,
    last_block_number: u64,
) -> Vec<Snark> {
    let name = format!("block_{}", INITIAL_DEPTH);

    let mut pk = None;
    let mut snarks = Vec::with_capacity(1 << (FULL_DEPTH - INITIAL_DEPTH));
    let mut block_number = last_block_number - (1 << FULL_DEPTH) + (1 << INITIAL_DEPTH);

    let infura_id = fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
    let provider =
        Provider::<Http>::try_from(format!("{}{}", GOERLI_PROVIDER_URL, infura_id).as_str())
            .expect("could not instantiate HTTP Provider");

    while block_number <= last_block_number {
        let circuit = EthBlockHeaderHashCircuit::<Fr>::from_provider(
            &provider,
            block_number,
            1 << INITIAL_DEPTH,
        );
        if pk.is_none() {
            pk = Some(gen_pk(params, &circuit, name.as_str()));
        }
        let pk = pk.as_ref().unwrap();

        // copy from create_snark_shplonk
        let config = Config::kzg().set_zk(true).with_num_proof(1).with_num_instance(vec![6]);
        let protocol = compile(params, pk.get_vk(), config);

        let instance = circuit.instances();
        let instance1: Vec<&[Fr]> = vec![&instance[0]];
        let instance2: &[&[Fr]] = &instance1[..];

        let proof = {
            let path = format!("./data/proof_{:06x}_{}.dat", block_number, 1 << INITIAL_DEPTH);
            match File::open(path.as_str()) {
                Ok(mut file) => {
                    let mut buf = vec![];
                    file.read_to_end(&mut buf).unwrap();
                    buf
                }
                Err(_) => {
                    let mut transcript =
                        PoseidonTranscript::<NativeLoader, Vec<u8>, _>::init(Vec::new());
                    create_proof::<
                        KZGCommitmentScheme<_>,
                        ProverSHPLONK<_>,
                        ChallengeScalar<_>,
                        _,
                        _,
                        _,
                    >(
                        &params,
                        pk,
                        &[circuit],
                        &[instance2],
                        &mut ChaCha20Rng::from_entropy(),
                        &mut transcript,
                    )
                    .unwrap();
                    let proof = transcript.finalize();
                    let mut file = File::create(path.as_str()).unwrap();
                    file.write_all(&proof).unwrap();
                    proof
                }
            }
        };
        snarks.push(Snark::new(protocol, instance, proof));

        block_number += 1 << INITIAL_DEPTH;
    }
    snarks
}

#[derive(Clone)]
pub struct MerkleVerifyCircuit(aggregation::AggregationCircuit);

impl MerkleVerifyCircuit {
    pub fn new(params: &ParamsKZG<Bn256>, snark: Snark, name: &str) -> Self {
        let merkle_snark = MerkleRootCircuit::create_snark_shplonk(
            snark.instances()[0][4 * LIMBS + 4..].iter().cloned().collect_vec(),
            format!("merkle_{}", name).as_str(),
        );
        let mut merkle_instance = merkle_snark.instances()[0].clone();
        merkle_instance.drain(..merkle_instance.len() - 2); // the last two is the merkle root
        let mut circuit = aggregation::AggregationCircuit::new(params, [snark, merkle_snark], true);
        circuit.instances.drain(8 * LIMBS + 4..);
        circuit.instances.drain(4 * LIMBS..8 * LIMBS); // drop the previous accumulator final pair
        circuit.instances.append(&mut merkle_instance); // add the merkle root of all block hashes
        assert_eq!(circuit.instances.len(), 4 * LIMBS + 6);
        // final instance is accumulator pair of this verify circuit, 2 u128 for parent block hash, 2 u128 for the last block hash, 2 u128 for the merkle root
        Self(circuit)
    }
}

impl Circuit<Fr> for MerkleVerifyCircuit {
    type Config = Halo2VerifierCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(self.0.without_witnesses())
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = "./configs/verify_for_evm.config";
        let params_str = fs::read_to_string(path).expect(format!("{} should exist", path).as_str());
        let params: Halo2VerifierCircuitConfigParams =
            serde_json::from_str(params_str.as_str()).unwrap();
        Self::Config::configure(meta, params)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let config_instance = config.instance.clone(); // instance column

        let start_left = 8 * LIMBS + 4;
        let start_right = start_left + (1 << (FULL_DEPTH - INITIAL_DEPTH + 1));

        // the merkle leaves from final input snark should be the public inputs to merkle circuit
        let mut instances = self.0.synthesize_proof(
            config,
            &mut layouter,
            (0..(1 << (FULL_DEPTH - INITIAL_DEPTH)))
                .map(|i| (start_left + i, start_right + i))
                .collect_vec(),
        )?;
        instances.drain(start_left..start_right + (1 << (FULL_DEPTH - INITIAL_DEPTH + 1))); // each hash is two u128
        instances.drain(4 * LIMBS..8 * LIMBS); // previous accumulator
        assert_eq!(instances.len(), 4 * LIMBS + 6);

        Ok({
            // TODO: use less instances by following Scroll's strategy of keeping only last bit of y coordinate
            let mut layouter = layouter.namespace(|| "expose");
            for (i, assigned_instance) in instances.iter().enumerate() {
                layouter.constrain_instance(
                    assigned_instance.cell().clone(),
                    config_instance,
                    i,
                )?;
            }
        })
    }
}

pub fn final_evm_verify(
    params: &ParamsKZG<Bn256>,
    final_block_agg_snark: Snark,
    last_block_number: u64,
    deploy: bool,
) {
    let name = format!("{:06x}_{}", last_block_number, 1 << FULL_DEPTH);
    let merkle_verify_circuit =
        MerkleVerifyCircuit::new(params, final_block_agg_snark, name.as_str());
    let pk = gen_pk(params, &merkle_verify_circuit, format!("verify_{}", FULL_DEPTH).as_str());

    let circuit_instances = merkle_verify_circuit.0.instances().clone();

    /*
    MockProver::run(params.k(), &merkle_verify_circuit, circuit_instances.clone())
        .unwrap()
        .assert_satisfied();
    */

    let proof = evm::gen_proof::<
        _,
        ChallengeEvm<G1Affine>,
        EvmTranscript<G1Affine, _, _, _>,
        EvmTranscript<G1Affine, _, _, _>,
    >(params, &pk, merkle_verify_circuit, circuit_instances.clone());

    let calldata = encode_calldata(&circuit_instances, &proof);
    let mut writer = BufWriter::new(
        File::create(format!("./data/calldata_{}.dat", name.as_str()).as_str()).unwrap(),
    );
    write!(writer, "{}", hex::encode(&calldata)).unwrap();

    /*
    aggregation::write_instances(
        &vec![circuit_instances.clone()],
        format!("./data/evm_instances_{}.dat", name).as_str(),
    );
    */

    if deploy {
        let deployment_code = evm::gen_aggregation_evm_verifier(
            params,
            pk.get_vk(),
            vec![circuit_instances[0].len()],
            aggregation::AggregationCircuit::accumulator_indices(),
        );
        fs::write(
            format!("./data/evm_verify_{}_bytecode.dat", FULL_DEPTH).as_str(),
            hex::encode(&deployment_code),
        )
        .unwrap();

        #[cfg(feature = "evm")]
        evm::evm_verify(deployment_code, circuit_instances, proof);
    }
}

pub fn run(last_block_number: u64, deploy: bool) {
    let config_str = std::fs::read_to_string("configs/block_header.config").unwrap();
    let config: EthBlockHeaderConfigParams = serde_json::from_str(config_str.as_str()).unwrap();
    let mut params = gen_srs(config.degree);
    let mut snarks = create_initial_block_header_snarks(&params, last_block_number);
    println!("== finished initial block header snarks ==");

    std::env::set_var("VERIFY_CONFIG", "./configs/block_agg_0.config");
    // assuming all block_agg circuits have the same degree
    let k = load_aggregation_circuit_degree();
    let params = if k <= config.degree {
        params.downsize(k);
        params
    } else {
        gen_srs(k)
    };

    for layer in 0..FULL_DEPTH - INITIAL_DEPTH {
        snarks = create_block_agg_snarks(&params, snarks, layer, last_block_number);
        println!("== finished layer {} block aggregation snarks ==", layer);
    }

    final_evm_verify(&params, snarks.into_iter().nth(0).unwrap(), last_block_number, deploy);
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use super::*;
    use crate::eth::block_header::EthBlockHeaderConfigParams;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::{
        dev::MockProver,
        poly::{commitment::Params, kzg::multiopen::VerifierSHPLONK},
    };
    use plonk_verifier::system::halo2::aggregation::gen_vk;

    struct EthMultiBlockHeaderCircuit;

    impl aggregation::TargetCircuit for EthMultiBlockHeaderCircuit {
        const N_PROOFS: usize = 1;
        const NAME: &'static str = "eth_multi_block_header";

        type Circuit = EthBlockHeaderHashCircuit<Fr>;
    }

    #[test]
    pub fn test_aggregation_multi_eth_header() {
        let block_circuit = EthBlockHeaderHashCircuit::<Fr>::default();
        let block_instances = block_circuit.instances();
        let (params_app, snark) = create_snark_shplonk::<EthMultiBlockHeaderCircuit>(
            21,
            vec![block_circuit],
            vec![block_instances],
            None,
        );
        let snarks = vec![snark];
        let agg_circuit = aggregation::AggregationCircuit::new(&params_app, snarks, true);
        println!("finished creating agg_circuit");

        let k = load_aggregation_circuit_degree();
        let prover = MockProver::run(k, &agg_circuit, agg_circuit.instances()).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    pub fn bench_block_aggregation() {
        let timer = start_timer!(|| format!("bench aggregation of {} blocks", 1 << FULL_DEPTH));
        run(0x765fb3, true);
        end_timer!(timer);
    }
}
