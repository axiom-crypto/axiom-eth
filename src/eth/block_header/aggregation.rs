use super::{EthBlockHeaderConfigParams, EthBlockHeaderHashCircuit};
use crate::keccak::merkle_root::MerkleRootCircuit;
use ark_std::{end_timer, start_timer};
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::biguint_to_fe,
    QuantumCell::{Constant, Existing, Witness},
};
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
    transcript::{Blake2bRead, EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
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
            PoseidonTranscript, Snark, SnarkWitness, TargetCircuit, KZG_QUERY_INSTANCE, RATE, R_F,
            R_P, T,
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

const INITIAL_DEPTH: usize = 3; // 7;
<<<<<<< Updated upstream
pub const FULL_DEPTH: usize = 4; // 10; // 13;
=======
pub const FULL_DEPTH: usize = 4; //10; // 13;
>>>>>>> Stashed changes

const MAINNET_PROVIDER_URL: &'static str = "https://mainnet.infura.io/v3/";
const GOERLI_PROVIDER_URL: &'static str = "https://goerli.infura.io/v3/";

const MAX_PROOF_LEN: usize = 10000;

#[derive(Clone)]
pub enum Direction {
    Forward,
    Backward,
}
#[derive(Clone)]
pub struct RecursiveHeaderCircuit {
    svk: aggregation::Svk,
    header_snarks: Vec<SnarkWitness>,
    prev_recursive_snark: SnarkWitness,
    // instances: accumulator [4 * LIMBS], index [1], block_number [1], parent_hash [2], last_block_hash [2], merkleRoots [2 << (FULL_DEPTH - INITIAL_DEPTH)], trusted_block_hash [2]
    instances: Vec<Fr>,
    as_vk: aggregation::AsVk,
    as_proof: Value<Vec<u8>>,
    // index in the recursion chain
    // we need this to keep track of where to place the merkle root for public outputs
    index: usize,
    first_block_number: u64,
    last_block_number: u64,
    direction: Direction,

    use_dummy: bool,
}

impl RecursiveHeaderCircuit {
    /// assume params for header and recursive snark have the same g[0], g[1]
    pub fn new(
        params: &ParamsKZG<Bn256>,
        header_snarks: Vec<Snark>,
        prev_recursive_snark: Snark,
        index: usize,
        first_block_number: u64,
        last_block_number: u64,
        direction: Direction,
        use_dummy: bool,
    ) -> Self {
        assert_eq!(
            last_block_number - first_block_number,
            ((index + header_snarks.len()) << INITIAL_DEPTH) as u64
        );
        let svk = params.get_g()[0].into();

        // get accumulators for header snarks
        let mut accumulators = header_snarks
            .iter()
            .flat_map(|snark| {
                let mut transcript = PoseidonTranscript::<NativeLoader, _, _>::new(snark.proof());
                let proof = aggregation::Plonk::read_proof(
                    &svk,
                    snark.protocol(),
                    snark.instances(),
                    &mut transcript,
                )
                .unwrap();
                aggregation::Plonk::succinct_verify(
                    &svk,
                    snark.protocol(),
                    snark.instances(),
                    &proof,
                )
                .unwrap()
            })
            .collect_vec();

        let mut prev_recursive_accumulators = if !use_dummy {
            let snark = &prev_recursive_snark;
            let mut transcript = PoseidonTranscript::<NativeLoader, _, _>::new(snark.proof());
            let proof = aggregation::Plonk::read_proof(
                &svk,
                snark.protocol(),
                snark.instances(),
                &mut transcript,
            )
            .unwrap();
            aggregation::Plonk::succinct_verify(&svk, snark.protocol(), snark.instances(), &proof)
                .unwrap()
        } else {
            vec![accumulators[0].clone(), accumulators[0].clone()]
        };
        dbg!(prev_recursive_accumulators.len());

        accumulators.append(&mut prev_recursive_accumulators);

        let as_pk = aggregation::AsPk::new(Some((params.get_g()[0], params.get_g()[1])));
        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _, _>::new(Vec::new());
            let accumulator = aggregation::As::create_proof(
                &as_pk,
                &accumulators,
                &mut transcript,
                ChaCha20Rng::from_seed(Default::default()),
            )
            .unwrap();
            (accumulator, Value::known(transcript.finalize()))
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let mut instances =
            [lhs.x, lhs.y, rhs.x, rhs.y].map(fe_to_limbs::<_, _, LIMBS, BITS>).concat();

        instances.push(Fr::from(index as u64));

        match direction {
            Direction::Forward => {
                // last block
                instances.push(header_snarks.last().unwrap().instances()[0][0].clone());
                instances.extend_from_slice(
                    &prev_recursive_snark.instances()[0][4 * LIMBS + 2..4 * LIMBS + 4],
                );
                instances.extend_from_slice(&header_snarks.last().unwrap().instances()[0][3..5]);

                let mut merkle_roots = prev_recursive_snark.instances()[0][4 * LIMBS + 6..]
                    .iter()
                    .cloned()
                    .collect_vec();
                for (i, snark) in header_snarks.iter().enumerate() {
                    merkle_roots[(index + i) * 2] = snark.instances()[0][5].clone();
                    merkle_roots[(index + i) * 2 + 1] = snark.instances()[0][6].clone();
                }

                instances.append(&mut merkle_roots);
            }
            Direction::Backward => {
                let earliest_block_number = header_snarks.last().unwrap().instances()[0][0]
                    - Fr::from((1u64 << INITIAL_DEPTH) - 1u64);
                instances.push(earliest_block_number);
                instances.extend_from_slice(&header_snarks.last().unwrap().instances()[0][1..3]);
                instances.extend_from_slice(
                    &prev_recursive_snark.instances()[0][4 * LIMBS + 4..4 * LIMBS + 6],
                );

                let mut merkle_roots = prev_recursive_snark.instances()[0][4 * LIMBS + 6..]
                    .iter()
                    .cloned()
                    .collect_vec();
                for (i, snark) in header_snarks.iter().enumerate() {
                    let idx = 1 << (FULL_DEPTH - INITIAL_DEPTH) - 1 - (index + i);
                    merkle_roots[idx * 2] = snark.instances()[0][5].clone();
                    merkle_roots[idx * 2 + 1] = snark.instances()[0][6].clone();
                }

                instances.append(&mut merkle_roots);
            }
        }

        Self {
            svk,
            header_snarks: header_snarks.into_iter().map_into().collect(),
            prev_recursive_snark: prev_recursive_snark.into(),
            instances,
            as_vk: as_pk.vk(),
            as_proof,
            index,
            first_block_number,
            last_block_number,
            direction,
            use_dummy,
        }
    }
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn num_instance(&self) -> Vec<usize> {
        dbg!(self.instances.len());
        vec![self.instances.len()]
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl Circuit<Fr> for RecursiveHeaderCircuit {
    type Config = Halo2VerifierCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            header_snarks: self.header_snarks.iter().map(SnarkWitness::without_witnesses).collect(),
            prev_recursive_snark: self.prev_recursive_snark.without_witnesses(),
            instances: Vec::new(),
            as_vk: self.as_vk,
            as_proof: Value::unknown(),
            index: self.index,
            first_block_number: 0,
            last_block_number: 0,
            direction: self.direction,
            use_dummy: self.use_dummy,
        }
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
        config.base_field_config.load_lookup_table(&mut layouter)?;
        // Need to trick layouter to skip first pass in get shape mode
        // Using simple floor planner
        let mut first_pass = true;
        let mut assigned_instances = None;
        layouter.assign_region(
            || "",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = aggregation::Context::new(
                    region,
                    aggregation::ContextParams {
                        num_advice: vec![(
                            config.base_field_config.range.context_id.clone(),
                            config.base_field_config.range.gate.num_advice,
                        )],
                    },
                );

                let loader = Halo2Loader::new(&config.base_field_config, ctx);
                let use_dummy = GateInstructions::assign_region(
                    loader.gate(),
                    &mut loader.ctx_mut(),
                    vec![Witness(Value::known(Fr::from(self.use_dummy as u64)))],
                    vec![],
                    None,
                )?
                .pop()
                .unwrap();

                let (mut new_instances, header_instances) = aggregation::recursive_aggregate(
                    &self.svk,
                    &loader,
                    &self.header_snarks,
                    &self.prev_recursive_snark,
                    &self.as_vk,
                    self.as_proof(),
                    use_dummy.clone(),
                );

                let trusted_block_hash = [
                    &new_instances[new_instances.len() - 2],
                    &new_instances[new_instances.len() - 1],
                ];
                let idx = match self.direction {
                    Direction::Forward => 1,
                    Direction::Backward => 3,
                };
                // check parent hash of first header equals trusted hash
                let mut dummy_flag = loader.range().is_equal(
                    &mut loader.ctx_mut(),
                    &Existing(trusted_block_hash[0]),
                    &Existing(&header_instances[0][idx]),
                )?;
                let dummy_flag1 = loader.range().is_equal(
                    &mut loader.ctx_mut(),
                    &Existing(trusted_block_hash[1]),
                    &Existing(&header_instances[0][idx + 1]),
                )?;
                dummy_flag = loader.gate().and(
                    &mut loader.ctx_mut(),
                    &Existing(&dummy_flag),
                    &Existing(&dummy_flag1),
                )?;
                loader.ctx_mut().region.constrain_equal(dummy_flag.cell(), use_dummy.cell())?;

                // check hash chains match
                match self.direction {
                    Direction::Forward => {
                        loader.ctx_mut().region.constrain_equal(
                            new_instances[4 * LIMBS + 4].cell(),
                            header_instances[0][1].cell(),
                        )?;
                        loader.ctx_mut().region.constrain_equal(
                            new_instances[4 * LIMBS + 5].cell(),
                            header_instances[0][2].cell(),
                        )?;
                        for i in 0..header_instances.len() - 1 {
                            loader.ctx_mut().region.constrain_equal(
                                header_instances[i][3].cell(),
                                header_instances[i + 1][1].cell(),
                            )?;
                            loader.ctx_mut().region.constrain_equal(
                                header_instances[i][4].cell(),
                                header_instances[i + 1][2].cell(),
                            )?;
                        }
                        // update block number to be last block number of last header
                        new_instances[4 * LIMBS + 1] = header_instances.last().unwrap()[0].clone();
                        // update last hash to be last hash of last header
                        new_instances[4 * LIMBS + 4] = header_instances.last().unwrap()[3].clone();
                        new_instances[4 * LIMBS + 5] = header_instances.last().unwrap()[4].clone();
                    }
                    Direction::Backward => todo!(),
                }
                // update index
                new_instances[4 * LIMBS] = loader.gate().add(
                    &mut loader.ctx_mut(),
                    &Existing(&new_instances[4 * LIMBS]),
                    &Constant(Fr::from(self.header_snarks.len() as u64)),
                )?;

                for (idx, header_instance) in header_instances.iter().enumerate() {
                    // fill in new merkle roots
                    let merkle_id = match self.direction {
                        Direction::Forward => {
                            if idx == 0 {
                                new_instances[4 * LIMBS].clone()
                            } else {
                                loader.gate().add(
                                    &mut loader.ctx_mut(),
                                    &Existing(&new_instances[4 * LIMBS]),
                                    &Constant(Fr::from(idx as u64)),
                                )?
                            }
                        }
                        Direction::Backward => todo!(),
                    };

                    let merkle_id_bits = loader.range().num_to_bits(
                        &mut loader.ctx_mut(),
                        &merkle_id,
                        FULL_DEPTH - INITIAL_DEPTH,
                    )?;
                    let indicator = loader.gate().bits_to_indicator(
                        &mut loader.ctx_mut(),
                        &merkle_id_bits.iter().map(|a| Existing(a)).collect_vec(),
                    )?;
                    for (i, sel) in indicator.iter().enumerate() {
                        new_instances[4 * LIMBS + 6 + 2 * i] = loader.gate().select(
                            &mut loader.ctx_mut(),
                            &Existing(&header_instance[5]),
                            &Existing(&new_instances[4 * LIMBS + 6 + 2 * i]),
                            &Existing(sel),
                        )?;
                        new_instances[4 * LIMBS + 6 + 2 * i + 1] = loader.gate().select(
                            &mut loader.ctx_mut(),
                            &Existing(&header_instance[6]),
                            &Existing(&new_instances[4 * LIMBS + 6 + 2 * i + 1]),
                            &Existing(sel),
                        )?;
                    }
                }

                // REQUIRED STEP
                loader.finalize();
                assigned_instances = Some(new_instances);
                Ok(())
            },
        )?;
        Ok({
            // TODO: use less instances by following Scroll's strategy of keeping only last bit of y coordinate
            let mut layouter = layouter.namespace(|| "expose");
            for (i, assigned_instance) in assigned_instances.unwrap().iter().enumerate() {
                layouter.constrain_instance(
                    assigned_instance.cell().clone(),
                    config.instance,
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

pub fn dummy_recursive_snark(
    params: &ParamsKZG<Bn256>, 
    
)

pub fn create_recursive_snark(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    header_snarks: Vec<Snark>,
    prev_recursive_snark: Snark,
    index: usize,
    first_block_number: u64,
    last_block_number: u64,
    direction: Direction,
    use_dummy: bool,
) -> Snark {
    let name = format!("recursive_header_{}_{}_{}", FULL_DEPTH, INITIAL_DEPTH, header_snarks.len());
    std::env::set_var("VERIFY_CONFIG", format!("./configs/{}.config", name.as_str()));

    let circuit = RecursiveHeaderCircuit::new(
        params,
        header_snarks,
        prev_recursive_snark,
        index,
        first_block_number,
        last_block_number,
        direction,
        use_dummy,
    );

    let config = Config::kzg(KZG_QUERY_INSTANCE)
        .set_zk(true)
        .with_num_proof(1)
        .with_accumulator_indices(RecursiveHeaderCircuit::accumulator_indices())
        .with_num_instance(circuit.num_instance());
    let protocol = compile(params, pk.get_vk(), config);

    let instance = circuit.instances();
    let instance1: Vec<&[Fr]> = vec![&instance[0]];
    let instance2: &[&[Fr]] = &instance1[..];

    let proof = {
        let path = format!(
            "./data/proof_{:06x}_{:06x}_recurse.dat",
            first_block_number, last_block_number
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
                        params,
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

    let instance_path = format!(
        "./data/instances_{:06x}_{:06x}_recurse.dat",
        first_block_number, last_block_number
    );
    aggregation::write_instances(&vec![instance.clone()], instance_path.as_str());

    Snark::new(protocol, instance, proof)
}

/// creates the snark for reading block headers of block numbers `start_block_number, ..., start_block_number + 2^INITIAL_DEPTH - 1` inclusive  
/// pass in the proving key which should be stored in memory throughout
pub fn create_header_snark_by_block_number(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    provider: &Provider<Http>,
    start_block_number: u64,
) -> Snark {
    let last_block_number = start_block_number + (1 << INITIAL_DEPTH) - 1;
    let circuit = EthBlockHeaderHashCircuit::<Fr>::from_provider(
        &provider,
        last_block_number,
        1 << INITIAL_DEPTH,
    );

    // copy from create_snark_shplonk
    let config =
        Config::kzg(KZG_QUERY_INSTANCE).set_zk(true).with_num_proof(1).with_num_instance(vec![6]);
    let protocol = compile(params, pk.get_vk(), config);

    let instance: Vec<Vec<Fr>> = circuit.instances();
    let instance1: Vec<&[Fr]> = vec![&instance[0]];
    let instance2: &[&[Fr]] = &instance1[..];

    #[cfg(feature = "display")]
    let pf_time = start_timer!(|| "block header proving time");
    let proof = {
        let path = format!("./data/proof_{:06x}_{:06x}.dat", start_block_number, last_block_number);
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
                    params,
                    pk,
                    &[circuit],
                    &[instance2],
                    &mut ChaCha20Rng::from_entropy(),
                    &mut transcript,
                )
                .unwrap();
                let proof = transcript.finalize();
                let mut writer = BufWriter::new(File::create(path.as_str()).unwrap());
                writer.write_all(&proof).unwrap();
                proof
            }
        }
    };
    #[cfg(feature = "display")]
    end_timer!(pf_time);

    Snark::new(protocol, instance, proof)
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
        let config = Config::kzg(KZG_QUERY_INSTANCE)
            .set_zk(true)
            .with_num_proof(1)
            .with_num_instance(vec![6]);
        let protocol = compile(params, pk.get_vk(), config);

        let instance = circuit.instances();
        let instance1: Vec<&[Fr]> = vec![&instance[0]];
        let instance2: &[&[Fr]] = &instance1[..];

        let pf_time = start_timer!(|| "block header proving time");
        let proof = {
            let path = format!("./data/proof_{:06x}_{}.dat", block_number, 1 << INITIAL_DEPTH);
            match File::open(path.as_str()) {
                Ok(mut file) => {
                    let mut buf = vec![];
                    file.read_to_end(&mut buf).unwrap();
                    // buf
                    dbg!(buf.len());
                    vec![0u8; 10000]
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
        end_timer!(pf_time);
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
    // MockProver::run(params.k(), &merkle_verify_circuit, circuit_instances.clone()).unwrap().assert_satisfied();
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
    println!("{:?}", params.get_g()[0]);
    println!("{:?}\n", params.get_g()[1]);
    let mut snarks = create_initial_block_header_snarks(&params, last_block_number);
    println!("== finished initial block header snarks ==");

    for layer in 0..FULL_DEPTH - INITIAL_DEPTH {
        std::env::set_var("VERIFY_CONFIG", format!("./configs/block_agg_{}.config", layer));
        let k = load_aggregation_circuit_degree();
        params = if k <= params.k() {
            params.downsize(k);
            params
        } else {
            gen_srs(k)
        };
        snarks = create_block_agg_snarks(&params, snarks, layer, last_block_number);
        println!("== finished layer {} block aggregation snarks ==", layer);
    }

    std::env::set_var("VERIFY_CONFIG", "./configs/verify_for_evm.config");
    let k = load_aggregation_circuit_degree();
    params = if k <= params.k() {
        params.downsize(k);
        params
    } else {
        gen_srs(k)
    };
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
        let params_app = gen_srs(21);
        let snark = create_snark_shplonk::<EthMultiBlockHeaderCircuit>(
            &params_app,
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
