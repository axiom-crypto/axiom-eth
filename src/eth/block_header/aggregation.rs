use super::EthBlockHeaderTestCircuit;
use ark_std::{end_timer, start_timer};
use ethereum_types::Address;
use foundry_evm::executor::{fork::MultiFork, Backend, ExecutorBuilder};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use hex::FromHex;
use itertools::Itertools;
use plonk_verifier::{
    loader::evm::{encode_calldata, EvmLoader},
    pcs::kzg::{Gwc19, Kzg, LimbsEncoding},
    system::halo2::{
        aggregation::{self, create_snark_shplonk, gen_pk, gen_srs, TargetCircuit},
        compile,
        transcript::evm::EvmTranscript,
        Config, BITS, LIMBS,
    },
    verifier::{self, PlonkVerifier},
};
use rand::rngs::OsRng;
use std::{fs, io::Cursor, marker::PhantomData, rc::Rc};

type Pcs = Kzg<Bn256, Gwc19>;
// type As = KzgAs<Pcs>;
type Plonk = verifier::Plonk<Pcs, LimbsEncoding<LIMBS, BITS>>;

fn gen_proof<
    C: Circuit<Fr>,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    //MockProver::run(params.k(), &circuit, instances.clone()).unwrap().assert_satisfied();

    let instances = instances.iter().map(|instances| instances.as_slice()).collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, TR, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_aggregation_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    accumulator_indices: Vec<(usize, usize)>,
) -> Vec<u8> {
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(accumulator_indices),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    loader.deployment_code()
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    fs::write("./data/verifier_calldata.dat", hex::encode(&calldata)).unwrap();
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build(Backend::new(MultiFork::new().0, None));

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm.deploy(caller, deployment_code.into(), 0.into(), None).unwrap();
        dbg!(verifier.gas);
        let verifier = verifier.address;

        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into()).unwrap();
        dbg!(result.gas);

        !result.reverted
    };
    assert!(success);
}

pub fn load_aggregation_circuit_degree() -> u32 {
    let path = "./configs/verify_circuit.config";
    let params_str =
        std::fs::read_to_string(path).expect(format!("{} file should exist", path).as_str());
    let params: plonk_verifier::system::halo2::Halo2VerifierCircuitConfigParams =
        serde_json::from_str(params_str.as_str()).unwrap();
    params.degree
}

struct EthMultiBlockHeaderCircuit;

impl aggregation::TargetCircuit for EthMultiBlockHeaderCircuit {
    const TARGET_CIRCUIT_K: u32 = 17;
    const PUBLIC_INPUT_SIZE: usize = 0; //(Self::TARGET_CIRCUIT_K * 2) as usize;
    const N_PROOFS: usize = 2;
    const NAME: &'static str = "eth_multi_block_header";

    type Circuit = EthBlockHeaderTestCircuit<Fr>;
    fn default_circuit() -> Self::Circuit {
        let blocks_str = std::fs::read_to_string("configs/block_chain.config").unwrap();
        let blocks: Vec<String> = serde_json::from_str(blocks_str.as_str()).unwrap();
        let mut input_bytes = Vec::new();
        for block_str in blocks.iter() {
            let mut block_vec: Vec<Option<u8>> =
                Vec::from_hex(block_str).unwrap().iter().map(|y| Some(*y)).collect();
            block_vec.append(&mut vec![Some(0u8); 556 - block_vec.len()]);
            input_bytes.push(block_vec);
        }
        let input_nones: Vec<Vec<Option<u8>>> =
            input_bytes.iter().map(|x| x.iter().map(|_| None).collect()).collect();

        EthBlockHeaderTestCircuit::<Fr> { inputs: input_nones, _marker: PhantomData }
    }

    fn instances() -> Vec<Vec<Fr>> {
        vec![]
    }
}

fn rand_circuits() -> Vec<EthBlockHeaderTestCircuit<Fr>> {
    let blocks_str = std::fs::read_to_string("configs/block_chain.config").unwrap();
    let blocks: Vec<String> = serde_json::from_str(blocks_str.as_str()).unwrap();
    let mut input_bytes = Vec::new();
    for block_str in blocks.iter() {
        let mut block_vec: Vec<Option<u8>> =
            Vec::from_hex(block_str).unwrap().iter().map(|y| Some(*y)).collect();
        block_vec.append(&mut vec![Some(0u8); 556 - block_vec.len()]);
        input_bytes.push(block_vec);
    }
    (0..EthMultiBlockHeaderCircuit::N_PROOFS)
        .map(|_| EthBlockHeaderTestCircuit::<Fr> {
            inputs: input_bytes.clone(),
            _marker: PhantomData,
        })
        .collect_vec()
}
fn default_instances<T: TargetCircuit>() -> Vec<Vec<Vec<Fr>>> {
    (0..T::N_PROOFS).map(|_| T::instances()).collect_vec()
}

#[cfg(test)]
#[test]
pub fn test_aggregation_multi_eth_header() {
    use halo2_proofs::poly::commitment::Params;

    let (params_app, snark) = create_snark_shplonk::<EthMultiBlockHeaderCircuit>(
        rand_circuits(),
        default_instances::<EthMultiBlockHeaderCircuit>(),
        None,
    );
    let snarks = vec![snark];
    let agg_circuit = aggregation::AggregationCircuit::new(&params_app, snarks, true);
    println!("finished creating agg_circuit");

    let k = load_aggregation_circuit_degree();
    let prover = MockProver::run(k, &agg_circuit, agg_circuit.instances()).unwrap();
    prover.assert_satisfied();
}

#[cfg(test)]
#[test]
pub fn bench_aggregation_multi_eth_header() {
    use halo2_proofs::poly::commitment::Params;

    let (params_app, snark) = create_snark_shplonk::<EthMultiBlockHeaderCircuit>(
        rand_circuits(),
        default_instances::<EthMultiBlockHeaderCircuit>(),
        None,
    );
    let snarks = vec![snark];
    let agg_circuit = aggregation::AggregationCircuit::new(&params_app, snarks, true);
    println!("finished creating agg_circuit");

    let k = load_aggregation_circuit_degree();
    let params = gen_srs(k);
    let pk = gen_pk(&params, &agg_circuit, "multi_header_agg_circuit");

    let deploy_time = start_timer!(|| "generate aggregation evm verifier code");
    let deployment_code = gen_aggregation_evm_verifier(
        &params,
        pk.get_vk(),
        agg_circuit.num_instance(),
        aggregation::AggregationCircuit::accumulator_indices(),
    );
    end_timer!(deploy_time);
    fs::write(
        format!("./data/multi_header_agg_{}_bytecode.dat", params.k()).as_str(),
        hex::encode(&deployment_code),
    )
    .unwrap();

    // todo: use different input snarks to test instances etc
    let proof_time = start_timer!(|| "create agg_circuit proof");
    let proof = gen_proof::<_, _, EvmTranscript<G1Affine, _, _, _>, EvmTranscript<G1Affine, _, _, _>>(
        &params,
        &pk,
        agg_circuit.clone(),
        agg_circuit.instances(),
    );
    end_timer!(proof_time);

    let verify_time = start_timer!(|| "on-chain verification");
    evm_verify(deployment_code, agg_circuit.instances(), proof);
    end_timer!(verify_time);
}
