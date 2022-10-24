#[cfg(feature = "evm")]
use ethereum_types::Address;
#[cfg(feature = "evm")]
use foundry_evm::executor::{fork::MultiFork, Backend, ExecutorBuilder};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};
use itertools::Itertools;
use plonk_verifier::{
    loader::{
        evm::{encode_calldata, EvmLoader},
        native::NativeLoader,
    },
    pcs::kzg::{Gwc19, Kzg, LimbsEncoding},
    system::halo2::{
        aggregation::{
            self, create_snark_shplonk, gen_pk, gen_srs, write_bytes, AggregationCircuit, Snark,
            TargetCircuit, KZG_QUERY_INSTANCE,
        },
        compile,
        transcript::evm::EvmTranscript,
        Config, BITS, LIMBS,
    },
    verifier::{self, PlonkVerifier},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{fs, io::Cursor, rc::Rc};

type Pcs = Kzg<Bn256, Gwc19>; // for use with evm verifier only
type Plonk = verifier::Plonk<Pcs, LimbsEncoding<LIMBS, BITS>>;

pub fn gen_proof<
    C: Circuit<Fr> + Clone,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    // MockProver::run(params.k(), &circuit, instances.clone()).unwrap().assert_satisfied();
    // Native verify
    /*{
        let proof = {
            let mut transcript = Blake2bWrite::init(Vec::new());
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverGWC<_>,
                Challenge255<G1Affine>,
                _,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
                _,
            >(
                params,
                pk,
                &[circuit.clone()],
                &[&[instances[0].as_slice()]],
                ChaCha20Rng::from_entropy(),
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };
        let svk = params.get_g()[0].into();
        let dk = (params.g2(), params.s_g2()).into();
        let protocol = compile(
            params,
            pk.get_vk(),
            Config::kzg()
                .with_num_instance(vec![instances[0].len()])
                .with_accumulator_indices(aggregation::AggregationCircuit::accumulator_indices()),
        );
        let mut transcript = Blake2bRead::<_, G1Affine, _>::init(proof.as_slice());
        let instances = &[instances[0].to_vec()];
        let proof = Plonk::read_proof(&svk, &protocol, instances, &mut transcript).unwrap();
        assert!(Plonk::verify(&svk, &dk, &protocol, instances, &proof).unwrap());
    }*/

    let instances = instances.iter().map(|instances| instances.as_slice()).collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            ChaCha20Rng::from_entropy(),
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

pub fn gen_aggregation_evm_verifier(
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
        Config::kzg(KZG_QUERY_INSTANCE)
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

#[cfg(feature = "evm")]
pub fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
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

pub fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg(KZG_QUERY_INSTANCE).with_num_instance(num_instance.clone()),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    loader.deployment_code()
}

#[cfg(test)]
mod tests {
    use crate::eth::{
        aggregation::load_aggregation_circuit_degree, block_header::EthBlockHeaderHashCircuit,
    };

    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::dev::MockProver;

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
    pub fn bench_aggregation_multi_eth_header() {
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
        let proof = gen_proof::<
            _,
            _,
            EvmTranscript<G1Affine, _, _, _>,
            EvmTranscript<G1Affine, _, _, _>,
        >(&params, &pk, agg_circuit.clone(), agg_circuit.instances());
        end_timer!(proof_time);

        #[cfg(feature = "evm")]
        {
            let verify_time = start_timer!(|| "on-chain verification");
            evm_verify(deployment_code, agg_circuit.instances(), proof);
            end_timer!(verify_time);
        }
    }
}
