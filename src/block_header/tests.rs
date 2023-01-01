use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::{
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::*,
        plonk::{Circuit, ConstraintSystem, Error},
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    utils::fs::gen_srs,
};
use hex::FromHex;
use rand_core::OsRng;
use serde::Deserialize;
use std::{fs::File, marker::PhantomData};

#[derive(Clone, Debug)]
struct EthBlockHeaderTestCircuit<F> {
    inputs: Vec<Vec<u8>>,
    network: Network,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> Circuit<F> for EthBlockHeaderTestCircuit<F> {
    type Config = EthBlockHeaderConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: self.inputs.iter().map(|input| vec![0; input.len()]).collect_vec(),
            network: self.network,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = EthBlockHeaderConfigParams::get();
        EthBlockHeaderConfig::configure(meta, params, 0)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let witness_time = start_timer!(|| "witness gen");
        config.rlp.range.load_lookup_table(&mut layouter).expect("load range lookup table");
        config.keccak.load(&mut layouter).expect("load keccak lookup tables");
        let mut chip = EthBlockHeaderChip::new(config, Value::unknown());

        let mut first_pass = SKIP_FIRST_PASS;

        layouter
            .assign_region(
                || "Eth block header chain test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: chip.gate().max_rows,
                            num_context_ids: 2,
                            fixed_columns: chip.gate().constants.clone(),
                        },
                    );
                    let ctx = &mut aux;

                    // ======== FIRST PHASE ===========
                    let block_chain_witness =
                        chip.decompose_block_header_chain_prepare(ctx, &self.inputs, self.network);
                    let num_lookup_advice_cells = chip.range().finalize(ctx);
                    ctx.next_phase();

                    // ======== SECOND PHASE ========
                    chip.get_challenge(ctx);
                    let _block_chain_trace =
                        chip.decompose_block_header_chain_finalize(ctx, block_chain_witness, None);

                    #[cfg(feature = "display")]
                    {
                        ctx.print_stats(&["Range", "RLC"], num_lookup_advice_cells);
                        chip.keccak.print_stats(ctx);
                    }
                    Ok(())
                },
            )
            .unwrap();
        end_timer!(witness_time);
        Ok(())
    }
}

#[test]
pub fn test_one_mainnet_header_mock() {
    set_var("BLOCK_HEADER_CONFIG", "configs/tests/one_block.config");
    let params = EthBlockHeaderConfigParams::get();
    let k = params.degree;
    let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();

    let circuit = EthBlockHeaderTestCircuit::<Fr> {
        inputs: vec![input_bytes],
        network: Network::Mainnet,
        _marker: PhantomData,
    };
    MockProver::run(k, &circuit, vec![vec![]]).unwrap().assert_satisfied();
}

#[test]
pub fn test_one_mainnet_header_prover() -> Result<(), Box<dyn std::error::Error>> {
    set_var("BLOCK_HEADER_CONFIG", "configs/tests/one_block.config");
    let params = EthBlockHeaderConfigParams::get();
    let k = params.degree;
    let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();

    let mut rng = OsRng;
    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let proof_circuit = EthBlockHeaderTestCircuit::<Fr> {
        inputs: vec![input_bytes],
        network: Network::Mainnet,
        _marker: PhantomData,
    };
    let circuit = proof_circuit.clone(); // proof_circuit.without_witnesses();

    let vk_time = start_timer!(|| "vk gen");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pk gen");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let pf_time = start_timer!(|| "proof gen");
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[proof_circuit], &[&[&[]]], rng, &mut transcript)?;
    let proof = transcript.finalize();
    end_timer!(pf_time);

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_time = start_timer!(|| "verify");
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[&[]]], &mut transcript)
    .unwrap();
    end_timer!(verify_time);

    Ok(())
}

fn get_default_goerli_header_chain_circuit() -> EthBlockHeaderChainCircuit<Fr> {
    let network = Network::Goerli;
    let header_rlp_max_bytes = GOERLI_BLOCK_HEADER_RLP_MAX_BYTES;
    let blocks: Vec<String> =
        serde_json::from_reader(File::open("data/headers/default_blocks_goerli.json").unwrap())
            .unwrap();
    let mut input_bytes = Vec::new();
    let max_depth = 3;
    for block_str in blocks.iter() {
        let mut block_vec: Vec<u8> = Vec::from_hex(block_str).unwrap();
        block_vec.append(&mut vec![0u8; header_rlp_max_bytes - block_vec.len()]);
        input_bytes.push(block_vec);
    }
    let dummy_header_rlp = input_bytes[0].clone();
    input_bytes.extend(iter::repeat(dummy_header_rlp).take((1 << max_depth) - input_bytes.len()));

    #[derive(Deserialize)]
    struct JsonInstance {
        prev_hash: String,
        end_hash: String,
        start_block_number: String,
        end_block_number: String,
        mmr: Vec<String>,
    }
    let JsonInstance { prev_hash, end_hash, start_block_number, end_block_number, mmr } =
        serde_json::from_reader(File::open("data/headers/default_hashes_goerli.json").unwrap())
            .unwrap();
    let [prev_hash, end_hash] =
        [prev_hash, end_hash].map(|str| H256::from_slice(&Vec::from_hex(str).unwrap()));
    let [start_block_number, end_block_number] = [start_block_number, end_block_number]
        .map(|str| u32::from_str_radix(&str[2..], 16).unwrap());
    let merkle_mountain_range =
        mmr.iter().map(|str| H256::from_slice(&Vec::from_hex(str).unwrap())).collect();

    EthBlockHeaderChainCircuit {
        inputs: input_bytes,
        num_blocks: 7,
        instance: EthBlockHeaderChainInstance {
            prev_hash,
            end_hash,
            start_block_number,
            end_block_number,
            merkle_mountain_range,
        },
        max_depth,
        network,
        _marker: PhantomData,
    }
}

#[test]
pub fn test_multi_goerli_header_mock() {
    set_var("BLOCK_HEADER_CONFIG", "configs/tests/multi_block.config");
    let config = EthBlockHeaderConfigParams::get();
    let k = config.degree;

    let circuit = get_default_goerli_header_chain_circuit();
    let instance = circuit.instance.to_instance();

    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
}

#[test]
pub fn test_multi_goerli_header_prover() {
    set_var("BLOCK_HEADER_CONFIG", "configs/tests/multi_block.config");
    let config = EthBlockHeaderConfigParams::get();
    let k = config.degree;
    let proof_circuit = get_default_goerli_header_chain_circuit();
    let circuit = proof_circuit.without_witnesses();

    let params = gen_srs(k);

    let vk_time = start_timer!(|| "vk gen");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pk gen");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    let instance = proof_circuit.instance.to_instance();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let pf_time = start_timer!(|| "proof gen");
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[proof_circuit], &[&[&instance]], OsRng, &mut transcript)
    .unwrap();
    let proof = transcript.finalize();
    end_timer!(pf_time);

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_time = start_timer!(|| "verify");
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[&instance]], &mut transcript)
    .unwrap();
    end_timer!(verify_time);
}

#[cfg(all(feature = "aggregation", feature = "providers"))]
mod aggregation {
    use super::helpers::gen_multiple_block_header_chain_snarks;
    use super::*;
    use crate::{
        block_header::helpers::autogen_final_block_header_chain_snark,
        providers::GOERLI_PROVIDER_URL,
    };
    use rand::SeedableRng;
    use snark_verifier_sdk::{
        halo2::{PoseidonTranscript, POSEIDON_SPEC},
        NativeLoader,
    };

    #[test]
    fn test_goerli_header_chain_provider() {
        let infura_id =
            std::fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider =
            Provider::<Http>::try_from(format!("{GOERLI_PROVIDER_URL}{infura_id}").as_str())
                .expect("could not instantiate HTTP Provider");

        let mut transcript =
            PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
        let mut rng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
        gen_multiple_block_header_chain_snarks(
            &provider,
            Network::Goerli,
            0x765fb3,
            0x765fb3 + 11,
            3,
            3,
            &mut transcript,
            &mut rng,
        );
    }

    #[test]
    fn test_goerli_header_chain_with_aggregation() {
        let infura_id =
            std::fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider =
            Provider::<Http>::try_from(format!("{GOERLI_PROVIDER_URL}{infura_id}").as_str())
                .expect("could not instantiate HTTP Provider");

        let mut transcript =
            PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
        let mut rng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
        gen_multiple_block_header_chain_snarks(
            &provider,
            Network::Goerli,
            0x765fb3,
            0x765fb3 + 11,
            4,
            3,
            &mut transcript,
            &mut rng,
        );
    }

    #[test]
    fn test_goerli_header_chain_final_aggregation() {
        let infura_id =
            std::fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider =
            Provider::<Http>::try_from(format!("{GOERLI_PROVIDER_URL}{infura_id}").as_str())
                .expect("could not instantiate HTTP Provider");

        let mut transcript =
            PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
        let mut rng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);

        autogen_final_block_header_chain_snark(
            &provider,
            Network::Goerli,
            0x765fb3,
            0x765fb3 + 11,
            4,
            3,
            &mut transcript,
            &mut rng,
        );
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_goerli_header_chain_for_evm() {
        use crate::block_header::helpers::evm::autogen_final_block_header_chain_snark_for_evm;

        let infura_id =
            std::fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider =
            Provider::<Http>::try_from(format!("{GOERLI_PROVIDER_URL}{infura_id}").as_str())
                .expect("could not instantiate HTTP Provider");
        let mut transcript =
            PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
        let mut rng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);

        autogen_final_block_header_chain_snark_for_evm(
            &provider,
            Network::Goerli,
            0x765fb3,
            0x765fb3 + 11,
            4,
            3,
            true,
            &mut transcript,
            &mut rng,
        );
    }
}
