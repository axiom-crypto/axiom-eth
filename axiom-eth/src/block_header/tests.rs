use crate::{
    mpt::MPTChip,
    rlc::{circuit::RlcCircuitParams, tests::get_rlc_params},
    utils::{
        assign_vec,
        eth_circuit::{create_circuit, EthCircuitImpl, EthCircuitInstructions},
    },
};

use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr},
        plonk::*,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::testing::{check_proof_with_instances, gen_proof_with_instances},
};
use hex::FromHex;
use rand_core::OsRng;
use std::marker::PhantomData;
use test_log::test;

/// The maximum possible RLP byte length of a block header *at any block* (including all EIPs).
///
/// Provided that the total length is < 256^2, this will be 1 + 2 + sum(max RLP byte length of each field)
const MAINNET_EXTRA_DATA_RLP_MAX_BYTES: usize = max_rlp_encoding_len(MAINNET_EXTRA_DATA_MAX_BYTES);
const MAINNET_BLOCK_HEADER_RLP_MAX_BYTES: usize =
    1 + 2 + (515 + MAINNET_EXTRA_DATA_RLP_MAX_BYTES + 33 + 33 + 9 * 2 + 33); // 33 + 33 is for basefee, withdrawals_root, 9*2 for eip-4844, 33 for eip-4788

#[test]
fn test_block_header_rlp_max_lens() {
    let from_chain = get_block_header_rlp_max_lens_from_chain_id(1);
    assert_eq!(from_chain.0, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES);
    assert_eq!(from_chain.1, MAINNET_HEADER_FIELDS_MAX_BYTES);
}

#[derive(Clone)]
struct HeaderTest<F: Field> {
    headers: Vec<Vec<u8>>,
    _marker: PhantomData<F>,
}

struct HeaderWitness<F: Field> {
    chain: Vec<EthBlockHeaderWitness<F>>,
}

impl<F: Field> EthCircuitInstructions<F> for HeaderTest<F> {
    type FirstPhasePayload = HeaderWitness<F>;
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let chip = EthBlockHeaderChip::new_from_network(mpt.rlp, Chain::Mainnet);
        let ctx = builder.base.main(0);
        let inputs = self
            .headers
            .iter()
            .map(|header| assign_vec(ctx, header.clone(), MAINNET_BLOCK_HEADER_RLP_MAX_BYTES))
            .collect_vec();
        let chain = chip.decompose_block_header_chain_phase0(builder, mpt.keccak, inputs);
        HeaderWitness { chain }
    }

    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        witness: Self::FirstPhasePayload,
    ) {
        let chip = EthBlockHeaderChip::new_from_network(mpt.rlp, Chain::Mainnet);
        chip.decompose_block_header_chain_phase1(builder, witness.chain, None);
    }
}

fn block_header_test_circuit<F: Field>(
    stage: CircuitBuilderStage,
    inputs: Vec<Vec<u8>>,
    params: RlcCircuitParams,
) -> EthCircuitImpl<F, HeaderTest<F>> {
    let test = HeaderTest { headers: inputs, _marker: PhantomData };
    let mut circuit = create_circuit(stage, params, test);
    circuit.mock_fulfill_keccak_promises(None);
    if !stage.witness_gen_only() {
        circuit.calculate_params();
    }
    circuit
}

#[test]
pub fn test_one_mainnet_header_mock() {
    let params = get_rlc_params("configs/tests/one_block.json");
    let k = params.base.k as u32;
    let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e60000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let circuit =
        block_header_test_circuit::<Fr>(CircuitBuilderStage::Mock, vec![input_bytes], params);
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test]
pub fn test_one_mainnet_header_before_london_mock() {
    let params = get_rlc_params("configs/tests/one_block.json");
    let k = params.base.k as u32;
    let input_hex = "f90221a0b8b861952bca93c10bc7c38f9ef5c4e047beae539cfe46fa456c78893d916927a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940501b62d81a3f072f1d393d2f74013bab8d36d5ca01fd1d6a626d5d72d433b776c0c348f0cab03d13c68ba39ca4a6d6f109032de34a0418c7fdf567a5989a727ea0fe6054008ecf4953aaf56c28f7f197f6e443f05c0a05f79bcb9839eb480350b541377d04c5088fc4bab6952ed27cb94c70dd6736d73b9010081029040054830208119a218064a503c384490dc2014a414e3148820851856c05008e643a88a4a0002242e1a702d8a516244220a18cd0121a13a20882930000e471369c142ad4323475013088accb068824a002cc35021640860a448405a904001094c200a6081d0420feb02802c2e090a121403213d2640c100503510300364e43020f55943142815080595b145040045890021412545119b9002891cfe41011a704100ca97641210002a3b22c10f24853849048420100465c361880421593000021022c90800008800750e546464068cc40290108c48741899114af9c52801403da6800c02000c6ea270992068b45618c46f1254d7601d4411104e41d00a0787074abe0f14de3383765fdd837a121d8379cbd7845cda8ef39fde830203088f5061726974792d457468657265756d86312e33332e30826c69a09d41f9f64af4ebd672dec132507a12a4c85c1a514f47969dbd9c2b5e9d7d214e882b8a10229542325400000000000000000000";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let circuit =
        block_header_test_circuit::<Fr>(CircuitBuilderStage::Mock, vec![input_bytes], params);
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test]
pub fn test_one_mainnet_header_withdrawals_mock() {
    let params = get_rlc_params("configs/tests/one_block.json");
    let k = params.base.k as u32;
    let input_hex = "f90222a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6a0f7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let circuit =
        block_header_test_circuit::<Fr>(CircuitBuilderStage::Mock, vec![input_bytes], params);
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test]
pub fn test_one_mainnet_header_fake_cancun_mock() {
    let params = get_rlc_params("configs/tests/one_block.json");
    let k = params.base.k as u32;
    let input_hex = "f90249a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6a0f7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549820123820456a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c2";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let circuit =
        block_header_test_circuit::<Fr>(CircuitBuilderStage::Mock, vec![input_bytes], params);
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test]
pub fn test_one_mainnet_header_prover() -> Result<(), Box<dyn std::error::Error>> {
    let config_params = get_rlc_params("configs/tests/one_block.json");
    let k = config_params.base.k as u32;
    let input_hex = "f90222a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6a0f7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let mut rng = OsRng;
    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let circuit = block_header_test_circuit::<Fr>(
        CircuitBuilderStage::Keygen,
        vec![input_bytes.clone()],
        config_params,
    );
    //circuit.config(k as usize, Some(109));
    let vk_time = start_timer!(|| "vk gen");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pk gen");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);
    let break_points = circuit.break_points();
    let config_params = circuit.params().rlc;

    let pf_time = start_timer!(|| "proof gen");
    let circuit = block_header_test_circuit::<Fr>(
        CircuitBuilderStage::Prover,
        vec![input_bytes],
        config_params,
    )
    .use_break_points(break_points);
    let instances = circuit.instances();
    assert_eq!(instances.len(), 1);
    let proof = gen_proof_with_instances(&params, &pk, circuit, &[&instances[0]]);
    end_timer!(pf_time);

    let verify_time = start_timer!(|| "verify");
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instances[0]], true);
    end_timer!(verify_time);

    Ok(())
}
