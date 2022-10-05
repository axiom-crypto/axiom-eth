use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::fe_to_biguint,
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Challenge, Circuit, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed,
        Instance, SecondPhase, Selector,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use std::cmp::max;
use std::marker::PhantomData;

use eth_types::Field;

use crate::{
    keccak::KeccakChip,
    rlp::rlc::RlcTrace,
    rlp::rlp::{RlpArrayChip, RlpArrayTrace},
};

// parentHash	256 bits	32	33	264
// ommersHash	256 bits	32	33	264
// beneficiary	160 bits	20	21	168
// stateRoot	256 bits	32	33	264
// transactionsRoot	256 bits	32	33	264
// receiptsRoot	256 bits	32	33	264
// logsBloom	256 bytes	256	259	2072
// difficulty	big int scalar	variable	8	64
// number	big int scalar	variable	<= 4	<= 32
// gasLimit	big int scalar	variable	5	40
// gasUsed	big int scalar	variable	<= 5	<= 40
// timestamp	big int scalar	variable	5	40
// extraData	up to 256 bits	variable, <= 32	<= 33	<= 264
// mixHash	256 bits	32	33	264
// nonce	64 bits	8	9	72
// basefee (post-1559)	big int scalar	variable	<= 6	<= 48
#[derive(Clone, Debug)]
pub struct EthBlockHeaderTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    parent_hash: RlcTrace<F>,
    ommers_hash: RlcTrace<F>,
    beneficiary: RlcTrace<F>,
    state_root: RlcTrace<F>,
    transactions_root: RlcTrace<F>,
    receipts_root: RlcTrace<F>,
    logs_bloom: RlcTrace<F>,
    difficulty: RlcTrace<F>,
    number: RlcTrace<F>,
    gas_limit: RlcTrace<F>,
    gas_used: RlcTrace<F>,
    timestamp: RlcTrace<F>,
    extra_data: RlcTrace<F>,
    mix_hash: RlcTrace<F>,
    nonce: RlcTrace<F>,
    basefee: RlcTrace<F>,

    block_hash: RlcTrace<F>,

    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockHeaderChip<F: Field> {
    rlp: RlpArrayChip<F>,
    keccak: KeccakChip<F>,
}

impl<F: Field> EthBlockHeaderChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_basic_chips: usize,
        num_chips_fixed: usize,
        challenge_id: String,
        context_id: String,
        range_strategy: RangeStrategy,
        num_advice: &[usize],
        mut num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
    ) -> Self {
        let rlp = RlpArrayChip::configure(
            meta,
            num_basic_chips,
            num_chips_fixed,
            challenge_id.clone(),
            context_id,
            range_strategy,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
        );
        let keccak = KeccakChip::configure(meta, "keccak".to_string(), 1088, 256, 64, 1);
        Self { rlp, keccak }
    }

    pub fn decompose_eth_block_header(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        block_header: &Vec<AssignedValue<F>>,
    ) -> Result<EthBlockHeaderTrace<F>, Error> {
        let max_len = 1 + 2 + 553;
        let max_field_lens = vec![33, 33, 21, 33, 33, 33, 259, 8, 4, 5, 5, 5, 33, 33, 9, 6];
        let num_fields = 16;
        let rlp_array_trace = self.rlp.decompose_rlp_array(
            ctx,
            range,
            block_header,
            max_field_lens,
            max_len,
            num_fields,
        )?;

        let mut block_bits = Vec::with_capacity(8 * block_header.len());
        for byte in block_header.iter() {
            let mut bits = range.num_to_bits(ctx, byte, 8)?;
            block_bits.append(&mut bits);
        }
        println!("block_bits {:?}", block_bits.len());
        let hash = self.keccak.keccak(ctx, block_bits.iter().map(|a| Existing(a)).collect())?;
        let mut hash_bytes = Vec::with_capacity(32);
        for idx in 0..32 {
            let (_, _, byte) = range.gate.inner_product(
                ctx,
                &hash[8 * idx..(8 * (idx + 1))].iter().map(|a| Existing(a)).collect(),
                &vec![128u64, 64u64, 32u64, 16u64, 8u64, 4u64, 2u64, 1u64]
                    .iter()
                    .map(|a| Constant(F::from(*a)))
                    .collect(),
            )?;
            hash_bytes.push(byte);
        }
        let hash_len = range.gate.assign_region_smart(
            ctx,
            vec![Constant(F::from(32))],
            vec![],
            vec![],
            vec![],
        )?;
        let block_hash =
            self.rlp.rlc.compute_rlc(ctx, range, &hash_bytes, hash_len[0].clone(), 32)?;

        let block_header_trace = EthBlockHeaderTrace {
            rlp_trace: rlp_array_trace.array_trace.clone(),
            parent_hash: rlp_array_trace.field_traces[0].clone(),
            ommers_hash: rlp_array_trace.field_traces[1].clone(),
            beneficiary: rlp_array_trace.field_traces[2].clone(),
            state_root: rlp_array_trace.field_traces[3].clone(),
            transactions_root: rlp_array_trace.field_traces[4].clone(),
            receipts_root: rlp_array_trace.field_traces[5].clone(),
            logs_bloom: rlp_array_trace.field_traces[6].clone(),
            difficulty: rlp_array_trace.field_traces[7].clone(),
            number: rlp_array_trace.field_traces[8].clone(),
            gas_limit: rlp_array_trace.field_traces[9].clone(),
            gas_used: rlp_array_trace.field_traces[10].clone(),
            timestamp: rlp_array_trace.field_traces[11].clone(),
            extra_data: rlp_array_trace.field_traces[12].clone(),
            mix_hash: rlp_array_trace.field_traces[13].clone(),
            nonce: rlp_array_trace.field_traces[14].clone(),
            basefee: rlp_array_trace.field_traces[15].clone(),

            block_hash: block_hash,

            prefix: rlp_array_trace.prefix.clone(),
            len_trace: rlp_array_trace.len_trace.clone(),
            field_prefixs: rlp_array_trace.field_prefixs.clone(),
            field_len_traces: rlp_array_trace.field_len_traces.clone(),
        };
        Ok(block_header_trace)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EthBlockHeaderTestCircuit<F> {
    pub inputs: Vec<Option<u8>>,
    pub _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for EthBlockHeaderTestCircuit<F> {
    type Config = EthBlockHeaderChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        EthBlockHeaderChip::configure(
            meta,
            1,
            1,
            "gamma".to_string(),
            "rlc".to_string(),
            Vertical,
            &[15],
            &[1],
            1,
            11,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.rlp.range.load_lookup_table(&mut layouter)?;
        let gamma = layouter.get_challenge(config.rlp.rlc.gamma);
        println!("gamma {:?}", gamma);

        let using_simple_floor_planner = true;
        let mut phase = 0u8;
        let keccak_inputs = layouter.assign_region(
            || "Eth block test",
            |mut region| {
                phase = phase + 1u8;

                println!("phase {:?}", phase);
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![
                            ("default".to_string(), config.rlp.range.gate.num_advice),
                            ("rlc".to_string(), config.rlp.rlc.basic_chips.len()),
                            ("keccak".to_string(), 1),
                        ],
                    },
                );
                let ctx = &mut aux;
                ctx.challenge.insert("gamma".to_string(), gamma);

                let inputs_assigned = config.rlp.range.gate.assign_region_smart(
                    ctx,
                    self.inputs
                        .iter()
                        .map(|x| {
                            Witness(
                                x.map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown()),
                            )
                        })
                        .collect(),
                    vec![],
                    vec![],
                    vec![],
                )?;

                let block_header_trace =
                    config.decompose_eth_block_header(ctx, &config.rlp.range, &inputs_assigned)?;
                let keccak_inputs_iter = inputs_assigned.iter().map(|x| x.value().copied());
                let keccak_inputs: Vec<Vec<Value<F>>> = vec![keccak_inputs_iter.collect()];

                let stats = config.rlp.range.finalize(ctx)?;
                println!("stats {:?}", stats);
                println!("ctx.rows rlc {:?}", ctx.advice_rows.get::<String>(&"rlc".to_string()));
                println!(
                    "ctx.rows default {:?}",
                    ctx.advice_rows.get::<String>(&"default".to_string())
                );
                Ok(keccak_inputs)
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::eth::block_header::EthBlockHeaderTestCircuit;
    use halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use hex::FromHex;
    use std::marker::PhantomData;

    #[test]
    pub fn test_mock_eth_block_header() {
        let k = 15;
        let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let input_bytes_pre: Vec<u8> = Vec::from_hex(input_hex).unwrap();
        let input_bytes: Vec<Option<u8>> = input_bytes_pre.iter().map(|x| Some(*x)).collect();

        let circuit = EthBlockHeaderTestCircuit::<Fr> { inputs: input_bytes, _marker: PhantomData };
        let prover_try = MockProver::run(k, &circuit, vec![]);
        let prover = prover_try.unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    pub fn test_eth_block_header() -> Result<(), Box<dyn std::error::Error>> {
        let k = 13;
        let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let input_bytes_pre: Vec<u8> = Vec::from_hex(input_hex).unwrap();
        let input_bytes: Vec<Option<u8>> = input_bytes_pre.iter().map(|x| Some(*x)).collect();
        let input_nones: Vec<Option<u8>> = input_bytes.iter().map(|x| None).collect();

        let mut rng = rand::thread_rng();
        let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let circuit = EthBlockHeaderTestCircuit::<Fr> { inputs: input_nones, _marker: PhantomData };

        println!("vk gen started");
        let vk = keygen_vk(&params, &circuit)?;
        println!("vk gen done");
        let pk = keygen_pk(&params, vk, &circuit)?;
        println!("pk gen done");
        println!("");
        println!("==============STARTING PROOF GEN===================");

        let proof_circuit =
            EthBlockHeaderTestCircuit::<Fr> { inputs: input_bytes, _marker: PhantomData };

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            EthBlockHeaderTestCircuit<Fr>,
        >(&params, &pk, &[proof_circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        println!("proof gen done");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .is_ok());
        println!("verify done");
        Ok(())
    }
}
