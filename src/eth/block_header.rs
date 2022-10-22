#[cfg(feature = "input_gen")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::{biguint_to_fe, fe_to_biguint},
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_curves::FieldExt;
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
use hex::FromHex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{cast::ToPrimitive, Num};
use rand_core::block;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::{cmp::max, fs};

use eth_types::Field;

use crate::{
    keccak::{print_bytes, KeccakChip},
    rlp::rlc::{RlcFixedTrace, RlcTrace},
    rlp::rlp::{RlpArrayChip, RlpArrayTrace},
};

#[cfg(feature = "aggregation")]
pub mod aggregation;

const MAINNET_EXTRA_DATA_RLP_MAX_BYTES: usize = 33;
const MAINNET_BLOCK_HEADER_RLP_MAX_BYTES: usize = 1 + 2 + 520 + MAINNET_EXTRA_DATA_RLP_MAX_BYTES;
const GOERLI_EXTRA_DATA_RLP_MAX_BYTES: usize = 98;
const GOERLI_BLOCK_HEADER_RLP_MAX_BYTES: usize = 1 + 2 + 520 + GOERLI_EXTRA_DATA_RLP_MAX_BYTES;

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
#[allow(dead_code)]
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

    block_hash: RlcFixedTrace<F>,

    block_hash_bytes: Vec<AssignedValue<F>>,
    block_hash_hexes: Vec<AssignedValue<F>>,

    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Strategy {
    Simple,
    SimplePlus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthBlockHeaderConfigParams {
    pub degree: u32,
    pub num_basic_chips: usize,
    pub range_strategy: Strategy,
    pub num_advice: Vec<usize>,
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    pub lookup_bits: usize,

    pub keccak_num_advice: usize,
    pub keccak_num_xor: usize,
    pub keccak_num_xorandn: usize,
    // pub keccak_num_fixed: usize,
}

#[derive(Clone, Debug)]
pub struct EthBlockHeaderChip<F: Field> {
    pub rlp: RlpArrayChip<F>,
    pub keccak: KeccakChip<F>,
    // the instance column will contain the latest blockhash and the merkle root of all the blockhashes
    pub instance: Column<Instance>,
}

impl<F: Field> EthBlockHeaderChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        challenge_id: String,
        context_id: String,
        params: EthBlockHeaderConfigParams,
    ) -> Self {
        let rlp = RlpArrayChip::configure(
            meta,
            params.num_basic_chips,
            0, // share fixed columns with rlp.range
            challenge_id.clone(),
            context_id,
            match params.range_strategy {
                Strategy::Simple => RangeStrategy::Vertical,
                _ => RangeStrategy::PlonkPlus,
            },
            &params.num_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
        );
        // println!("params adv {:?} fix {:?}", params.num_advice, params.num_fixed);
        let keccak = KeccakChip::configure(
            meta,
            "keccak".to_string(),
            1088,
            256,
            params.keccak_num_advice,
            params.keccak_num_xor,
            params.keccak_num_xorandn,
            0, // keccak should just use the fixed columns of RLP chip
        );
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self { rlp, keccak, instance }
    }

    pub fn decompose_eth_block_header(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        block_header: &Vec<AssignedValue<F>>,
    ) -> Result<EthBlockHeaderTrace<F>, Error> {
        let max_len = 1 + 2 + 520 + GOERLI_EXTRA_DATA_RLP_MAX_BYTES;
        let max_field_lens = vec![
            33,
            33,
            21,
            33,
            33,
            33,
            259,
            8,
            4,
            5,
            5,
            5,
            GOERLI_EXTRA_DATA_RLP_MAX_BYTES,
            33,
            9,
            6,
        ];
        let num_fields = 16;
        let rlp_array_trace = self.rlp.decompose_rlp_array(
            ctx,
            range,
            block_header,
            max_field_lens,
            max_len,
            num_fields,
        )?;
        let (hash_bytes, hash_hexes) = self.keccak.keccak_bytes_var_len(
            ctx,
            range,
            &block_header,
            rlp_array_trace.array_trace.rlc_len.clone(),
            479,
            max_len,
        )?;
        let block_hash = self.rlp.rlc.compute_rlc_fixed_len(ctx, range, &hash_bytes, 32)?;

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
            block_hash_bytes: hash_bytes,
            block_hash_hexes: hash_hexes,

            prefix: rlp_array_trace.prefix.clone(),
            len_trace: rlp_array_trace.len_trace.clone(),
            field_prefixs: rlp_array_trace.field_prefixs.clone(),
            field_len_traces: rlp_array_trace.field_len_traces.clone(),
        };
        Ok(block_header_trace)
    }

    // headers[0] is the earliest block
    pub fn decompose_eth_block_header_chain(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        headers: &Vec<Vec<AssignedValue<F>>>,
    ) -> Result<Vec<EthBlockHeaderTrace<F>>, Error> {
        let traces = headers
            .iter()
            .map(|header| self.decompose_eth_block_header(ctx, range, header).unwrap())
            .collect_vec();

        // check the hash of headers[idx] is in headers[idx + 1]
        for idx in 0..traces.len() - 1 {
            ctx.region.constrain_equal(
                traces[idx].block_hash.rlc_val.cell(),
                traces[idx + 1].parent_hash.rlc_val.cell(),
            )?;
            ctx.constants_to_assign
                .push((F::from(32), Some(traces[idx + 1].parent_hash.rlc_len.cell())));
        }
        Ok(traces)
    }
}

pub fn limbs_be_to_u128<F: FieldExt>(
    ctx: &mut Context<'_, F>,
    gate: &impl GateInstructions<F>,
    limbs: &[AssignedValue<F>],
    limb_bits: usize,
) -> Vec<AssignedValue<F>> {
    assert_eq!(128 % limb_bits, 0);
    (0..limbs.len())
        .step_by(128 / limb_bits)
        .map(|i| {
            let chunk_size = std::cmp::min(128 / limb_bits, limbs.len() - i);
            let (_, _, word) = gate
                .inner_product(
                    ctx,
                    &(0..chunk_size).map(|idx| Existing(&limbs[i + idx])).collect_vec(),
                    &(0..chunk_size)
                        .rev()
                        .map(|idx| {
                            Constant(biguint_to_fe(&(BigUint::from(1u64) << (limb_bits * idx))))
                        })
                        .collect_vec(),
                )
                .unwrap();
            word
        })
        .collect_vec()
}

pub fn bytes_be_to_u128<F: FieldExt>(
    ctx: &mut Context<'_, F>,
    gate: &impl GateInstructions<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    limbs_be_to_u128(ctx, gate, bytes, 8)
}

// this function is too specialized to be used outside the crate
pub(crate) fn hexes_to_u128<F: FieldExt>(
    ctx: &mut Context<'_, F>,
    gate: &impl GateInstructions<F>,
    hexes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    assert_eq!(hexes.len() % 32, 0);
    // unfortunately the hexes should be considered as a big endian byte string, but each pair of hex -> byte is little endian
    (0..hexes.len())
        .step_by(32)
        .map(|i| {
            let (_, _, word) = gate
                .inner_product(
                    ctx,
                    &(0..32).map(|idx| Existing(&hexes[i + idx])).collect_vec(),
                    &(0..16)
                        .rev()
                        .flat_map(|idx| {
                            [
                                BigUint::from(1u64) << (4 * 2 * idx),
                                BigUint::from(1u64) << (4 * (2 * idx + 1)),
                            ]
                            .map(|x| Constant(biguint_to_fe(&x)))
                        })
                        .into_iter()
                        .collect_vec(),
                )
                .unwrap();
            word
        })
        .collect_vec()
}

#[derive(Clone, Debug)]
pub struct EthBlockHeaderHashCircuit<F> {
    pub inputs: Vec<Vec<Option<u8>>>,
    // parent hash, last blockhash, merkle root
    pub instance: Vec<BigUint>,
    pub _marker: PhantomData<F>,
}

impl<F> Default for EthBlockHeaderHashCircuit<F> {
    fn default() -> Self {
        let blocks_str = std::fs::read_to_string("data/headers/default_blocks.json").unwrap();
        let blocks: Vec<String> = serde_json::from_str(blocks_str.as_str()).unwrap();
        let mut input_bytes = Vec::new();
        for block_str in blocks.iter() {
            let mut block_vec: Vec<Option<u8>> =
                Vec::from_hex(block_str).unwrap().iter().map(|y| Some(*y)).collect();
            block_vec
                .append(&mut vec![Some(0u8); MAINNET_BLOCK_HEADER_RLP_MAX_BYTES - block_vec.len()]);
            input_bytes.push(block_vec);
        }

        let instance_str = std::fs::read_to_string("data/headers/default_hashes.json").unwrap();
        let instance: Vec<String> = serde_json::from_str(instance_str.as_str()).unwrap();
        let instance = instance
            .iter()
            .map(|instance| BigUint::from_str_radix(instance.as_str(), 16).unwrap())
            .collect_vec();

        Self { inputs: input_bytes, instance, _marker: PhantomData }
    }
}

impl<F: Field> EthBlockHeaderHashCircuit<F> {
    pub fn instances(&self) -> Vec<Vec<F>> {
        let instance = self
            .instance
            .iter()
            .flat_map(|x| vec![x.clone() >> 128usize, x.clone() % (BigUint::from(1u64) << 128)])
            .into_iter()
            .map(|x| biguint_to_fe(&x))
            .collect_vec();
        vec![instance]
    }

    // this is read from file generated by python script
    // for testing purposes only; the production usage uses binary serialization
    pub fn from_file(last_block_number: u64, num_blocks: u64) -> Self {
        let path = format!("./data/headers/{:06x}_{}.json", last_block_number, num_blocks);
        let blocks_str = std::fs::read_to_string(path.as_str()).unwrap();
        let blocks: Vec<String> = serde_json::from_str(blocks_str.as_str()).unwrap();
        let mut input_bytes = Vec::new();
        for block_str in blocks.iter() {
            let mut block_vec: Vec<Option<u8>> =
                Vec::from_hex(block_str).unwrap().iter().map(|y| Some(*y)).collect();
            block_vec
                .append(&mut vec![Some(0u8); MAINNET_BLOCK_HEADER_RLP_MAX_BYTES - block_vec.len()]);
            input_bytes.push(block_vec);
        }

        let path =
            format!("./data/headers/{:06x}_{}_instances.json", last_block_number, num_blocks);
        let instance_str = std::fs::read_to_string(path.as_str()).unwrap();
        let instance: Vec<String> = serde_json::from_str(instance_str.as_str()).unwrap();
        let instance = instance
            .iter()
            .map(|instance| BigUint::from_str_radix(instance.as_str(), 16).unwrap())
            .collect_vec();

        Self { inputs: input_bytes, instance, _marker: PhantomData }
    }

    #[cfg(feature = "input_gen")]
    pub fn from_provider(
        provider: &Provider<Http>,
        last_block_number: u64,
        num_blocks: u64,
    ) -> Self {
        let (block_rlps, instance) = crate::input_gen::get_blocks_input(
            provider,
            last_block_number - num_blocks + 1,
            num_blocks,
        );
        let input_bytes = block_rlps
            .into_iter()
            .map(|block| {
                let block_len = block.len();
                block
                    .into_iter()
                    .map(|y| Some(y))
                    .into_iter()
                    .chain(
                        (0..GOERLI_BLOCK_HEADER_RLP_MAX_BYTES - block_len)
                            .map(|_| Some(0u8))
                            .into_iter(),
                    )
                    .collect_vec()
            })
            .collect_vec();
        let instance =
            instance.into_iter().map(|bytes| BigUint::from_bytes_be(&bytes)).collect_vec();

        Self { inputs: input_bytes, instance, _marker: PhantomData }
    }
}

impl<F: Field> Circuit<F> for EthBlockHeaderHashCircuit<F> {
    type Config = EthBlockHeaderChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: self.inputs.iter().map(|input| vec![None; input.len()]).collect_vec(),
            instance: Vec::new(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params_str = fs::read_to_string("configs/block_header.config").unwrap();
        let params: EthBlockHeaderConfigParams = serde_json::from_str(params_str.as_str()).unwrap();

        EthBlockHeaderChip::configure(meta, "gamma".to_string(), "rlc".to_string(), params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.rlp.range.load_lookup_table(&mut layouter)?;
        config.keccak.load_lookup_table(&mut layouter)?;
        let gamma = layouter.get_challenge(config.rlp.rlc.gamma);
        #[cfg(feature = "display")]
        println!("gamma {:?}", gamma);

        let using_simple_floor_planner = true;
        let mut first_pass = true;
        let mut phase = 0u8;
        let mut parent_block_hash = None;
        let mut latest_block_hash = None;
        let mut merkle_root = None;
        layouter.assign_region(
            || "Eth block header with merkle root",
            |region| {
                if using_simple_floor_planner && first_pass {
                    first_pass = false;
                    return Ok(());
                }
                phase = phase + 1u8;

                #[cfg(feature = "display")]
                println!("phase {:?}", phase);
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![
                            ("default".to_string(), config.rlp.range.gate.num_advice),
                            ("rlc".to_string(), config.rlp.rlc.basic_chips.len()),
                            ("keccak".to_string(), config.keccak.rotation.len()),
                            ("keccak_xor".to_string(), config.keccak.xor_values.len() / 3),
                            ("keccak_xorandn".to_string(), config.keccak.xorandn_values.len() / 4),
                        ],
                    },
                );
                let ctx = &mut aux;
                ctx.challenge.insert("gamma".to_string(), gamma);

                let mut inputs_assigned = Vec::with_capacity(self.inputs.len());
                for input in self.inputs.iter() {
                    let input_assigned = config.rlp.range.gate.assign_region_smart(
                        ctx,
                        input
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
                    inputs_assigned.push(input_assigned);
                }

                let block_header_trace = config
                    .decompose_eth_block_header_chain(ctx, &config.rlp.range, &inputs_assigned)
                    .unwrap();

                // block_hash is 256 bits, but we need them in 128 bits to fit in Bn254 scalar field
                parent_block_hash = Some(bytes_be_to_u128(
                    ctx,
                    config.rlp.range.gate(),
                    &inputs_assigned[0][4..36],
                ));
                latest_block_hash = Some(bytes_be_to_u128(
                    ctx,
                    config.rlp.range.gate(),
                    &block_header_trace.last().unwrap().block_hash_bytes,
                ));

                let tree_root_hexes = config.keccak.merkle_tree_root(
                    ctx,
                    &block_header_trace
                        .iter()
                        .map(|trace| trace.block_hash_hexes.as_slice())
                        .collect_vec(),
                )?;
                merkle_root = Some(hexes_to_u128(ctx, config.rlp.range.gate(), &tree_root_hexes));

                let stats = config.rlp.range.finalize(ctx)?;
                #[cfg(feature = "display")]
                {
                    println!("stats (fixed rows, total fixed, lookups) {:?}", stats);
                    println!(
                        "ctx.rows rlc {:?}",
                        ctx.advice_rows.get::<String>(&"rlc".to_string())
                    );
                    println!(
                        "ctx.rows default {:?}",
                        ctx.advice_rows.get::<String>(&"default".to_string())
                    );
                    println!("ctx.rows keccak_xor {:?}", ctx.advice_rows["keccak_xor"]);
                    println!("ctx.rows keccak_xorandn {:?}", ctx.advice_rows["keccak_xorandn"]);
                    println!(
                        "ctx.advice_rows sums: {:#?}",
                        ctx.advice_rows
                            .iter()
                            .map(|(key, val)| (key, val.iter().sum::<usize>()))
                            .collect::<Vec<_>>()
                    );
                    println!("{:#?}", ctx.op_count);
                }

                Ok(())
            },
        )?;
        Ok({
            let parent_block_hash = parent_block_hash.unwrap();
            let latest_block_hash = latest_block_hash.unwrap();
            let merkle_root = merkle_root.unwrap();
            assert_eq!(latest_block_hash.len(), 2);
            assert_eq!(merkle_root.len(), 2);
            let mut layouter = layouter.namespace(|| "expose");
            for (i, assigned_instance) in parent_block_hash
                .iter()
                .chain(latest_block_hash.iter())
                .chain(merkle_root.iter())
                .enumerate()
            {
                layouter.constrain_instance(assigned_instance.cell(), config.instance, i)?;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{end_timer, start_timer};
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
    #[cfg(feature = "aggregation")]
    use plonk_verifier::system::halo2::aggregation::gen_srs;
    use std::marker::PhantomData;

    #[derive(Clone, Debug, Default)]
    pub struct EthBlockHeaderTestCircuit<F> {
        pub inputs: Vec<Vec<Option<u8>>>,
        pub _marker: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for EthBlockHeaderTestCircuit<F> {
        type Config = EthBlockHeaderChip<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let params_str = fs::read_to_string("configs/block_header.config").unwrap();
            let params: EthBlockHeaderConfigParams =
                serde_json::from_str(params_str.as_str()).unwrap();

            EthBlockHeaderChip::configure(meta, "gamma".to_string(), "rlc".to_string(), params)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let witness_time = start_timer!(|| "witness gen");
            config.rlp.range.load_lookup_table(&mut layouter)?;
            config.keccak.load_lookup_table(&mut layouter)?;
            let gamma = layouter.get_challenge(config.rlp.rlc.gamma);
            println!("gamma {:?}", gamma);

            let using_simple_floor_planner = true;
            let mut first_pass = true;
            let mut phase = 0u8;
            let mut block_header_trace = None;
            layouter.assign_region(
                || "Eth block test",
                |region| {
                    if using_simple_floor_planner && first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    phase = phase + 1u8;

                    println!("phase {:?}", phase);
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            num_advice: vec![
                                ("default".to_string(), config.rlp.range.gate.num_advice),
                                ("rlc".to_string(), config.rlp.rlc.basic_chips.len()),
                                ("keccak".to_string(), config.keccak.rotation.len()),
                                ("keccak_xor".to_string(), config.keccak.xor_values.len() / 3),
                                (
                                    "keccak_xorandn".to_string(),
                                    config.keccak.xorandn_values.len() / 4,
                                ),
                            ],
                        },
                    );
                    let ctx = &mut aux;
                    ctx.challenge.insert("gamma".to_string(), gamma);

                    let mut inputs_assigned = Vec::with_capacity(self.inputs.len());
                    for input in self.inputs.iter() {
                        let input_assigned = config.rlp.range.gate.assign_region_smart(
                            ctx,
                            input
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
                        inputs_assigned.push(input_assigned);
                    }

                    block_header_trace = Some(
                        config
                            .decompose_eth_block_header_chain(
                                ctx,
                                &config.rlp.range,
                                &inputs_assigned,
                            )
                            .unwrap(),
                    );

                    let stats = config.rlp.range.finalize(ctx)?;
                    println!("stats (fixed rows, total fixed, lookups) {:?}", stats);
                    println!(
                        "ctx.rows rlc {:?}",
                        ctx.advice_rows.get::<String>(&"rlc".to_string())
                    );
                    println!(
                        "ctx.rows default {:?}",
                        ctx.advice_rows.get::<String>(&"default".to_string())
                    );
                    println!("ctx.rows keccak_xor {:?}", ctx.advice_rows["keccak_xor"]);
                    println!("ctx.rows keccak_xorandn {:?}", ctx.advice_rows["keccak_xorandn"]);
                    println!(
                        "ctx.advice_rows sums: {:#?}",
                        ctx.advice_rows
                            .iter()
                            .map(|(key, val)| (key, val.iter().sum::<usize>()))
                            .collect::<Vec<_>>()
                    );
                    #[cfg(feature = "display")]
                    println!("{:#?}", ctx.op_count);

                    Ok(())
                },
            )?;
            end_timer!(witness_time);
            Ok(())
        }
    }

    #[test]
    pub fn test_mock_one_eth_header() {
        let params_str = std::fs::read_to_string("configs/block_header.config").unwrap();
        let params: crate::keccak::KeccakCircuitParams =
            serde_json::from_str(params_str.as_str()).unwrap();
        let k = params.degree;
        let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let input_bytes_pre: Vec<u8> = Vec::from_hex(input_hex).unwrap();
        let input_bytes: Vec<Option<u8>> = input_bytes_pre.iter().map(|x| Some(*x)).collect();

        let circuit =
            EthBlockHeaderTestCircuit::<Fr> { inputs: vec![input_bytes], _marker: PhantomData };
        let prover_try = MockProver::run(k, &circuit, vec![]);
        let prover = prover_try.unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    pub fn test_eth_block_header() -> Result<(), Box<dyn std::error::Error>> {
        let params_str = std::fs::read_to_string("configs/block_header.config").unwrap();
        let params: crate::keccak::KeccakCircuitParams =
            serde_json::from_str(params_str.as_str()).unwrap();
        let k = params.degree;

        let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let input_bytes_pre: Vec<u8> = Vec::from_hex(input_hex).unwrap();
        let input_bytes: Vec<Vec<Option<u8>>> =
            vec![input_bytes_pre.iter().map(|x| Some(*x)).collect()];
        let input_nones: Vec<Vec<Option<u8>>> =
            vec![input_bytes_pre.iter().map(|x| None).collect()];

        let mut rng = rand::thread_rng();
        let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let circuit = EthBlockHeaderTestCircuit::<Fr> { inputs: input_nones, _marker: PhantomData };

        let vk_time = start_timer!(|| "vk gen");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);
        let pk_time = start_timer!(|| "pk gen");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let proof_circuit =
            EthBlockHeaderTestCircuit::<Fr> { inputs: input_bytes, _marker: PhantomData };
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        let pf_time = start_timer!(|| "proof gen");
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            EthBlockHeaderTestCircuit<Fr>,
        >(&params, &pk, &[proof_circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(pf_time);

        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verify_time = start_timer!(|| "verify");
        assert!(verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .is_ok());
        end_timer!(verify_time);

        Ok(())
    }

    #[test]
    pub fn test_mock_multi_eth_header() {
        let config_str = std::fs::read_to_string("configs/block_header.config").unwrap();
        let config: EthBlockHeaderConfigParams = serde_json::from_str(config_str.as_str()).unwrap();
        let k = config.degree;

        let circuit = EthBlockHeaderHashCircuit::<Fr>::default();
        let instances = circuit.instances();

        let prover_try = MockProver::run(k, &circuit, instances);
        let prover = prover_try.unwrap();
        prover.assert_satisfied();
    }

    #[test]
    pub fn test_multi_eth_header() -> Result<(), Box<dyn std::error::Error>> {
        let config_str = std::fs::read_to_string("configs/block_header.config").unwrap();
        let config: EthBlockHeaderConfigParams = serde_json::from_str(config_str.as_str()).unwrap();
        let k = config.degree;

        #[cfg(feature = "aggregation")]
        let params = gen_srs(k);
        #[cfg(not(feature = "aggregation"))]
        let params = ParamsKZG::<Bn256>::setup(k, &mut rand::thread_rng());
        let circuit = EthBlockHeaderHashCircuit::<Fr>::default();

        let vk_time = start_timer!(|| "vk gen");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);
        let pk_time = start_timer!(|| "pk gen");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let proof_circuit = circuit.clone();
        let instance = circuit.instances()[0].clone();
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        let rng = rand::thread_rng();

        let pf_time = start_timer!(|| "proof gen");
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[proof_circuit], &[&[&instance]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(pf_time);

        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verify_time = start_timer!(|| "verify");
        assert!(verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[&instance]], &mut transcript)
        .is_ok());
        end_timer!(verify_time);

        Ok(())
    }
}
