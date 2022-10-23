use ark_std::{end_timer, start_timer};
use eth_types::H256;
use ethers_core::types::{
    Address, Block, BlockId, BlockId::Number, BlockNumber, EIP1186ProofResponse, StorageProof, U256,
};
use ethers_providers::{Http, Middleware, Provider};
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::{biguint_to_fe, fe_to_biguint},
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
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
use plonk_verifier::system::halo2::aggregation::gen_srs;
use std::marker::PhantomData;

use eth_types::Field;
use hex::FromHex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{cast::ToPrimitive, Num};
use rand_core::block;
use serde::{Deserialize, Serialize};
use std::{cmp::max, fs};

use crate::input_gen::{get_block_acct_storage_input, GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL};
use crate::{
    eth::{EthChip, EthConfigParams, Network, NETWORK},
    keccak::{print_bytes, KeccakChip},
    mpt::mpt::{AssignedBytes, MPTChip, MPTFixedKeyProof},
    rlp::rlc::{RlcFixedTrace, RlcTrace},
    rlp::rlp::{RlpArrayChip, RlpArrayTrace},
};

#[derive(Clone, Debug, Default)]
pub struct EthBlockAcctStorageTestCircuit<F> {
    pub block_hash: (Option<F>, Option<F>),
    pub addr: Option<F>,
    pub slot: (Option<F>, Option<F>),
    pub block_header: Vec<Option<u8>>,

    pub acct_pf_key_bytes: Vec<Option<u8>>,
    pub acct_pf_value_bytes: Vec<Option<u8>>,
    pub acct_pf_value_byte_len: Option<F>,
    pub acct_pf_root_hash_bytes: Vec<Option<u8>>,
    pub acct_pf_leaf_bytes: Vec<Option<u8>>,
    pub acct_pf_nodes: Vec<Vec<Option<u8>>>,
    pub acct_pf_node_types: Vec<Option<u8>>,
    pub acct_pf_depth: Option<F>,
    pub acct_pf_key_frag_hexs: Vec<Vec<Option<u8>>>,
    pub acct_pf_key_frag_is_odd: Vec<Option<u8>>,
    pub acct_pf_key_frag_byte_len: Vec<Option<F>>,
    pub acct_pf_key_byte_len: usize,
    pub acct_pf_value_max_byte_len: usize,
    pub acct_pf_max_depth: usize,

    pub storage_pf_key_bytes: Vec<Option<u8>>,
    pub storage_pf_value_bytes: Vec<Option<u8>>,
    pub storage_pf_value_byte_len: Option<F>,
    pub storage_pf_root_hash_bytes: Vec<Option<u8>>,
    pub storage_pf_leaf_bytes: Vec<Option<u8>>,
    pub storage_pf_nodes: Vec<Vec<Option<u8>>>,
    pub storage_pf_node_types: Vec<Option<u8>>,
    pub storage_pf_depth: Option<F>,
    pub storage_pf_key_frag_hexs: Vec<Vec<Option<u8>>>,
    pub storage_pf_key_frag_is_odd: Vec<Option<u8>>,
    pub storage_pf_key_frag_byte_len: Vec<Option<F>>,
    pub storage_pf_key_byte_len: usize,
    pub storage_pf_value_max_byte_len: usize,
    pub storage_pf_max_depth: usize,

    pub _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for EthBlockAcctStorageTestCircuit<F> {
    type Config = EthChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params_str = fs::read_to_string("configs/block_header.config").unwrap();
        let params: EthConfigParams = serde_json::from_str(params_str.as_str()).unwrap();

        EthChip::configure(meta, "gamma".to_string(), "rlc".to_string(), params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let witness_time = start_timer!(|| "witness gen");
        config.mpt.rlp.range.load_lookup_table(&mut layouter)?;
        config.mpt.keccak.load_lookup_table(&mut layouter)?;
        let gamma = layouter.get_challenge(config.mpt.rlp.rlc.gamma);
        println!("gamma {:?}", gamma);

        let using_simple_floor_planner = true;
        let mut first_pass = true;
        let mut phase = 0u8;
        let mut block_acct_storage = None;
        layouter.assign_region(
            || "Eth block acct storage test",
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
                            ("default".to_string(), config.mpt.rlp.range.gate.num_advice),
                            ("rlc".to_string(), config.mpt.rlp.rlc.basic_chips.len()),
                            ("keccak".to_string(), config.mpt.keccak.rotation.len()),
                            ("keccak_xor".to_string(), config.mpt.keccak.xor_values.len() / 3),
                            (
                                "keccak_xorandn".to_string(),
                                config.mpt.keccak.xorandn_values.len() / 4,
                            ),
                        ],
                    },
                );
                let ctx = &mut aux;
                ctx.challenge.insert("gamma".to_string(), gamma);

                let block_hash0 = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self.block_hash.0.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
                )?;
                let block_hash1 = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self.block_hash.1.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
                )?;
                let block_hash_assigned = (block_hash0[0].clone(), block_hash1[0].clone());

                let addr_assigned = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self.addr.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
                )?;

                let slot0 = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self.slot.0.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
                )?;
                let slot1 = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self.slot.1.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
                )?;
                let slot_assigned = (slot0[0].clone(), slot1[0].clone());

                let block_header_assigned = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.block_header
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;

                let acct_key_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.acct_pf_key_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let acct_value_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.acct_pf_value_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let acct_value_byte_len = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self
                        .acct_pf_value_byte_len
                        .map(|x| Value::known(x))
                        .unwrap_or(Value::unknown())],
                )?;
                let acct_root_hash_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.acct_pf_root_hash_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let acct_leaf_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.acct_pf_leaf_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let mut acct_nodes = Vec::new();
                for node in self.acct_pf_nodes.iter() {
                    let next = config.mpt.rlp.range.gate.assign_witnesses(
                        ctx,
                        node.iter()
                            .map(|x| {
                                x.map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown())
                            })
                            .collect(),
                    )?;
                    acct_nodes.push(next);
                }
                let acct_node_types = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.acct_pf_node_types
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let acct_depth = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self.acct_pf_depth.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
                )?;
                let mut acct_key_frag_hexs = Vec::new();
                for frag in self.acct_pf_key_frag_hexs.iter() {
                    let next = config.mpt.rlp.range.gate.assign_witnesses(
                        ctx,
                        frag.iter()
                            .map(|x| {
                                x.map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown())
                            })
                            .collect(),
                    )?;
                    acct_key_frag_hexs.push(next);
                }
                let acct_key_frag_is_odd = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.acct_pf_key_frag_is_odd
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let acct_key_frag_byte_len = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.acct_pf_key_frag_byte_len
                        .iter()
                        .map(|x| x.map(|v| Value::known(v)).unwrap_or(Value::unknown()))
                        .collect(),
                )?;
                let acct_pf_assigned = MPTFixedKeyProof {
                    key_bytes: acct_key_bytes,
                    value_bytes: acct_value_bytes,
                    value_byte_len: acct_value_byte_len[0].clone(),
                    root_hash_bytes: acct_root_hash_bytes,

                    leaf_bytes: acct_leaf_bytes,
                    nodes: acct_nodes,
                    node_types: acct_node_types,
                    depth: acct_depth[0].clone(),

                    key_frag_hexs: acct_key_frag_hexs,
                    key_frag_is_odd: acct_key_frag_is_odd,
                    key_frag_byte_len: acct_key_frag_byte_len,

                    key_byte_len: self.acct_pf_key_byte_len,
                    value_max_byte_len: self.acct_pf_value_max_byte_len,
                    max_depth: self.acct_pf_max_depth,
                };

                let storage_key_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.storage_pf_key_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let storage_value_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.storage_pf_value_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let storage_value_byte_len = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self
                        .storage_pf_value_byte_len
                        .map(|x| Value::known(x))
                        .unwrap_or(Value::unknown())],
                )?;
                let storage_root_hash_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.storage_pf_root_hash_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let storage_leaf_bytes = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.storage_pf_leaf_bytes
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let mut storage_nodes = Vec::new();
                for node in self.storage_pf_nodes.iter() {
                    let next = config.mpt.rlp.range.gate.assign_witnesses(
                        ctx,
                        node.iter()
                            .map(|x| {
                                x.map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown())
                            })
                            .collect(),
                    )?;
                    storage_nodes.push(next);
                }
                let storage_node_types = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.storage_pf_node_types
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let storage_depth = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    vec![self
                        .storage_pf_depth
                        .map(|x| Value::known(x))
                        .unwrap_or(Value::unknown())],
                )?;
                let mut storage_key_frag_hexs = Vec::new();
                for frag in self.storage_pf_key_frag_hexs.iter() {
                    let next = config.mpt.rlp.range.gate.assign_witnesses(
                        ctx,
                        frag.iter()
                            .map(|x| {
                                x.map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown())
                            })
                            .collect(),
                    )?;
                    storage_key_frag_hexs.push(next);
                }
                let storage_key_frag_is_odd = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.storage_pf_key_frag_is_odd
                        .iter()
                        .map(|x| {
                            x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown())
                        })
                        .collect(),
                )?;
                let storage_key_frag_byte_len = config.mpt.rlp.range.gate.assign_witnesses(
                    ctx,
                    self.storage_pf_key_frag_byte_len
                        .iter()
                        .map(|x| x.map(|v| Value::known(v)).unwrap_or(Value::unknown()))
                        .collect(),
                )?;
                let storage_pf_assigned = MPTFixedKeyProof {
                    key_bytes: storage_key_bytes,
                    value_bytes: storage_value_bytes,
                    value_byte_len: storage_value_byte_len[0].clone(),
                    root_hash_bytes: storage_root_hash_bytes,

                    leaf_bytes: storage_leaf_bytes,
                    nodes: storage_nodes,
                    node_types: storage_node_types,
                    depth: storage_depth[0].clone(),

                    key_frag_hexs: storage_key_frag_hexs,
                    key_frag_is_odd: storage_key_frag_is_odd,
                    key_frag_byte_len: storage_key_frag_byte_len,

                    key_byte_len: self.storage_pf_key_byte_len,
                    value_max_byte_len: self.storage_pf_value_max_byte_len,
                    max_depth: self.storage_pf_max_depth,
                };

                block_acct_storage = Some(
                    config
                        .parse_block_acct_storage_pf_min(
                            ctx,
                            &config.mpt.rlp.range,
                            &block_hash_assigned,
                            &addr_assigned[0],
                            &slot_assigned,
                            &block_header_assigned,
                            &acct_pf_assigned,
                            &storage_pf_assigned,
                        )
                        .unwrap(),
                );

                let stats = config.mpt.rlp.range.finalize(ctx)?;
                #[cfg(feature = "display")]
                {
                    println!("stats (fixed rows, total fixed, lookups) {:?}", stats);
                    println!("ctx.rows rlc {:?}", ctx.advice_rows["rlc"]);
                    println!("ctx.rows default {:?}", ctx.advice_rows["default"]);
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
        end_timer!(witness_time);
        Ok(())
    }
}

#[test]
pub fn test_mock_one_eth_block_acct_storage() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(NETWORK, Network::Mainnet);
    let k = 21;
    let provider_url = match NETWORK {
        Network::Mainnet => MAINNET_PROVIDER_URL,
        Network::Goerli => GOERLI_PROVIDER_URL,
    };
    let infura_id = fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
    let provider = Provider::<Http>::try_from(format!("{}{}", provider_url, infura_id).as_str())
        .expect("could not instantiate HTTP Provider");

    let addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>()?;
    let input = get_block_acct_storage_input(&provider, 0xef0000, addr, U256::from(2), 8, 8);

    let circuit = EthBlockAcctStorageTestCircuit::<Fr> {
        block_hash: (
            input.block_hash.0.map(|x| biguint_to_fe(&x)),
            input.block_hash.1.map(|x| biguint_to_fe(&x)),
        ),
        addr: input.addr.map(|x| biguint_to_fe(&x)),
        slot: (input.slot.0.map(|x| biguint_to_fe(&x)), input.slot.1.map(|x| biguint_to_fe(&x))),
        block_header: input.block_header,
        acct_pf_key_bytes: input.acct_pf_key_bytes,
        acct_pf_value_bytes: input.acct_pf_value_bytes,
        acct_pf_value_byte_len: input.acct_pf_value_byte_len.map(|x| biguint_to_fe(&x)),
        acct_pf_root_hash_bytes: input.acct_pf_root_hash_bytes,
        acct_pf_leaf_bytes: input.acct_pf_leaf_bytes,
        acct_pf_nodes: input.acct_pf_nodes,
        acct_pf_node_types: input.acct_pf_node_types,
        acct_pf_depth: input.acct_pf_depth.map(|x| biguint_to_fe(&x)),
        acct_pf_key_frag_hexs: input.acct_pf_key_frag_hexs,
        acct_pf_key_frag_is_odd: input.acct_pf_key_frag_is_odd,
        acct_pf_key_frag_byte_len: input
            .acct_pf_key_frag_byte_len
            .iter()
            .map(|x| x.clone().map(|y| biguint_to_fe(&y)))
            .collect(),
        acct_pf_key_byte_len: input.acct_pf_key_byte_len,
        acct_pf_value_max_byte_len: input.acct_pf_value_max_byte_len,
        acct_pf_max_depth: input.acct_pf_max_depth,
        storage_pf_key_bytes: input.storage_pf_key_bytes,
        storage_pf_value_bytes: input.storage_pf_value_bytes,
        storage_pf_value_byte_len: input.storage_pf_value_byte_len.map(|x| biguint_to_fe(&x)),
        storage_pf_root_hash_bytes: input.storage_pf_root_hash_bytes,
        storage_pf_leaf_bytes: input.storage_pf_leaf_bytes,
        storage_pf_nodes: input.storage_pf_nodes,
        storage_pf_node_types: input.storage_pf_node_types,
        storage_pf_depth: input.storage_pf_depth.map(|x| biguint_to_fe(&x)),
        storage_pf_key_frag_hexs: input.storage_pf_key_frag_hexs,
        storage_pf_key_frag_is_odd: input.storage_pf_key_frag_is_odd,
        storage_pf_key_frag_byte_len: input
            .storage_pf_key_frag_byte_len
            .iter()
            .map(|x| x.clone().map(|y| biguint_to_fe(&y)))
            .collect(),
        storage_pf_key_byte_len: input.storage_pf_key_byte_len,
        storage_pf_value_max_byte_len: input.storage_pf_value_max_byte_len,
        storage_pf_max_depth: input.storage_pf_max_depth,
        _marker: PhantomData,
    };
    let prover_try = MockProver::run(k, &circuit, vec![vec![]]);
    let prover = prover_try.unwrap();
    prover.assert_satisfied();
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}
