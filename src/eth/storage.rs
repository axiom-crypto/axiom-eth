use ark_std::{end_timer, start_timer};
use eth_types::Field;
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
use hex::FromHex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{cast::ToPrimitive, Num};
use plonk_verifier::system::halo2::aggregation::gen_srs;
use plonk_verifier::system::halo2::aggregation::TargetCircuit;
use rand_core::block;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::{cmp::max, fs};

#[cfg(feature = "input_gen")]
use crate::input_gen::{get_block_acct_storage_input, GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL};
use crate::{
    eth::{EthChip, EthConfigParams, Network, NETWORK},
    input_gen::EthBlockAcctStorageInput,
    keccak::{print_bytes, KeccakChip},
    mpt::mpt::{AssignedBytes, MPTChip, MPTFixedKeyProof},
    rlp::rlc::{RlcFixedTrace, RlcTrace},
    rlp::rlp::{RlpArrayChip, RlpArrayTrace},
};

#[derive(Clone, Debug, Default)]
pub struct EthSingleAcctStorageProof<F> {
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

    pub pub_hash: F,

    pub k: usize, // for testing convenience, not used by circuit itself
    pub _marker: PhantomData<F>,
}

impl<F: Field> From<EthBlockAcctStorageInput> for EthSingleAcctStorageProof<F> {
    fn from(input: EthBlockAcctStorageInput) -> Self {
        Self {
            block_hash: (
                input.block_hash.0.map(|x| biguint_to_fe(&x)),
                input.block_hash.1.map(|x| biguint_to_fe(&x)),
            ),
            addr: input.addr.map(|x| biguint_to_fe(&x)),
            slot: (
                input.slot.0.map(|x| biguint_to_fe(&x)),
                input.slot.1.map(|x| biguint_to_fe(&x)),
            ),
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
            pub_hash: biguint_to_fe(&input.pub_hash),
            _marker: PhantomData,
            k: 21,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthAssignedBlockAcctStorageInput<F: Field> {
    pub block_hash: (AssignedValue<F>, AssignedValue<F>), // H256 as (u128, u128)
    pub address: AssignedValue<F>,                        // U160
    pub slot: (AssignedValue<F>, AssignedValue<F>),       // U256 as (u128, u128)
    pub block_header: AssignedBytes<F>,
    pub acct_pf: MPTFixedKeyProof<F>,
    pub storage_pf: MPTFixedKeyProof<F>,
}

impl<F: Field> EthSingleAcctStorageProof<F> {
    #[cfg(feature = "input_gen")]
    pub fn from_provider(
        provider: &Provider<Http>,
        block_number: u64,
        address: Address,
        slot: U256,
        acct_pf_max_depth: usize,
        storage_pf_max_depth: usize,
        k: u32,
    ) -> Self {
        let input = get_block_acct_storage_input(
            provider,
            block_number,
            address,
            slot,
            acct_pf_max_depth,
            storage_pf_max_depth,
        );
        let mut circuit: Self = input.into();
        circuit.k = k as usize;
        circuit
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![self.pub_hash]]
    }

    pub fn assign_inputs(
        &self,
        ctx: &mut Context<'_, F>,
        config: &<Self as Circuit<F>>::Config,
    ) -> Result<EthAssignedBlockAcctStorageInput<F>, Error> {
        let block_hash0 = config
            .mpt
            .rlp
            .range
            .gate
            .assign_witnesses(
                ctx,
                vec![self.block_hash.0.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
            )?
            .pop()
            .unwrap();
        let block_hash1 = config
            .mpt
            .rlp
            .range
            .gate
            .assign_witnesses(
                ctx,
                vec![self.block_hash.1.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
            )?
            .pop()
            .unwrap();
        let block_hash = (block_hash0, block_hash1);

        let address = config
            .mpt
            .rlp
            .range
            .gate
            .assign_witnesses(
                ctx,
                vec![self.addr.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
            )?
            .pop()
            .unwrap();

        let slot0 = config
            .mpt
            .rlp
            .range
            .gate
            .assign_witnesses(
                ctx,
                vec![self.slot.0.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
            )?
            .pop()
            .unwrap();
        let slot1 = config
            .mpt
            .rlp
            .range
            .gate
            .assign_witnesses(
                ctx,
                vec![self.slot.1.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
            )?
            .pop()
            .unwrap();
        let slot = (slot0, slot1);

        let block_header = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.block_header
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;

        let acct_key_bytes = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.acct_pf_key_bytes
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let acct_value_bytes = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.acct_pf_value_bytes
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let acct_value_byte_len = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            vec![self.acct_pf_value_byte_len.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
        )?;
        let acct_root_hash_bytes = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.acct_pf_root_hash_bytes
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let acct_leaf_bytes = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.acct_pf_leaf_bytes
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let mut acct_nodes = Vec::new();
        for node in self.acct_pf_nodes.iter() {
            let next = config.mpt.rlp.range.gate.assign_witnesses(
                ctx,
                node.iter()
                    .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                    .collect(),
            )?;
            acct_nodes.push(next);
        }
        let acct_node_types = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.acct_pf_node_types
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
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
                    .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                    .collect(),
            )?;
            acct_key_frag_hexs.push(next);
        }
        let acct_key_frag_is_odd = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.acct_pf_key_frag_is_odd
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let acct_key_frag_byte_len = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.acct_pf_key_frag_byte_len
                .iter()
                .map(|x| x.map(|v| Value::known(v)).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let acct_pf = MPTFixedKeyProof {
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
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let storage_value_bytes = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.storage_pf_value_bytes
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
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
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let storage_leaf_bytes = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.storage_pf_leaf_bytes
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let mut storage_nodes = Vec::new();
        for node in self.storage_pf_nodes.iter() {
            let next = config.mpt.rlp.range.gate.assign_witnesses(
                ctx,
                node.iter()
                    .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                    .collect(),
            )?;
            storage_nodes.push(next);
        }
        let storage_node_types = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.storage_pf_node_types
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let storage_depth = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            vec![self.storage_pf_depth.map(|x| Value::known(x)).unwrap_or(Value::unknown())],
        )?;
        let mut storage_key_frag_hexs = Vec::new();
        for frag in self.storage_pf_key_frag_hexs.iter() {
            let next = config.mpt.rlp.range.gate.assign_witnesses(
                ctx,
                frag.iter()
                    .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                    .collect(),
            )?;
            storage_key_frag_hexs.push(next);
        }
        let storage_key_frag_is_odd = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.storage_pf_key_frag_is_odd
                .iter()
                .map(|x| x.map(|v| Value::known(F::from(v as u64))).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let storage_key_frag_byte_len = config.mpt.rlp.range.gate.assign_witnesses(
            ctx,
            self.storage_pf_key_frag_byte_len
                .iter()
                .map(|x| x.map(|v| Value::known(v)).unwrap_or(Value::unknown()))
                .collect(),
        )?;
        let storage_pf = MPTFixedKeyProof {
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
        Ok(EthAssignedBlockAcctStorageInput {
            block_hash,
            address,
            slot,
            block_header,
            acct_pf,
            storage_pf,
        })
    }
}

impl<F: Field> Circuit<F> for EthSingleAcctStorageProof<F> {
    type Config = EthChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params_str = fs::read_to_string("configs/storage_1.config").unwrap();
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
        // dbg!(&gamma);

        let mut first_pass = true; // using simple floor planner
        let mut phase = 0u8;
        let mut block_acct_storage = None;
        layouter.assign_region(
            || "Eth block acct storage test",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                phase = phase + 1u8;

                dbg!(phase);
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![
                            ("default".to_string(), config.mpt.rlp.range.gate.num_advice),
                            ("rlc".to_string(), config.mpt.rlp.rlc.basic_chips.len()),
                            ("keccak_rot".to_string(), config.mpt.keccak.rotation.len()),
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

                let EthAssignedBlockAcctStorageInput {
                    block_hash,
                    address,
                    slot,
                    block_header,
                    acct_pf,
                    storage_pf,
                } = self.assign_inputs(ctx, &config)?;

                block_acct_storage = Some(
                    config
                        .parse_block_acct_storage_pf_min(
                            ctx,
                            &config.mpt.rlp.range,
                            &block_hash,
                            &address,
                            &slot,
                            &block_header,
                            &acct_pf,
                            &storage_pf,
                        )
                        .unwrap(),
                );

                let stats = config.mpt.rlp.range.finalize(ctx)?;
                #[cfg(feature = "display")]
                {
                    println!("stats (fixed rows, total fixed, lookups) {:?}", stats);
                    println!("ctx.rows rlc {:?}", ctx.advice_rows["rlc"]);
                    println!("ctx.rows default {:?}", ctx.advice_rows["default"]);
                    println!(
                        "ctx.advice_rows sums: {:#?}",
                        ctx.advice_rows
                            .iter()
                            .map(|(key, val)| (key, val.iter().sum::<usize>()))
                            .collect::<Vec<_>>()
                    );
                    println!("{:#?}", ctx.op_count);
                    let total_rlc = ctx.advice_rows["rlc"].iter().sum::<usize>();
                    println!("optimal rlc #: {}", (total_rlc + (1 << self.k) - 1) >> self.k);
                    let total_default = ctx.advice_rows["default"].iter().sum::<usize>();
                    println!(
                        "optimal default #: {}",
                        (total_default + (1 << self.k) - 1) >> self.k
                    );
                    println!(
                        "optimal lookup #: {}",
                        (ctx.cells_to_lookup.len() + (1 << self.k) - 1) >> self.k
                    );
                    println!("optimal fixed #: {}", (stats.1 + (1 << self.k) - 1) >> self.k);
                    let total_rot = ctx.advice_rows["keccak_rot"].iter().sum::<usize>();
                    println!("optimal rot #: {}", (total_rot + (1 << self.k) - 1) >> self.k);
                    let total_xor = ctx.advice_rows["keccak_xor"].iter().sum::<usize>();
                    println!("optimal xor #: {}", (total_xor + (1 << self.k) - 1) >> self.k,);
                    let total_xorandn = ctx.advice_rows["keccak_xorandn"].iter().sum::<usize>();
                    println!(
                        "Optimal xorandn #: {}",
                        (total_xorandn + (1 << self.k) - 1) >> self.k
                    );
                }

                Ok(())
            },
        )?;
        end_timer!(witness_time);
        // single pub_hash as public instance
        layouter.constrain_instance(block_acct_storage.unwrap().pub_hash.cell(), config.instance, 0)
    }
}

impl TargetCircuit for EthSingleAcctStorageProof<Fr> {
    const N_PROOFS: usize = 1;
    const NAME: &'static str = "storage_1";

    type Circuit = Self;
}

#[cfg(feature = "input_gen")]
#[cfg(test)]
mod tests {
    use std::io::{BufRead, Write};

    use halo2_proofs::poly::commitment::Params;

    use super::*;
    #[test]
    pub fn test_mock_one_eth_block_acct_storage() -> Result<(), Box<dyn std::error::Error>> {
        let mut folder = std::path::PathBuf::new();
        folder.push("configs/storage_1.config");
        let file = std::fs::File::open(folder.as_path())?;
        let config: EthConfigParams = serde_json::from_reader(file).unwrap();
        let k = config.degree;
        let provider_url = match NETWORK {
            Network::Mainnet => MAINNET_PROVIDER_URL,
            Network::Goerli => GOERLI_PROVIDER_URL,
        };
        let infura_id =
            fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider =
            Provider::<Http>::try_from(format!("{}{}", provider_url, infura_id).as_str())
                .expect("could not instantiate HTTP Provider");

        let input = match NETWORK {
            Network::Mainnet => {
                let addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>()?;
                get_block_acct_storage_input(&provider, 0xef0000, addr, U256::from(2), 8, 8)
            }
            Network::Goerli => {
                let addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>()?;
                get_block_acct_storage_input(&provider, 0x713d54, addr, U256::from(2), 8, 8)
            }
        };

        let mut circuit: EthSingleAcctStorageProof<Fr> = input.into();
        circuit.k = k as usize;
        let prover_try = MockProver::run(k, &circuit, circuit.instances());
        let prover = prover_try.unwrap();
        prover.assert_satisfied();
        assert_eq!(prover.verify(), Ok(()));

        Ok(())
    }

    #[test]
    pub fn bench_one_eth_block_acct_storage() -> Result<(), Box<dyn std::error::Error>> {
        let provider_url = match NETWORK {
            Network::Mainnet => MAINNET_PROVIDER_URL,
            Network::Goerli => GOERLI_PROVIDER_URL,
        };
        let infura_id =
            fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider =
            Provider::<Http>::try_from(format!("{}{}", provider_url, infura_id).as_str())
                .expect("could not instantiate HTTP Provider");

        let input = match NETWORK {
            Network::Mainnet => {
                let addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>()?;
                get_block_acct_storage_input(&provider, 0xef0000, addr, U256::from(2), 8, 8)
            }
            Network::Goerli => {
                let addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>()?;
                get_block_acct_storage_input(&provider, 0x713d54, addr, U256::from(2), 8, 8)
            }
        };

        let mut circuit: EthSingleAcctStorageProof<Fr> = input.into();

        let mut folder = std::path::PathBuf::new();
        folder.push("configs/bench_storage_1.config");
        let bench_params_file = std::fs::File::open(folder.as_path())?;
        folder.pop();
        folder.pop();

        folder.push("data");
        folder.push("storage_1_bench.csv");
        let mut fs_results = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        write!(fs_results, "degree,total_advice,num_rlc_chip,num_default,num_lookup,num_fixed,num_keccak,num_xor,num_xorandn,proof_time,proof_size,verify_time\n")?;

        let mut params_folder = std::path::PathBuf::new();
        params_folder.push("./params");
        if !params_folder.is_dir() {
            std::fs::create_dir(params_folder.as_path())?;
        }

        let bench_params_reader = std::io::BufReader::new(bench_params_file);
        for line in bench_params_reader.lines() {
            let bench_params: EthConfigParams =
                serde_json::from_str(line.unwrap().as_str()).unwrap();
            println!(
                "---------------------- degree = {} ------------------------------",
                bench_params.degree
            );
            let mut rng = rand::thread_rng();

            {
                folder.pop();
                folder.push("configs/storage_1.config");
                let mut f = std::fs::File::create(folder.as_path())?;
                write!(f, "{}", serde_json::to_string(&bench_params).unwrap())?;
                folder.pop();
                folder.pop();
                folder.push("data");
            }
            let params_time = start_timer!(|| "Params construction");
            let params = {
                params_folder.push(format!("kzg_bn254_{}.srs", bench_params.degree));
                let fd = std::fs::File::open(params_folder.as_path());
                let params = if let Ok(mut f) = fd {
                    println!("Found existing params file. Reading params...");
                    ParamsKZG::<Bn256>::read(&mut f).unwrap()
                } else {
                    println!("Creating new params file...");
                    let mut f = std::fs::File::create(params_folder.as_path())?;
                    let params = ParamsKZG::<Bn256>::setup(bench_params.degree, &mut rng);
                    params.write(&mut f).unwrap();
                    params
                };
                params_folder.pop();
                params
            };
            end_timer!(params_time);

            circuit.k = bench_params.degree as usize;

            let vk_time = start_timer!(|| "Generating vkey");
            let vk = keygen_vk(&params, &circuit)?;
            end_timer!(vk_time);

            let pk_time = start_timer!(|| "Generating pkey");
            let pk = keygen_pk(&params, vk, &circuit)?;
            end_timer!(pk_time);

            let proof_circuit = circuit.clone();
            let instances = proof_circuit.instances();
            let instances = instances.iter().map(|instance| instance.as_slice()).collect_vec();
            // create a proof
            let proof_time = start_timer!(|| "SHPLONK");
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                _,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
                _,
            >(&params, &pk, &[proof_circuit], &[&instances], rng, &mut transcript)?;
            let proof = transcript.finalize();
            end_timer!(proof_time);

            let verify_time = start_timer!(|| "Verify time");
            let verifier_params = params.verifier_params();
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            match verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                SingleStrategy<'_, Bn256>,
            >(
                verifier_params, pk.get_vk(), strategy, &[&instances], &mut transcript
            ) {
                Ok(_) => {}
                Err(e) => {
                    println!("{:#?}", e);
                    panic!()
                }
            }
            end_timer!(verify_time);

            let proof_size = {
                folder.push("storage_1_proof.data");
                let mut fd = std::fs::File::create(folder.as_path()).unwrap();
                folder.pop();
                fd.write_all(&proof).unwrap();
                fd.metadata().unwrap().len()
            };

            write!(
                fs_results,
                "{},{},{},{},{},{},{},{}, {}, {:?},{},{:?}\n",
                bench_params.degree,
                bench_params.num_basic_chips * 2
                    + bench_params.num_advice[0]
                    + bench_params.num_lookup_advice[0]
                    + bench_params.keccak_num_rot * 3
                    + bench_params.keccak_num_xor * 3
                    + bench_params.keccak_num_xorandn * 4,
                bench_params.num_basic_chips,
                bench_params.num_advice[0],
                bench_params.num_lookup_advice[0],
                bench_params.num_fixed,
                bench_params.keccak_num_rot,
                bench_params.keccak_num_xor,
                bench_params.keccak_num_xorandn,
                proof_time.time.elapsed(),
                proof_size,
                verify_time.time.elapsed()
            )?;
        }

        Ok(())
    }

    #[cfg(feature = "aggregation")]
    #[test]
    pub fn evm_one_eth_block_acct_storage() {
        #[cfg(feature = "evm")]
        use crate::eth::aggregation::evm::evm_verify;
        use crate::eth::aggregation::{
            evm::{gen_aggregation_evm_verifier, gen_evm_verifier, gen_proof},
            load_aggregation_circuit_degree,
        };
        use plonk_verifier::system::halo2::{
            aggregation::{create_snark_shplonk, gen_pk, AggregationCircuit},
            transcript::evm::EvmTranscript,
        };

        let file = std::fs::File::open("configs/storage_1.config").unwrap();
        let config: EthConfigParams = serde_json::from_reader(file).unwrap();
        let k = config.degree;

        let provider_url = match NETWORK {
            Network::Mainnet => MAINNET_PROVIDER_URL,
            Network::Goerli => GOERLI_PROVIDER_URL,
        };
        let infura_id =
            fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider =
            Provider::<Http>::try_from(format!("{}{}", provider_url, infura_id).as_str())
                .expect("could not instantiate HTTP Provider");

        let input = match NETWORK {
            Network::Mainnet => {
                let addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>().unwrap();
                get_block_acct_storage_input(&provider, 0xef0000, addr, U256::from(2), 8, 8)
            }
            Network::Goerli => {
                let addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>().unwrap();
                get_block_acct_storage_input(&provider, 0x713d54, addr, U256::from(2), 8, 8)
            }
        };

        let mut circuit: EthSingleAcctStorageProof<Fr> = input.into();
        circuit.k = k as usize;
        let instances = circuit.instances();

        let params = gen_srs(k);
        let snark = create_snark_shplonk::<EthSingleAcctStorageProof<Fr>>(
            &params,
            vec![circuit],
            vec![instances],
            None,
        );
        let snarks = vec![snark];

        std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");
        let k = load_aggregation_circuit_degree();
        let params = gen_srs(k);
        let agg_circuit = AggregationCircuit::new(&params, snarks, true);
        let pk = gen_pk(&params, &agg_circuit, "storage_agg_circuit");

        let deployment_code = gen_aggregation_evm_verifier(
            &params,
            pk.get_vk(),
            agg_circuit.num_instance(),
            AggregationCircuit::accumulator_indices(),
        );
        fs::write("./data/storage_verifier_bytecode.dat", hex::encode(&deployment_code)).unwrap();

        let proof_time = start_timer!(|| "create agg_circuit proof");
        let proof = gen_proof::<
            _,
            _,
            EvmTranscript<G1Affine, _, _, _>,
            EvmTranscript<G1Affine, _, _, _>,
        >(&params, &pk, agg_circuit.clone(), agg_circuit.instances());
        end_timer!(proof_time);

        #[cfg(feature = "evm")]
        evm_verify(deployment_code, agg_circuit.instances(), proof);
    }
}
