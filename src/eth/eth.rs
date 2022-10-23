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
use num_bigint::{BigUint};
use num_traits::{cast::ToPrimitive, Num};
use rand_core::block;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::{cmp::max, fs};

use eth_types::Field;

use crate::{
    keccak::{print_bytes, KeccakChip},
    mpt::mpt::{AssignedBytes, MPTChip, MPTFixedKeyProof},
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

#[derive(Clone, Debug)]
pub struct EthAccountTrace<F: Field> {
    nonce_trace: RlcTrace<F>,
    balance_trace: RlcTrace<F>,
    storage_root_trace: RlcTrace<F>,
    code_hash_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthStorageTrace<F: Field> {
    value_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthAccountStorageTrace<F: Field> {
    acct_trace: EthAccountTrace<F>,
    storage_trace: EthStorageTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTrace<F: Field> {
    block_trace: EthBlockHeaderTrace<F>,
    acct_trace: EthAccountTrace<F>,
    storage_trace: EthStorageTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageMinTrace<F: Field> {
    block_trace: EthBlockHeaderTrace<F>,
    acct_trace: EthAccountTrace<F>,
    storage_trace: EthStorageTrace<F>,
    pub_hash: AssignedValue<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Strategy {
    Simple,
    SimplePlus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthConfigParams {
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
pub struct EthChip<F: Field> {
    pub mpt: MPTChip<F>,
    // the instance column will contain the latest blockhash and the merkle root of all the blockhashes
    pub instance: Column<Instance>,
}

impl<F: Field> EthChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        challenge_id: String,
        context_id: String,
        params: EthConfigParams,
    ) -> Self {
	let mpt = MPTChip::configure(meta, challenge_id, context_id, params);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self { mpt, instance }
    }

    pub fn decompose_eth_block_header(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        block_header: &Vec<AssignedValue<F>>,
    ) -> Result<EthBlockHeaderTrace<F>, Error> {
        let max_len = 1 + 2 + 520 + MAINNET_EXTRA_DATA_RLP_MAX_BYTES;
        let max_field_lens = vec![
            33, 33, 21, 33, 33, 33, 259, 8, 4, 5, 5, 5, 
            MAINNET_EXTRA_DATA_RLP_MAX_BYTES, 33, 9, 6,
        ];
        let num_fields = 16;
        let rlp_array_trace = self.mpt.rlp.decompose_rlp_array(
            ctx,
            range,
            block_header,
            max_field_lens,
            max_len,
            num_fields,
        )?;
        let (hash_bytes, hash_hexes) = self.mpt.keccak.keccak_bytes_var_len(
            ctx,
            range,
            &block_header,
            rlp_array_trace.array_trace.rlc_len.clone(),
            479,
            max_len,
        )?;
        let block_hash = self.mpt.rlp.rlc.compute_rlc_fixed_len(ctx, range, &hash_bytes, 32)?;

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

    pub fn parse_acct_pf(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	state_root: &AssignedBytes<F>,
	addr: &AssignedBytes<F>,
	proof: &MPTFixedKeyProof<F>,
    ) -> Result<EthAccountTrace<F>, Error> {
	assert_eq!(32, proof.key_byte_len);
	
	// check key is keccak(addr)
	let len = range.gate.assign_region_smart(
            ctx, vec![Constant(F::from(20))], vec![], vec![], vec![],
        )?;
	let (hash_bytes, hash_hexes) = self.mpt.keccak.keccak_bytes_var_len(
	    ctx, range, addr, len[0].clone(), 19, 20
	)?;
	
	for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.clone()) {
	    ctx.region.constrain_equal(hash.cell(), key.cell())?;
	}

	// check MPT root is state root
	for (pf_root, root) in proof.root_hash_bytes.iter().zip(state_root.clone()) {
	    ctx.region.constrain_equal(pf_root.cell(), root.cell())?;
	}
	
	// Check MPT inclusion for:
	// keccak(addr) => RLP([nonce, balance, storage_root, code_hash])
	self.mpt.parse_mpt_inclusion_fixed_key(
	    ctx, range, proof, 32, 114, proof.max_depth
	)?;

	// parse value
	let array_trace = self.mpt.rlp.decompose_rlp_array(
	    ctx,
	    range,
	    &proof.value_bytes,
	    vec![33, 13, 33, 33],
	    114,
	    4
	)?;

	let eth_account_trace = EthAccountTrace {
	    nonce_trace: array_trace.field_traces[0].clone(),
	    balance_trace: array_trace.field_traces[1].clone(),
	    storage_root_trace: array_trace.field_traces[2].clone(),
	    code_hash_trace: array_trace.field_traces[3].clone(),
	};
	Ok(eth_account_trace)
    }

    pub fn parse_storage_pf(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	storage_root: &AssignedBytes<F>,
	slot: &AssignedBytes<F>,
	proof: &MPTFixedKeyProof<F>,
    ) -> Result<EthStorageTrace<F>, Error> {
	assert_eq!(32, proof.key_byte_len);

	// check key is keccak(slot)
	let len = range.gate.assign_region_smart(
            ctx, vec![Constant(F::from(32))], vec![], vec![], vec![],
        )?;
	let (hash_bytes, hash_hexes) = self.mpt.keccak.keccak_bytes_var_len(
	    ctx, range, slot, len[0].clone(), 31, 32
	)?;
	
	for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.clone()) {
	    ctx.region.constrain_equal(hash.cell(), key.cell())?;
	}
	
	// check MPT root is storage_root
	for (pf_root, root) in proof.root_hash_bytes.iter().zip(storage_root.clone()) {
	    ctx.region.constrain_equal(pf_root.cell(), root.cell())?;
	}

	// check MPT inclusion
	self.mpt.parse_mpt_inclusion_fixed_key(
	    ctx, range, proof, 32, 33, proof.max_depth
	)?;

	// parse slot value
	let field_trace = self.mpt.rlp.decompose_rlp_field(
	    ctx, range, &proof.value_bytes, 32
	)?;
	
	let storage_trace = EthStorageTrace {
	    value_trace: field_trace.field_trace,
	};
	Ok(storage_trace)
    }

    pub fn parse_acct_storage_pf(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	addr: &AssignedBytes<F>,
	state_root: &AssignedBytes<F>,
	slot: &AssignedBytes<F>,
	acct_pf: &MPTFixedKeyProof<F>,
	storage_pf: &MPTFixedKeyProof<F>,
    ) -> Result<EthAccountStorageTrace<F>, Error> {
	let acct_trace = self.parse_acct_pf(
	    ctx, range, state_root, addr, acct_pf
	)?;
	let storage_root = &acct_trace.storage_root_trace.val;

	let storage_trace = self.parse_storage_pf(
	    ctx, range, storage_root, slot, storage_pf
	)?;

	let trace = EthAccountStorageTrace { acct_trace, storage_trace };
	Ok(trace)
    }
    
    pub fn parse_block_acct_storage_pf(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	block_hash: &AssignedBytes<F>,
	addr: &AssignedBytes<F>,
	slot: &AssignedBytes<F>,
	block_header: &AssignedBytes<F>,
	acct_pf: &MPTFixedKeyProof<F>,
	storage_pf: &MPTFixedKeyProof<F>,
    ) -> Result<EthBlockAccountStorageTrace<F>, Error> {
	// extract state root from block
	let block_trace = self.decompose_eth_block_header(
	    ctx, range, block_header
	)?;
	let state_root = &block_trace.state_root.val;

	// check block_hash
	for (hash, b_hash) in block_hash.iter().zip(block_trace.block_hash.val.clone()) {
	    ctx.region.constrain_equal(hash.cell(), b_hash.cell())?;
	}
	
	// verify account + storage proof
	let acct_storage_trace = self.parse_acct_storage_pf(
	    ctx, range, addr, state_root, slot, acct_pf, storage_pf
	)?;
	let trace = EthBlockAccountStorageTrace {
	    block_trace,
	    acct_trace: acct_storage_trace.acct_trace,
	    storage_trace: acct_storage_trace.storage_trace,
	};
	Ok(trace)
    }

    pub fn uint_to_bytes_be(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	input: &AssignedValue<F>,
	num_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
	let coeffs = (0..num_bytes).map(|idx| {
	    Witness(input.value().map(|x| {
		biguint_to_fe(&((fe_to_biguint(x) / BigUint::from(256u64).pow(u32::try_from(num_bytes - 1 - idx).unwrap())) % BigUint::from(256u64)))
	    }))
	}).collect();
	let weights = (0..num_bytes).map(|idx| {
	    Constant(biguint_to_fe(&BigUint::from(256u64).pow(u32::try_from(num_bytes - 1 - idx).unwrap())))
	}).collect();
	let (coeffs_assigned, _, val) = range.gate.inner_product(
	    ctx, &coeffs, &weights
	)?;

	ctx.region.constrain_equal(input.cell(), val.cell())?;
	for coeff in coeffs_assigned.clone().unwrap().iter() {
	    self.mpt.keccak.byte_to_hex(ctx, range, coeff)?;
	}
	Ok(coeffs_assigned.unwrap())
    }

    pub fn bytes_be_to_uint(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	input: &AssignedBytes<F>,
	num_bytes: usize,
    ) -> Result<AssignedValue<F>, Error> {
	let (_, _, val) = range.gate.inner_product(
	    ctx,
	    &input[..num_bytes].iter().map(|x| Existing(x)).collect(),
	    &(0..num_bytes).map(|idx| {
		Constant(biguint_to_fe(&BigUint::from(256u64).pow(u32::try_from(num_bytes - 1 - idx).unwrap())))
	    }).collect()
	)?;
	Ok(val)
    }
    
    // slot and block_hash are big-endian 16-byte
    pub fn parse_block_acct_storage_pf_min(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	block_hash: &(AssignedValue<F>, AssignedValue<F>),
	addr: &AssignedValue<F>,
	slot: &(AssignedValue<F>, AssignedValue<F>),
	block_header: &AssignedBytes<F>,
	acct_pf: &MPTFixedKeyProof<F>,
	storage_pf: &MPTFixedKeyProof<F>,
    ) -> Result<EthBlockAccountStorageMinTrace<F>, Error> {
	// extract state root from block
	let block_trace = self.decompose_eth_block_header(
	    ctx, range, block_header
	)?;
	let state_root = &block_trace.state_root.val;

	// check block_hash	
	let mut block_hash_bytes = self.uint_to_bytes_be(
	    ctx, range, &block_hash.0, 16
	)?;
	let block_hash_bytes2 = self.uint_to_bytes_be(
	    ctx, range, &block_hash.1, 16
	)?;
	block_hash_bytes.extend(block_hash_bytes2);
	for (hash, b_hash) in block_hash_bytes.iter().zip(block_trace.block_hash.val.clone()) {
	    ctx.region.constrain_equal(hash.cell(), b_hash.cell())?;
	}

	// verify account + storage proof
	let addr_bytes = self.uint_to_bytes_be(
	    ctx, range, addr, 20
	)?;
	let mut slot_bytes = self.uint_to_bytes_be(
	    ctx, range, &slot.0, 16
	)?;
	let slot_bytes2 = self.uint_to_bytes_be(
	    ctx, range, &slot.1, 16
	)?;
	slot_bytes.extend(slot_bytes2);
	let acct_storage_trace = self.parse_acct_storage_pf(
	    ctx, range, &addr_bytes, state_root, &slot_bytes, acct_pf, storage_pf
	)?;

	// blockHash || address || slot || blockNumber || slot value
	// 32 + 20 + 32 + 4 + 32 = 120 bytes
	let mut hash_inp = Vec::new();
	hash_inp.extend(block_hash_bytes);
	hash_inp.extend(addr_bytes);
	hash_inp.extend(slot_bytes);
	hash_inp.extend(block_trace.number.val.clone());
	hash_inp.extend(acct_storage_trace.storage_trace.value_trace.val.clone());
	
	let len = range.gate.assign_region_smart(
            ctx, vec![Constant(F::from(120))], vec![], vec![], vec![],
        )?;
	let (pub_hash_bytes, _) = self.mpt.keccak.keccak_bytes_var_len(
	    ctx, range, &hash_inp, len[0].clone(), 119, 120
	)?;
	let pub_hash = self.bytes_be_to_uint(
	    ctx, range, &pub_hash_bytes, 31
	)?;
	
	let trace = EthBlockAccountStorageMinTrace {
	    block_trace,
	    acct_trace: acct_storage_trace.acct_trace,
	    storage_trace: acct_storage_trace.storage_trace,
	    pub_hash,
	};
	Ok(trace)
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
    type Config = EthChip<F>;
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
        let params: EthConfigParams = serde_json::from_str(params_str.as_str()).unwrap();

        EthChip::configure(meta, "gamma".to_string(), "rlc".to_string(), params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.mpt.rlp.range.load_lookup_table(&mut layouter)?;
        config.mpt.keccak.load_lookup_table(&mut layouter)?;
        let gamma = layouter.get_challenge(config.mpt.rlp.rlc.gamma);
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
                            ("default".to_string(), config.mpt.rlp.range.gate.num_advice),
                            ("rlc".to_string(), config.mpt.rlp.rlc.basic_chips.len()),
                            ("keccak".to_string(), config.mpt.keccak.rotation.len()),
                            ("keccak_xor".to_string(), config.mpt.keccak.xor_values.len() / 3),
                            ("keccak_xorandn".to_string(), config.mpt.keccak.xorandn_values.len() / 4),
                        ],
                    },
                );
                let ctx = &mut aux;
                ctx.challenge.insert("gamma".to_string(), gamma);

                let mut inputs_assigned = Vec::with_capacity(self.inputs.len());
                for input in self.inputs.iter() {
                    let input_assigned = config.mpt.rlp.range.gate.assign_region_smart(
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
                    .decompose_eth_block_header_chain(ctx, &config.mpt.rlp.range, &inputs_assigned)
                    .unwrap();

                // block_hash is 256 bits, but we need them in 128 bits to fit in Bn254 scalar field
                parent_block_hash = Some(bytes_be_to_u128(
                    ctx,
                    config.mpt.rlp.range.gate(),
                    &inputs_assigned[0][4..36],
                ));
                latest_block_hash = Some(bytes_be_to_u128(
                    ctx,
                    config.mpt.rlp.range.gate(),
                    &block_header_trace.last().unwrap().block_hash_bytes,
                ));

                let tree_root_hexes = config.mpt.keccak.merkle_tree_root(
                    ctx,
                    &block_header_trace
                        .iter()
                        .map(|trace| trace.block_hash_hexes.as_slice())
                        .collect_vec(),
                )?;
                merkle_root = Some(hexes_to_u128(ctx, config.mpt.rlp.range.gate(), &tree_root_hexes));

                let stats = config.mpt.rlp.range.finalize(ctx)?;
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

