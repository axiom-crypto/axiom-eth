#[cfg(feature = "input_gen")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::{biguint_to_fe, fe_to_biguint, value_to_option},
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
    mpt::mpt::{AssignedBytes, MPTChip, MPTFixedKeyProof},
    rlp::rlc::{RlcFixedTrace, RlcTrace},
    rlp::rlp::{RlpArrayChip, RlpArrayTrace},
};

#[cfg(feature = "aggregation")]
pub mod aggregation;
pub mod block_header;
pub mod storage;

use block_header::{bytes_be_to_u128, decompose_eth_block_header, EthBlockHeaderTrace};

#[derive(Clone, Debug, PartialEq)]
pub enum Network {
    Mainnet,
    Goerli,
}
pub const NETWORK: Network = Network::Goerli;

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

    pub keccak_num_rot: usize,
    pub keccak_num_xor: usize,
    pub keccak_num_xorandn: usize,
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
    value: AssignedBytes<F>,
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
        decompose_eth_block_header(ctx, &self.mpt.rlp, &self.mpt.keccak, block_header, NETWORK)
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
            range.gate.assert_is_const(ctx, &traces[idx + 1].parent_hash.rlc_len, F::from(32))?;
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
        assert_eq!(addr.len(), 20);
        let hash_bytes = self.mpt.keccak.keccak_bytes_fixed_len(ctx, range, addr)?;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.iter()) {
            ctx.region.constrain_equal(hash.cell(), key.cell())?;
        }

        // check MPT root is state root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(state_root.iter()) {
            ctx.region.constrain_equal(pf_root.cell(), root.cell())?;
        }

        // Check MPT inclusion for:
        // keccak(addr) => RLP([nonce, balance, storage_root, code_hash])
        self.mpt.parse_mpt_inclusion_fixed_key(ctx, range, proof, 32, 114, proof.max_depth)?;

        // parse value
        let array_trace = self.mpt.rlp.decompose_rlp_array(
            ctx,
            range,
            &proof.value_bytes,
            vec![33, 13, 33, 33],
            114,
            4,
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
        let hash_bytes = self.mpt.keccak.keccak_bytes_fixed_len(ctx, range, slot)?;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.clone()) {
            ctx.region.constrain_equal(hash.cell(), key.cell())?;
        }

        // check MPT root is storage_root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(storage_root.clone()) {
            ctx.region.constrain_equal(pf_root.cell(), root.cell())?;
        }

        // check MPT inclusion
        self.mpt.parse_mpt_inclusion_fixed_key(ctx, range, proof, 32, 33, proof.max_depth)?;

        // parse slot value
        let slot_value =
            self.mpt.rlp.decompose_rlp_field_get_value(ctx, range, &proof.value_bytes, 32)?;
        assert_eq!(slot_value.len(), 32);

        let storage_trace = EthStorageTrace { value: slot_value };
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
        let acct_trace = self.parse_acct_pf(ctx, range, state_root, addr, acct_pf)?;
        let storage_root = &acct_trace.storage_root_trace.val;

        let storage_trace = self.parse_storage_pf(ctx, range, storage_root, slot, storage_pf)?;
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
        let block_trace = self.decompose_eth_block_header(ctx, range, block_header)?;
        let state_root = &block_trace.state_root.val;

        // check block_hash
        for (hash, b_hash) in block_hash.iter().zip(block_trace.block_hash.val.clone()) {
            ctx.region.constrain_equal(hash.cell(), b_hash.cell())?;
        }

        // verify account + storage proof
        let acct_storage_trace =
            self.parse_acct_storage_pf(ctx, range, addr, state_root, slot, acct_pf, storage_pf)?;
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
        let mask = BigUint::from(255u64);
        let coeffs = (0..num_bytes).map(|idx| {
            Witness(input.value().map(|x| {
                F::from(
                    ((fe_to_biguint(x) >> (8 * (num_bytes - 1 - idx))) & &mask).to_u64().unwrap(),
                )
            }))
        });
        let weights = (0..num_bytes)
            .map(|idx| Constant(biguint_to_fe(&(BigUint::from(1u64) << (8 * idx)))))
            .rev();
        let (coeffs_assigned, _, val) = range.gate.inner_product(ctx, coeffs, weights)?;

        ctx.region.constrain_equal(input.cell(), val.cell())?;
        for coeff in coeffs_assigned.clone().unwrap().iter() {
            self.mpt.keccak.byte_to_hex(ctx, range, coeff)?;
        }
        Ok(coeffs_assigned.unwrap())
    }

    pub fn uint_to_bytes_le(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        input: &AssignedValue<F>,
        num_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mask = BigUint::from(255u64);
        let coeffs = (0..num_bytes).map(|idx| {
            Witness(
                input
                    .value()
                    .map(|x| F::from(((fe_to_biguint(x) >> (8 * idx)) & &mask).to_u64().unwrap())),
            )
        });
        let weights =
            (0..num_bytes).map(|idx| Constant(biguint_to_fe(&(BigUint::from(1u64) << (8 * idx)))));
        let (coeffs_assigned, _, val) = range.gate.inner_product(ctx, coeffs, weights)?;

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
            input[..num_bytes].iter().map(|x| Existing(x)),
            (0..num_bytes)
                .map(|idx| Constant(biguint_to_fe(&(BigUint::from(1u64) << (8 * idx)))))
                .rev(),
        )?;
        Ok(val)
    }

    // slot and block_hash are big-endian 16-byte
    pub fn parse_block_acct_storage_pf_min(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        block_hash: &(AssignedValue<F>, AssignedValue<F>), // H256 as (u128, u128)
        addr: &AssignedValue<F>,                           // U160
        slot: &(AssignedValue<F>, AssignedValue<F>),       // H256 as (u128, u128)
        block_header: &AssignedBytes<F>,
        acct_pf: &MPTFixedKeyProof<F>,
        storage_pf: &MPTFixedKeyProof<F>,
    ) -> Result<EthBlockAccountStorageMinTrace<F>, Error> {
        // extract state root from block
        let block_trace = self.decompose_eth_block_header(ctx, range, block_header)?;
        let state_root = &block_trace.state_root.val;

        // check block_hash
        let mut block_hash_bytes = self.uint_to_bytes_be(ctx, range, &block_hash.0, 16)?;
        let block_hash_bytes2 = self.uint_to_bytes_be(ctx, range, &block_hash.1, 16)?;
        block_hash_bytes.extend(block_hash_bytes2);
        for (hash, b_hash) in block_hash_bytes.iter().zip(block_trace.block_hash.val.clone()) {
            ctx.region.constrain_equal(hash.cell(), b_hash.cell())?;
        }

        // verify account + storage proof
        let addr_bytes = self.uint_to_bytes_be(ctx, range, addr, 20)?;
        let mut slot_bytes = self.uint_to_bytes_be(ctx, range, &slot.0, 16)?;
        let slot_bytes2 = self.uint_to_bytes_be(ctx, range, &slot.1, 16)?;
        slot_bytes.extend(slot_bytes2);
        let acct_storage_trace = self.parse_acct_storage_pf(
            ctx,
            range,
            &addr_bytes,
            state_root,
            &slot_bytes,
            acct_pf,
            storage_pf,
        )?;

        // blockHash || address || slot || blockNumber || slot value
        // 32 + 20 + 32 + 4 + 32 = 120 bytes
        let mut hash_inp = Vec::new();
        hash_inp.extend(block_hash_bytes);
        hash_inp.extend(addr_bytes);
        hash_inp.extend(slot_bytes);
        hash_inp.extend(block_trace.number.val.clone());
        hash_inp.extend(acct_storage_trace.storage_trace.value.iter().cloned());
        assert_eq!(hash_inp.len(), 120);
        /*for byte in hash_inp.iter() {
            print!("{:02x}", value_to_option(byte.value()).unwrap().get_lower_32());
        }
        println!("");*/

        let pub_hash_bytes = self.mpt.keccak.keccak_bytes_fixed_len(ctx, range, &hash_inp)?;
        /*for byte in pub_hash_bytes.iter() {
            print!("{:02x}", value_to_option(byte.value()).unwrap().get_lower_32());
        }
        println!("");*/
        let pub_hash = self.bytes_be_to_uint(ctx, range, &pub_hash_bytes, 31)?;

        let trace = EthBlockAccountStorageMinTrace {
            block_trace,
            acct_trace: acct_storage_trace.acct_trace,
            storage_trace: acct_storage_trace.storage_trace,
            pub_hash,
        };
        Ok(trace)
    }
}
