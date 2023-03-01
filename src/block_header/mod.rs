use super::{
    util::{bytes_be_to_u128, encode_h256_to_field, EthConfigParams},
    Field, Network,
};
use crate::{
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::{RlcContextPair, RlcFixedTrace, RlcTrace, FIRST_PHASE, RLC_PHASE},
        RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness,
    },
    util::{bytes_be_var_to_fixed, decode_field_to_h256},
    EthChip, EthCircuitBuilder, ETH_LOOKUP_BITS,
};
use core::{
    iter::{self, once},
    marker::PhantomData,
};
use ethers_core::types::H256;
#[cfg(feature = "providers")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions, RangeChip},
    utils::bit_length,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use itertools::Itertools;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, env::var};

#[cfg(feature = "aggregation")]
pub mod aggregation;
#[cfg(all(feature = "aggregation", feature = "providers"))]
pub mod sequencer;
#[cfg(test)]
mod tests;

const MAINNET_EXTRA_DATA_MAX_BYTES: usize = 32;
const MAINNET_EXTRA_DATA_RLP_MAX_BYTES: usize = MAINNET_EXTRA_DATA_MAX_BYTES + 1;
pub const MAINNET_BLOCK_HEADER_RLP_MAX_BYTES: usize =
    1 + 2 + 521 + MAINNET_EXTRA_DATA_RLP_MAX_BYTES;
const GOERLI_EXTRA_DATA_MAX_BYTES: usize = 97;
const GOERLI_EXTRA_DATA_RLP_MAX_BYTES: usize = GOERLI_EXTRA_DATA_MAX_BYTES + 1;
pub const GOERLI_BLOCK_HEADER_RLP_MAX_BYTES: usize = 1 + 2 + 521 + GOERLI_EXTRA_DATA_RLP_MAX_BYTES;
const BLOCK_HEADER_RLP_MIN_BYTES: usize = 479;

const NUM_BLOCK_HEADER_FIELDS: usize = 16;
const MAINNET_HEADER_FIELDS_MAX_BYTES: [usize; NUM_BLOCK_HEADER_FIELDS] =
    [32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, MAINNET_EXTRA_DATA_MAX_BYTES, 32, 8, 6];
const GOERLI_HEADER_FIELDS_MAX_BYTES: [usize; NUM_BLOCK_HEADER_FIELDS] =
    [32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, GOERLI_EXTRA_DATA_MAX_BYTES, 32, 8, 6];
pub const BLOCK_NUMBER_MAX_BYTES: usize = MAINNET_HEADER_FIELDS_MAX_BYTES[8];

// Field        Type        Size (bytes) RLP size (bytes) RLP size (bits)
// parentHash	256 bits	32	33	264
// ommersHash	256 bits	32	33	264
// beneficiary	160 bits	20	21	168
// stateRoot	256 bits	32	33	264
// transactionsRoot	256 bits	32	33	264
// receiptsRoot	256 bits	32	33	264
// logsBloom	256 bytes	256	259	2072
// difficulty	big int scalar	variable	8   64
// number	big int scalar	variable	<= 5    <= 32
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
    // pub rlp_trace: RlcTrace<F>,
    pub parent_hash: RlpFieldTrace<F>,
    pub ommers_hash: RlpFieldTrace<F>,
    pub beneficiary: RlpFieldTrace<F>,
    pub state_root: RlpFieldTrace<F>,
    pub transactions_root: RlpFieldTrace<F>,
    pub receipts_root: RlpFieldTrace<F>,

    pub logs_bloom: RlpFieldTrace<F>,
    pub difficulty: RlpFieldTrace<F>,
    pub number: RlpFieldTrace<F>,
    pub gas_limit: RlpFieldTrace<F>,
    pub gas_used: RlpFieldTrace<F>,
    pub timestamp: RlpFieldTrace<F>,
    pub extra_data: RlpFieldTrace<F>,
    pub mix_hash: RlpFieldTrace<F>,
    pub nonce: RlpFieldTrace<F>,
    pub basefee: Option<RlpFieldTrace<F>>,

    pub block_hash: RlcFixedTrace<F>,

    // pub prefix: AssignedValue<F>,
    pub len_trace: RlcTrace<F>,
}
#[derive(Clone, Debug)]
pub struct EthBlockHeaderTraceWitness<F: Field> {
    pub rlp_witness: RlpArrayTraceWitness<F>,
    pub block_hash: Vec<AssignedValue<F>>,
    pub block_hash_query_idx: usize,
}

impl<F: Field> EthBlockHeaderTraceWitness<F> {
    pub fn get(&self, header_field: &str) -> &RlpFieldWitness<F> {
        match header_field {
            "parent_hash" | "parentHash" => &self.rlp_witness.field_witness[0],
            "ommers_hash" | "ommersHash" => &self.rlp_witness.field_witness[1],
            "beneficiary" => &self.rlp_witness.field_witness[2],
            "state_root" | "stateRoot" => &self.rlp_witness.field_witness[3],
            "transactions_root" | "transactionsRoot" => &self.rlp_witness.field_witness[4],
            "receipts_root" | "receiptsRoot" => &self.rlp_witness.field_witness[5],
            "logs_bloom" | "logsBloom" => &self.rlp_witness.field_witness[6],
            "difficulty" => &self.rlp_witness.field_witness[7],
            "number" => &self.rlp_witness.field_witness[8],
            "gas_limit" | "gasLimit" => &self.rlp_witness.field_witness[9],
            "gas_used" | "gasUsed" => &self.rlp_witness.field_witness[10],
            "timestamp" => &self.rlp_witness.field_witness[11],
            "extra_data" | "extraData" => &self.rlp_witness.field_witness[12],
            "mix_hash" | "mixHash" => &self.rlp_witness.field_witness[13],
            "nonce" => &self.rlp_witness.field_witness[14],
            "basefee" => &self.rlp_witness.field_witness[15],
            _ => panic!("Invalid header field"),
        }
    }
}

pub trait EthBlockHeaderChip<F: Field> {
    /// Takes the variable length RLP encoded block header, padded with 0s to the maximum possible block header RLP length, and outputs the decomposition into block header fields.
    ///
    /// In addition, the keccak block hash of the block is calculated.
    ///
    /// Assumes `block_header` and `block_header_assigned` have the same values as bytes. The former is only used for faster witness generation.
    ///
    /// This is the preparation step that computes the witnesses. This MUST be done in `FirstPhase`.
    /// The accompanying `decompose_block_header_finalize` must be called in `SecondPhase` to constrain the RLCs associated to the RLP decoding.
    fn decompose_block_header_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        block_header: &[u8],
        network: Network,
    ) -> EthBlockHeaderTraceWitness<F>;

    /// Takes the variable length RLP encoded block header, padded with 0s to the maximum possible block header RLP length, and outputs the decomposition into block header fields.
    ///
    /// In addition, the keccak block hash of the block is calculated.
    ///
    /// Assumes `block_header` and `block_header_assigned` have the same values as bytes. The former is only used for faster witness generation.
    ///
    /// This is the finalization step that constrains RLC concatenations.
    /// This should be called after `decompose_block_header_phase0`.
    /// This MUST be done in `SecondPhase`.
    ///
    /// WARNING: This function is not thread-safe unless you call `load_rlc_cache` ahead of time.
    fn decompose_block_header_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthBlockHeaderTraceWitness<F>,
    ) -> EthBlockHeaderTrace<F>;

    /// Takes a list of (purported) RLP encoded block headers and
    /// decomposes each header into it's fields.
    /// `headers[0]` is the earliest block.
    ///
    /// This is the preparation step that computes the witnesses. This MUST be done in `FirstPhase`.
    /// The accompanying `decompose_block_header_chain_phase1` must be called in `SecondPhase` to constrain the RLCs associated to the RLP decoding.
    fn decompose_block_header_chain_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        headers: &[Vec<u8>],
        network: Network,
    ) -> Vec<EthBlockHeaderTraceWitness<F>>;

    /// Takes a list of `2^max_depth` (purported) RLP encoded block headers.
    /// Decomposes each header into it's fields.
    /// `headers[0]` is the earliest block
    ///
    /// - If `num_blocks_minus_one` is not None, then the circuit checks that the first `num_blocks := num_blocks_minus_one + 1` block headers form a chain: meaning that the parent hash of block i + 1 equals the hash of block i.
    /// - Otherwise if `num_blocks` is None, the circuit checks that all `headers` form a hash chain.
    ///
    /// Assumes that `0 <= num_blocks_minus_one < 2^max_depth`.
    ///
    /// This is the finalization step that constrains RLC concatenations. In this step the hash chain is actually constrained.
    /// This should be called after `decompose_block_header_chain_phase0`.
    /// This MUST be done in `SecondPhase`.
    fn decompose_block_header_chain_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<EthBlockHeaderTraceWitness<F>>,
        num_blocks_minus_one: Option<AssignedValue<F>>,
    ) -> Vec<EthBlockHeaderTrace<F>>;
}

impl<'chip, F: Field> EthBlockHeaderChip<F> for EthChip<'chip, F> {
    fn decompose_block_header_phase0(
        &self,
        ctx: &mut Context<F>, // ctx_gate in FirstPhase
        keccak: &mut KeccakChip<F>,
        block_header: &[u8],
        network: Network,
    ) -> EthBlockHeaderTraceWitness<F> {
        let (max_len, max_field_lens) = match network {
            Network::Mainnet => {
                (MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, &MAINNET_HEADER_FIELDS_MAX_BYTES)
            }
            Network::Goerli => (GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, &GOERLI_HEADER_FIELDS_MAX_BYTES),
        };
        assert_eq!(block_header.len(), max_len);
        let block_header_assigned =
            ctx.assign_witnesses(block_header.iter().map(|byte| F::from(*byte as u64)));
        let rlp_witness =
            self.rlp().decompose_rlp_array_phase0(ctx, block_header_assigned, max_field_lens, true); // `is_variable_len = true` because RLP can have either 15 or 16 fields, depending on whether block is pre-London or not

        let block_hash_query_idx = keccak.keccak_var_len(
            ctx,
            self.range(),
            rlp_witness.rlp_array.clone(), // this is `block_header_assigned`
            Some(block_header.to_vec()),
            rlp_witness.rlp_len,
            BLOCK_HEADER_RLP_MIN_BYTES,
        );
        let block_hash = keccak.var_len_queries[block_hash_query_idx].output_assigned.clone();
        EthBlockHeaderTraceWitness { rlp_witness, block_hash, block_hash_query_idx }
    }

    fn decompose_block_header_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthBlockHeaderTraceWitness<F>,
    ) -> EthBlockHeaderTrace<F> {
        let mut trace = self.rlp().decompose_rlp_array_phase1(ctx, witness.rlp_witness, true);
        let block_hash = self.keccak_var_len_rlcs()[witness.block_hash_query_idx].1;

        // Base fee per unit gas only after London
        let basefee = trace.field_trace.pop();
        let [parent_hash, ommers_hash, beneficiary, state_root, transactions_root, receipts_root, logs_bloom, difficulty, number, gas_limit, gas_used, timestamp, extra_data, mix_hash, nonce]: [RlpFieldTrace<F>; 15] =
            trace.field_trace.try_into().unwrap();

        EthBlockHeaderTrace {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            mix_hash,
            nonce,
            basefee,
            block_hash,
            len_trace: trace.len_trace,
        }
    }

    fn decompose_block_header_chain_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        headers: &[Vec<u8>],
        network: Network,
    ) -> Vec<EthBlockHeaderTraceWitness<F>> {
        let (max_len, max_field_lens) = match network {
            Network::Mainnet => {
                (MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, &MAINNET_HEADER_FIELDS_MAX_BYTES)
            }
            Network::Goerli => (GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, &GOERLI_HEADER_FIELDS_MAX_BYTES),
        };
        // we cannot directly parallelize `decompose_block_header_phase0` because `KeccakChip` is not thread-safe (we need to deterministically add new queries), so we explicitly parallelize the logic here:
        let witness_gen_only = thread_pool.witness_gen_only();
        let ctx_ids = headers.iter().map(|_| thread_pool.get_new_thread_id()).collect::<Vec<_>>();
        let (rlp_witnesses, mut ctxs): (Vec<_>, Vec<_>) = headers
            .par_iter()
            .zip(ctx_ids.into_par_iter())
            .map(|(header, ctx_id)| {
                assert_eq!(header.len(), max_len);
                let mut ctx = Context::new(witness_gen_only, ctx_id);
                let header = ctx.assign_witnesses(header.iter().map(|byte| F::from(*byte as u64)));
                let rlp_witness =
                    self.rlp().decompose_rlp_array_phase0(&mut ctx, header, max_field_lens, true); // `is_variable_len = true` because RLP can have either 15 or 16 fields, depending on whether block is pre-London or not
                (rlp_witness, ctx)
            })
            .unzip();
        // single-threaded adding of keccak queries
        thread_pool.threads[FIRST_PHASE].append(&mut ctxs);
        let ctx = thread_pool.main(FIRST_PHASE);
        rlp_witnesses
            .into_iter()
            .zip(headers.iter())
            .map(|(rlp_witness, header)| {
                let block_hash_query_idx = keccak.keccak_var_len(
                    ctx,
                    self.range(),
                    rlp_witness.rlp_array.clone(), // this is `block_header_assigned`
                    Some(header.to_vec()),
                    rlp_witness.rlp_len,
                    BLOCK_HEADER_RLP_MIN_BYTES,
                );
                let block_hash =
                    keccak.var_len_queries[block_hash_query_idx].output_assigned.clone();
                EthBlockHeaderTraceWitness { rlp_witness, block_hash, block_hash_query_idx }
            })
            .collect()
    }

    fn decompose_block_header_chain_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<EthBlockHeaderTraceWitness<F>>,
        num_blocks_minus_one: Option<AssignedValue<F>>,
    ) -> Vec<EthBlockHeaderTrace<F>> {
        assert!(!witnesses.is_empty());
        let ctx = thread_pool.rlc_ctx_pair();
        // to ensure thread-safety of the later calls, we load rlc_cache to the max length first.
        // assuming this is called after `decompose_block_header_chain_phase0`, all headers should be same length = max_len
        let cache_bits = bit_length(witnesses[0].rlp_witness.rlp_array.len() as u64);
        self.rlc().load_rlc_cache(ctx, self.gate(), cache_bits);
        // now multi-threading:
        let witness_gen_only = thread_pool.witness_gen_only();
        let ctx_ids = witnesses
            .iter()
            .map(|_| (thread_pool.get_new_thread_id(), thread_pool.get_new_thread_id()))
            .collect_vec();
        let (traces, ctxs): (Vec<_>, Vec<_>) = witnesses
            .into_par_iter()
            .zip(ctx_ids.into_par_iter())
            .map(|(witness, (gate_id, rlc_id))| {
                let mut ctx_gate = Context::new(witness_gen_only, gate_id);
                let mut ctx_rlc = Context::new(witness_gen_only, rlc_id);
                let trace =
                    self.decompose_block_header_phase1((&mut ctx_gate, &mut ctx_rlc), witness);
                (trace, (ctx_gate, ctx_rlc))
            })
            .unzip();
        let (mut ctxs_gate, mut ctxs_rlc): (Vec<_>, Vec<_>) = ctxs.into_iter().unzip();
        thread_pool.gate_builder.threads[RLC_PHASE].append(&mut ctxs_gate);
        thread_pool.threads_rlc.append(&mut ctxs_rlc);

        let ctx_gate = thread_pool.gate_builder.main(RLC_PHASE);
        let thirty_two = self.gate().get_field_element(32);
        // record for each idx whether hash of headers[idx] is in headers[idx + 1]
        if let Some(num_blocks_minus_one) = num_blocks_minus_one {
            let mut hash_checks = Vec::with_capacity(traces.len() - 1);
            for idx in 0..traces.len() - 1 {
                let hash_check = self.gate().is_equal(
                    ctx_gate,
                    traces[idx].block_hash.rlc_val,
                    traces[idx + 1].parent_hash.field_trace.rlc_val,
                );
                hash_checks.push(hash_check);
                self.gate().assert_is_const(
                    ctx_gate,
                    &traces[idx + 1].parent_hash.field_trace.len,
                    &thirty_two,
                );
            }
            let hash_check_sums =
                self.gate().partial_sums(ctx_gate, hash_checks.iter().copied()).collect_vec();
            let hash_check_sum = self.gate().select_from_idx(
                ctx_gate,
                once(Constant(F::zero())).chain(hash_check_sums.into_iter().map(Existing)),
                num_blocks_minus_one,
            );
            ctx_gate.constrain_equal(&hash_check_sum, &num_blocks_minus_one);
        } else {
            for idx in 0..traces.len() - 1 {
                ctx_gate.constrain_equal(
                    &traces[idx].block_hash.rlc_val,
                    &traces[idx + 1].parent_hash.field_trace.rlc_val,
                );
                self.gate().assert_is_const(
                    ctx_gate,
                    &traces[idx + 1].parent_hash.field_trace.len,
                    &thirty_two,
                );
            }
        }

        traces
    }
}

/// Given a block header chain `chain` of fixed length `2^max_depth`, returns
/// ```
/// (prev_block_hash, end_block_hash, start_block_number || end_block_number)
/// ```
/// where
/// ```
/// prev_block_hash = chain[0].parent_hash,
/// end_block_hash = chain[num_blocks_minus_one].block_hash,
/// start_block_number = chain[0].number,
/// end_block_number = chain[num_blocks_minus_one].number
/// ```
/// The hashes are H256 that are represented as two u128
/// (we need them in 128 bits to fit in Bn254 scalar field).
///
/// The numbers are left padded by zeros to be exactly 4 bytes (u32); the two padded numbers are concatenated together to a u64.
///
/// This function should be called in `FirstPhase`.
pub fn get_boundary_block_data<F: Field>(
    ctx: &mut Context<F>, // ctx_gate in FirstPhase
    gate: &impl GateInstructions<F>,
    chain: &[EthBlockHeaderTraceWitness<F>],
    num_blocks_minus_one: AssignedValue<F>,
) -> ([AssignedValue<F>; 2], [AssignedValue<F>; 2], AssignedValue<F>) {
    let prev_block_hash: [_; 2] =
        bytes_be_to_u128(ctx, gate, &chain[0].get("parent_hash").field_cells).try_into().unwrap();
    let end_block_hash: [_; 2] = {
        let end_block_hash_bytes = (0..32)
            .map(|idx| {
                gate.select_from_idx(
                    ctx,
                    chain.iter().map(|header| header.block_hash[idx]),
                    num_blocks_minus_one,
                )
            })
            .collect_vec();
        bytes_be_to_u128(ctx, gate, &end_block_hash_bytes).try_into().unwrap()
    };

    // start_block_number || end_block_number
    let block_numbers = {
        debug_assert_eq!(chain[0].get("number").max_field_len, BLOCK_NUMBER_MAX_BYTES);
        let start_block_number_bytes = bytes_be_var_to_fixed(
            ctx,
            gate,
            &chain[0].get("number").field_cells,
            chain[0].get("number").field_len,
            BLOCK_NUMBER_MAX_BYTES,
        );
        // TODO: is there a way to do this without so many selects
        let end_block_number_bytes: [_; BLOCK_NUMBER_MAX_BYTES] =
            core::array::from_fn(|i| i).map(|idx| {
                gate.select_from_idx(
                    ctx,
                    chain.iter().map(|header| header.get("number").field_cells[idx]),
                    num_blocks_minus_one,
                )
            });
        let end_block_number_len = gate.select_from_idx(
            ctx,
            chain.iter().map(|header| header.get("number").field_len),
            num_blocks_minus_one,
        );
        let mut end_block_number_bytes = bytes_be_var_to_fixed(
            ctx,
            gate,
            &end_block_number_bytes,
            end_block_number_len,
            BLOCK_NUMBER_MAX_BYTES,
        );
        let mut block_numbers_bytes = start_block_number_bytes;
        block_numbers_bytes.append(&mut end_block_number_bytes);
        let [block_numbers]: [_; 1] =
            bytes_be_to_u128(ctx, gate, &block_numbers_bytes).try_into().unwrap();
        block_numbers
    };

    (prev_block_hash, end_block_hash, block_numbers)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthBlockHeaderChainInstance {
    pub prev_hash: H256,
    pub end_hash: H256,
    pub start_block_number: u32,
    pub end_block_number: u32,
    pub merkle_mountain_range: Vec<H256>,
}

impl EthBlockHeaderChainInstance {
    pub fn new(
        prev_hash: H256,
        end_hash: H256,
        start_block_number: u32,
        end_block_number: u32,
        merkle_mountain_range: Vec<H256>,
    ) -> Self {
        Self { prev_hash, end_hash, start_block_number, end_block_number, merkle_mountain_range }
    }

    pub fn to_instance<F: Field>(&self) -> Vec<F> {
        // * prevHash: uint256 represented as 2 uint128s
        // * endHash:  uint256 represented as 2 uint128s
        // * startBlockNumber || endBlockNumber: 0..0 || uint32 || 0..0 || uint32 as u64 (exactly 64 bits)
        // * merkleRoots: Vec<uint256>, each represented as 2 uint128s
        let [prev_hash, end_hash] =
            [&self.prev_hash, &self.end_hash].map(|hash| encode_h256_to_field::<F>(hash));
        let block_numbers =
            F::from(((self.start_block_number as u64) << 32) + (self.end_block_number as u64));
        let merkle_mountain_range = self
            .merkle_mountain_range
            .iter()
            .flat_map(|hash| encode_h256_to_field::<F>(hash))
            .collect_vec();

        [&prev_hash[..], &end_hash[..], &[block_numbers], &merkle_mountain_range].concat()
    }

    pub fn from_instance<F: Field>(instance: &[F]) -> Self {
        let prev_hash = decode_field_to_h256(&instance[0..2]);
        let end_hash = decode_field_to_h256(&instance[2..4]);
        let block_numbers = instance[4].to_repr(); // little endian
        let start_block_number = u32::from_le_bytes(block_numbers[4..8].try_into().unwrap());
        let end_block_number = u32::from_le_bytes(block_numbers[..4].try_into().unwrap());
        let merkle_mountain_range =
            instance[5..].chunks(2).map(|chunk| decode_field_to_h256(chunk)).collect_vec();

        Self::new(prev_hash, end_hash, start_block_number, end_block_number, merkle_mountain_range)
    }
}

#[derive(Clone, Debug)]
/// The input datum for the block header chain circuit. It is used to generate a circuit.
pub struct EthBlockHeaderChainCircuit<F> {
    /// The private inputs, which are the RLP encodings of the block headers
    header_rlp_encodings: Vec<Vec<u8>>,
    num_blocks: u32, // num_blocks in [0, 2 ** max_depth)
    // The public inputs:
    // (prev_hash, end_hash, start_block_number, end_block_number, merkle_roots: [H256; max_depth + 1])
    // pub instance: EthBlockHeaderChainInstance,
    max_depth: usize,
    network: Network,
    _marker: PhantomData<F>,
}

impl<F: Field> EthBlockHeaderChainCircuit<F> {
    pub fn create_circuit(
        self,
        mut builder: RlcThreadBuilder<F>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<F, impl FnSynthesize<F>> {
        let prover = builder.witness_gen_only();
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        // KECCAK_ROWS should be set if prover = true
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();

        let ctx = builder.gate_builder.main(FIRST_PHASE);
        // ======== FIRST PHASE ===========
        // ==== Load private inputs =====
        let num_blocks = ctx.load_witness(F::from(self.num_blocks as u64));
        let num_blocks_minus_one = chip.gate().sub(ctx, num_blocks, Constant(F::one()));
        // `num_blocks_minus_one` should be < 2^max_depth. We do not check this because `num_blocks_minus_one` will equal the difference of the start, end block numbers, which are public inputs

        // ==== Load RLP encoding and decode ====
        // The block header RLPs are assigned as witnesses in this function
        let block_chain_witness = chip.decompose_block_header_chain_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            &self.header_rlp_encodings,
            self.network,
        );
        // All keccaks must be done in FirstPhase, so we compute the merkle mountain range from the RLP decoded witnesses now
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let num_leaves_bits = chip.gate().num_to_bits(ctx, num_blocks, self.max_depth + 1);
        let block_hashes = block_chain_witness
            .iter()
            .map(|witness| {
                keccak.var_len_queries[witness.block_hash_query_idx].output_assigned.clone()
            })
            .collect_vec();
        // mountain range in bytes
        let mountain_range =
            keccak.merkle_mountain_range(ctx, chip.gate(), &block_hashes, &num_leaves_bits);
        let mountain_range = mountain_range
            .into_iter()
            .zip(num_leaves_bits.into_iter().rev())
            .flat_map(|(hash_bytes, bit)| {
                // convert bytes32 to two u128
                let hash_u128s: [_; 2] =
                    bytes_be_to_u128(ctx, chip.gate(), &hash_bytes).try_into().unwrap();
                // if the bit is 0, then we set the hash root to 0
                hash_u128s.map(|hash_u128| chip.gate().mul(ctx, hash_u128, bit))
            })
            .collect_vec();

        let (prev_block_hash, end_block_hash, block_numbers) =
            get_boundary_block_data(ctx, chip.gate(), &block_chain_witness, num_blocks_minus_one);
        let assigned_instances = iter::empty()
            .chain(prev_block_hash)
            .chain(end_block_hash)
            .chain(iter::once(block_numbers))
            .chain(mountain_range)
            .collect_vec();

        let circuit = EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<F>,
                  rlp: RlpChip<F>,
                  keccak_rlcs: (FixedLenRLCs<F>, VarLenRLCs<F>)| {
                // ======== SECOND PHASE ===========
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                let _block_chain_trace = chip.decompose_block_header_chain_phase1(
                    builder,
                    block_chain_witness,
                    Some(num_blocks_minus_one),
                );
            },
        );
        if !prover {
            let config_params: EthConfigParams = serde_json::from_str(
                var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
            )
            .unwrap();
            circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
        }
        circuit
    }

    pub fn get_num_instance(max_depth: usize) -> usize {
        5 + 2 * (max_depth + 1)
    }

    #[cfg(feature = "providers")]
    pub fn from_provider(
        provider: &Provider<Http>,
        network: Network,
        start_block_number: u32,
        num_blocks: u32,
        max_depth: usize,
    ) -> Self {
        let header_rlp_max_bytes = match network {
            Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
            Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
        };
        let (mut block_rlps, instance) =
            crate::providers::get_blocks_input(provider, start_block_number, num_blocks, max_depth);
        for block_rlp in block_rlps.iter_mut() {
            block_rlp.resize(header_rlp_max_bytes, 0u8);
        }

        Self {
            header_rlp_encodings: block_rlps,
            num_blocks,
            max_depth,
            network,
            _marker: PhantomData,
        }
    }
}
