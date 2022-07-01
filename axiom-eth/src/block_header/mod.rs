use crate::Field;
use crate::{
    keccak::{types::KeccakVarLenQuery, KeccakChip},
    rlc::{
        chip::RlcChip,
        circuit::builder::{RlcCircuitBuilder, RlcContextPair},
        types::RlcTrace,
    },
    rlp::{
        evaluate_byte_array, max_rlp_encoding_len,
        types::{RlpArrayWitness, RlpFieldTrace, RlpFieldWitness},
        RlpChip,
    },
    utils::{bytes_be_to_u128, AssignedH256},
};
use core::iter::once;
use ethers_core::types::Chain;
use halo2_base::{
    gates::{
        flex_gate::threads::parallelize_core, GateChip, GateInstructions, RangeChip,
        RangeInstructions,
    },
    safe_types::{left_pad_var_array_to_fixed, FixLenBytes, SafeTypeChip},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use itertools::Itertools;

#[cfg(test)]
mod tests;

// extra data max byte length is different for different networks
pub const MAINNET_EXTRA_DATA_MAX_BYTES: usize = 32;
pub const GOERLI_EXTRA_DATA_MAX_BYTES: usize = 300;

/// This is the minimum possible RLP byte length of a block header *at any block* (including pre EIPs)
pub const BLOCK_HEADER_RLP_MIN_BYTES: usize = 479;

pub const MIN_NUM_BLOCK_HEADER_FIELDS: usize = 15;
pub const NUM_BLOCK_HEADER_FIELDS: usize = 20;
pub const MAINNET_HEADER_FIELDS_MAX_BYTES: [usize; NUM_BLOCK_HEADER_FIELDS] = [
    32,                           // parent_hash
    32,                           // ommers_hash
    20,                           // coinbase [beneficiary]
    32,                           // state_root
    32,                           // txs_root
    32,                           // receipts_root
    256,                          // logs_bloom
    7,                            // difficulty
    4,                            // number
    4,                            // gas_limit
    4,                            // gas_used
    4,                            // timestamp
    MAINNET_EXTRA_DATA_MAX_BYTES, // extradata
    32,                           // mix_hash or prev_randao
    8,                            // nonce
    32,                           // base_fee_per_gas
    32,                           // withdrawals_root
    8,                            // data_gas_used
    8,                            // excess_data_gas
    32,                           // parent_beacon_block_root
];
pub const BLOCK_HEADER_FIELD_IS_VAR_LEN: [bool; NUM_BLOCK_HEADER_FIELDS] = [
    false, false, false, false, false, false, false, true, true, true, true, true, true, false,
    false, true, false, true, true, false,
];
/// The maximum number of bytes it takes to represent a block number, without any RLP encoding.
pub const BLOCK_NUMBER_MAX_BYTES: usize = MAINNET_HEADER_FIELDS_MAX_BYTES[BLOCK_NUMBER_INDEX];
pub const STATE_ROOT_INDEX: usize = 3;
pub const TX_ROOT_INDEX: usize = 4;
pub const RECEIPT_ROOT_INDEX: usize = 5;
pub const LOGS_BLOOM_INDEX: usize = 6;
pub const BLOCK_NUMBER_INDEX: usize = 8;
pub const EXTRA_DATA_INDEX: usize = 12;
pub const WITHDRAWALS_ROOT_INDEX: usize = 16;

/**
| Field                        | Type            | Size (bytes)    | RLP size (bytes) | RLP size (bits) |
|------------------------------|-----------------|-----------------|------------------|-----------------|
| parentHash                   | 256 bits        | 32              | 33               | 264             |
| ommersHash                   | 256 bits        | 32              | 33               | 264             |
| beneficiary                  | 160 bits        | 20              | 21               | 168             |
| stateRoot                    | 256 bits        | 32              | 33               | 264             |
| transactionsRoot             | 256 bits        | 32              | 33               | 264             |
| receiptsRoot                 | 256 bits        | 32              | 33               | 264             |
| logsBloom                    | 256 bytes       | 256             | 259              | 2072            |
| difficulty                   | big int scalar  | variable        | 8                | 64              |
| number                       | big int scalar  | variable        | <= 5             | <= 40           |
| gasLimit                     | big int scalar  | variable        | 5                | 40              |
| gasUsed                      | big int scalar  | variable        | <= 5             | <= 40           |
| timestamp                    | big int scalar  | variable        | 5                | 40              |
| extraData (Mainnet)          | up to 256 bits  | variable, <= 32 | <= 33            | <= 264          |
| mixHash                      | 256 bits        | 32              | 33               | 264             |
| nonce                        | 64 bits         | 8               | 9                | 72              |
| basefee (post-1559)          | big int scalar  | variable, <=32  | <= 33            | <= 264          |
| withdrawalsRoot (post-4895)  | 256 bits        | 32              | 33               | 264             |
| blobGasUsed (post-4844)      | 64 bits         | <= 8            | <= 9             | <= 72           |
| excessBlobGas (post-4844)    | 64 bits         | <= 8            | <= 9             | <= 72           |
| parentBeaconBlockRoot (post-4788) | 256 bits   | 32              | 33               | 264             |
*/
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
    pub basefee: RlpFieldTrace<F>, // this is 0 (or undefined) for pre-EIP1559 (London) blocks
    pub withdrawals_root: RlpFieldTrace<F>, // this is 0 (or undefined) for pre-EIP4895 (Shapella) blocks (before block number 1681338455)
    // the user will have to separately determine whether the block is EIP1559 or not
    pub block_hash: KeccakVarLenQuery<F>,

    // pub prefix: AssignedValue<F>,
    pub len_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockHeaderWitness<F: Field> {
    pub rlp_witness: RlpArrayWitness<F>,
    pub block_hash: KeccakVarLenQuery<F>,
}

impl<F: Field> EthBlockHeaderWitness<F> {
    /// Returns block number as bytes4 (left padded with zeros, big endian)
    pub fn get_number_fixed(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> FixLenBytes<F, BLOCK_NUMBER_MAX_BYTES> {
        let block_num_bytes = &self.get_number().field_cells;
        let block_num_len = self.get_number().field_len;
        SafeTypeChip::unsafe_to_fix_len_bytes(
            left_pad_var_array_to_fixed(
                ctx,
                gate,
                block_num_bytes,
                block_num_len,
                BLOCK_NUMBER_MAX_BYTES,
            )
            .try_into()
            .unwrap(),
        )
    }
    /// Returns block number as a field element
    pub fn get_number_value(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> AssignedValue<F> {
        let block_num_bytes = &self.get_number().field_cells;
        let block_num_len = self.get_number().field_len;
        evaluate_byte_array(ctx, gate, block_num_bytes, block_num_len)
    }
    pub fn get_block_hash_hi_lo(&self) -> AssignedH256<F> {
        self.block_hash.hi_lo()
    }
    pub fn get_parent_hash(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[0]
    }
    pub fn get_ommers_hash(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[1]
    }
    pub fn get_beneficiary(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[2]
    }
    pub fn get_state_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[3]
    }
    pub fn get_transactions_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[4]
    }
    pub fn get_receipts_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[5]
    }
    pub fn get_logs_bloom(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[6]
    }
    pub fn get_difficulty(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[7]
    }
    pub fn get_number(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[8]
    }
    pub fn get_gas_limit(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[9]
    }
    pub fn get_gas_used(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[10]
    }
    pub fn get_timestamp(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[11]
    }
    pub fn get_extra_data(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[12]
    }
    pub fn get_mix_hash(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[13]
    }
    pub fn get_nonce(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[14]
    }
    pub fn get_basefee(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[15]
    }
    pub fn get_withdrawals_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[16]
    }
    pub fn get_index(&self, idx: usize) -> Option<&RlpFieldWitness<F>> {
        self.rlp_witness.field_witness.get(idx)
    }
    /// Returns the number of fields in the block header
    pub fn get_list_len(&self) -> AssignedValue<F> {
        self.rlp_witness.list_len.unwrap()
    }
}

pub struct EthBlockHeaderChip<'chip, F: Field> {
    pub rlp: RlpChip<'chip, F>,
    pub max_extra_data_bytes: usize,
}

impl<'chip, F: Field> EthBlockHeaderChip<'chip, F> {
    pub fn new(rlp: RlpChip<'chip, F>, max_extra_data_bytes: usize) -> Self {
        Self { rlp, max_extra_data_bytes }
    }

    pub fn new_from_network(rlp: RlpChip<'chip, F>, chain: Chain) -> Self {
        let max_extra_data_bytes = get_block_header_extra_bytes(chain);
        Self { rlp, max_extra_data_bytes }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.rlp.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.rlp.range()
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.rlp.rlc()
    }

    pub fn rlp(&self) -> &RlpChip<F> {
        &self.rlp
    }

    /// Takes the variable length RLP encoded block header, padded with 0s to the maximum possible block header RLP length, and outputs the decomposition into block header fields.
    ///
    /// This function _will_ range check that `block_header` consists of bytes (8 bits).
    ///
    /// In addition, the keccak block hash of the block is calculated.
    ///
    /// This is the preparation step that computes the witnesses. This MUST be done in `FirstPhase`.
    /// The accompanying `decompose_block_header_phase1` must be called in `SecondPhase` to constrain the RLCs associated to the RLP decoding.
    pub fn decompose_block_header_phase0(
        &self,
        ctx: &mut Context<F>, // ctx_gate in FirstPhase
        keccak: &KeccakChip<F>,
        block_header: &[AssignedValue<F>],
    ) -> EthBlockHeaderWitness<F> {
        let (max_len, max_field_lens) =
            get_block_header_rlp_max_lens_from_extra(self.max_extra_data_bytes);
        assert_eq!(block_header.len(), max_len);
        // range check that block_header consists of bytes
        for b in block_header {
            self.range().range_check(ctx, *b, 8);
        }

        let rlp_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            block_header.to_vec(),
            &max_field_lens,
            true,
        ); // `is_variable_len = true` because RLP can have >=15 fields, depending on which EIPs are active at that block

        let block_hash = keccak.keccak_var_len(
            ctx,
            rlp_witness.rlp_array.clone(), // this is `block_header_assigned`
            rlp_witness.rlp_len,
            BLOCK_HEADER_RLP_MIN_BYTES,
        );
        EthBlockHeaderWitness { rlp_witness, block_hash }
    }

    /// Takes the variable length RLP encoded block header, padded with 0s to the maximum possible block header RLP length, and outputs the decomposition into block header fields.
    ///
    /// In addition, the keccak block hash of the block is calculated.
    ///
    /// This is the finalization step that constrains RLC concatenations.
    /// This should be called after `decompose_block_header_phase0`.
    /// This MUST be done in `SecondPhase`.
    pub fn decompose_block_header_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthBlockHeaderWitness<F>,
    ) -> EthBlockHeaderTrace<F> {
        let trace = self.rlp().decompose_rlp_array_phase1(ctx, witness.rlp_witness, true);
        let block_hash = witness.block_hash;

        // Base fee per unit gas only after London
        let [parent_hash, ommers_hash, beneficiary, state_root, transactions_root, receipts_root, logs_bloom, difficulty, number, gas_limit, gas_used, timestamp, extra_data, mix_hash, nonce, basefee, withdrawals_root, ..]: [RlpFieldTrace<F>; NUM_BLOCK_HEADER_FIELDS] =
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
            withdrawals_root,
            block_hash,
            len_trace: trace.len_trace,
        }
    }

    /// Makes multiple calls to `decompose_block_header_phase0` in parallel threads. Should be called in FirstPhase.
    pub fn decompose_block_headers_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        keccak: &KeccakChip<F>,
        block_headers: Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<EthBlockHeaderWitness<F>> {
        parallelize_core(builder.base.pool(0), block_headers, |ctx, block_header| {
            self.decompose_block_header_phase0(ctx, keccak, &block_header)
        })
    }

    /// Makes multiple calls to `decompose_block_header_phase1` in parallel threads. Should be called in SecondPhase.
    pub fn decompose_block_headers_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        witnesses: Vec<EthBlockHeaderWitness<F>>,
    ) -> Vec<EthBlockHeaderTrace<F>> {
        assert!(!witnesses.is_empty());
        // `load_rlc_cache` no longer called here: it should be called globally when `RlcCircuitBuilder` is constructed
        builder.parallelize_phase1(witnesses, |(ctx_gate, ctx_rlc), witness| {
            self.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    /// Takes a list of (purported) RLP encoded block headers and
    /// decomposes each header into it's fields.
    /// `headers[0]` is the earliest block.
    ///
    /// This is the preparation step that computes the witnesses. This MUST be done in `FirstPhase`.
    /// The accompanying `decompose_block_header_chain_phase1` must be called in `SecondPhase` to constrain the RLCs associated to the RLP decoding.
    pub fn decompose_block_header_chain_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        keccak: &KeccakChip<F>,
        block_headers: Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<EthBlockHeaderWitness<F>> {
        self.decompose_block_headers_phase0(builder, keccak, block_headers)
    }

    /// Takes a list of `2^max_depth` (purported) RLP encoded block headers.
    /// Decomposes each header into it's fields.
    /// `headers[0]` is the earliest block
    ///
    /// - If `num_blocks_minus_one = (num_blocks_minus_one, indicator)` is not None, then the circuit checks that the first `num_blocks := num_blocks_minus_one + 1` block headers form a chain: meaning that the parent hash of block i + 1 equals the hash of block i.
    /// - `indicator` is a vector with index `i` equal to `i == num_blocks - 1 ? 1 : 0`.
    /// - Otherwise if `num_blocks` is None, the circuit checks that all `headers` form a hash chain.
    ///
    /// Assumes that `0 <= num_blocks_minus_one < 2^max_depth`.
    ///
    /// This is the finalization step that constrains RLC concatenations. In this step the hash chain is actually constrained.
    /// This should be called after `decompose_block_header_chain_phase0`.
    /// This MUST be done in `SecondPhase`.
    pub fn decompose_block_header_chain_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        witnesses: Vec<EthBlockHeaderWitness<F>>,
        num_blocks_minus_one: Option<(AssignedValue<F>, Vec<AssignedValue<F>>)>,
    ) -> Vec<EthBlockHeaderTrace<F>> {
        assert!(!witnesses.is_empty());
        let traces = self.decompose_block_headers_phase1(builder, witnesses);
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        let thirty_two = F::from(32);
        // record for each idx whether hash of headers[idx] is in headers[idx + 1]
        if let Some((num_blocks_minus_one, indicator)) = num_blocks_minus_one {
            let mut hash_checks = Vec::with_capacity(traces.len() - 1);
            for idx in 0..traces.len() - 1 {
                let block_hash_bytes = traces[idx].block_hash.output_bytes.as_ref().iter().copied();
                let block_hash = self.rlc().compute_rlc_fixed_len(ctx_rlc, block_hash_bytes);
                let hash_check = self.gate().is_equal(
                    ctx_gate,
                    block_hash.rlc_val,
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
            let hash_check_sum = self.gate().select_by_indicator(
                ctx_gate,
                once(Constant(F::ZERO)).chain(hash_check_sums.into_iter().map(Existing)),
                indicator,
            );
            ctx_gate.constrain_equal(&hash_check_sum, &num_blocks_minus_one);
        } else {
            for idx in 0..traces.len() - 1 {
                let block_hash_bytes = traces[idx].block_hash.output_bytes.as_ref().iter().copied();
                let block_hash = self.rlc().compute_rlc_fixed_len(ctx_rlc, block_hash_bytes);
                ctx_gate.constrain_equal(
                    &block_hash.rlc_val,
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
/// `indicator` is the indicator for `num_blocks_minus_one`, where `indicator[i] = (i == end_block_number - start_block_number ? 1 : 0)`.
///
/// This function should be called in `FirstPhase`.
pub fn get_boundary_block_data<F: Field>(
    ctx: &mut Context<F>, // ctx_gate in FirstPhase
    gate: &impl GateInstructions<F>,
    chain: &[EthBlockHeaderWitness<F>],
    indicator: &[AssignedValue<F>],
) -> ([AssignedValue<F>; 2], [AssignedValue<F>; 2], AssignedValue<F>) {
    let parent_hash_bytes = SafeTypeChip::unsafe_to_fix_len_bytes_vec(
        chain[0].get_parent_hash().field_cells.clone(),
        32,
    );
    let prev_block_hash: [_; 2] =
        bytes_be_to_u128(ctx, gate, parent_hash_bytes.bytes()).try_into().unwrap();
    let end_block_hash: [_; 2] = [0, 1].map(|idx| {
        gate.select_by_indicator(
            ctx,
            chain.iter().map(|header| header.block_hash.hi_lo()[idx]),
            indicator.iter().copied(),
        )
    });

    // start_block_number || end_block_number
    let block_numbers = {
        debug_assert_eq!(chain[0].get_number().max_field_len, BLOCK_NUMBER_MAX_BYTES);
        let start_block_number_bytes = chain[0].get_number_fixed(ctx, gate);
        let end_block_number_bytes = {
            // TODO: is there a way to do this without so many selects
            let bytes: [_; BLOCK_NUMBER_MAX_BYTES] = core::array::from_fn(|i| i).map(|idx| {
                gate.select_by_indicator(
                    ctx,
                    chain.iter().map(|header| header.get_number().field_cells[idx]),
                    indicator.iter().copied(),
                )
            });
            let len = gate.select_by_indicator(
                ctx,
                chain.iter().map(|header| header.get_number().field_len),
                indicator.iter().copied(),
            );
            let var_bytes = SafeTypeChip::unsafe_to_var_len_bytes(bytes, len);
            var_bytes.left_pad_to_fixed(ctx, gate)
        };
        let block_numbers_bytes =
            [start_block_number_bytes.into_bytes(), end_block_number_bytes.into_bytes()].concat();
        let [block_numbers]: [_; 1] =
            bytes_be_to_u128(ctx, gate, &block_numbers_bytes).try_into().unwrap();
        block_numbers
    };

    (prev_block_hash, end_block_hash, block_numbers)
}

pub fn get_block_header_rlp_max_lens(chain: Chain) -> (usize, [usize; NUM_BLOCK_HEADER_FIELDS]) {
    get_block_header_rlp_max_lens_from_chain_id(chain as u64)
}

pub fn get_block_header_rlp_max_lens_from_extra(
    max_extra_data_bytes: usize,
) -> (usize, [usize; NUM_BLOCK_HEADER_FIELDS]) {
    let mut field_lens = [0usize; NUM_BLOCK_HEADER_FIELDS];
    for (a, b) in field_lens.iter_mut().zip_eq(MAINNET_HEADER_FIELDS_MAX_BYTES.iter()) {
        *a = *b;
    }
    field_lens[EXTRA_DATA_INDEX] = max_extra_data_bytes;
    let mut list_payload_len = 0;
    for &field_len in &field_lens {
        list_payload_len += max_rlp_encoding_len(field_len);
    }
    let rlp_len = max_rlp_encoding_len(list_payload_len);
    (rlp_len, field_lens)
}

pub fn get_block_header_extra_bytes(chain: Chain) -> usize {
    get_block_header_extra_bytes_from_chain_id(chain as u64)
}

pub fn get_block_header_rlp_max_lens_from_chain_id(
    chain_id: u64,
) -> (usize, [usize; NUM_BLOCK_HEADER_FIELDS]) {
    let max_extra_data_bytes = get_block_header_extra_bytes_from_chain_id(chain_id);
    get_block_header_rlp_max_lens_from_extra(max_extra_data_bytes)
}

pub fn get_block_header_extra_bytes_from_chain_id(chain_id: u64) -> usize {
    match chain_id {
        5 => GOERLI_EXTRA_DATA_MAX_BYTES,
        _ => MAINNET_EXTRA_DATA_MAX_BYTES, // for now everything besides Goerli assumed to be mainnet equivalent
    }
}

/// RLP of block number 0 on mainnet
pub const GENESIS_BLOCK_RLP: &[u8] = &[
    249, 2, 20, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212,
    26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 215, 248, 151, 79, 181, 172, 120, 217,
    172, 9, 155, 154, 213, 1, 139, 237, 194, 206, 10, 114, 218, 209, 130, 122, 23, 9, 218, 48, 88,
    15, 5, 68, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91,
    72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 86, 232, 31, 23, 27,
    204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1,
    98, 47, 181, 227, 99, 180, 33, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 4, 0, 0, 0, 0, 128, 130, 19, 136, 128, 128, 160,
    17, 187, 232, 219, 78, 52, 123, 78, 140, 147, 124, 28, 131, 112, 228, 181, 237, 51, 173, 179,
    219, 105, 203, 219, 122, 56, 225, 229, 11, 27, 130, 250, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0, 0, 0, 0, 66,
];
