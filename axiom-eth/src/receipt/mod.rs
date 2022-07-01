use std::cmp::max;

use crate::{
    batch_query::response::ByteArray,
    block_header::EthBlockHeaderChip,
    keccak::{self, parallelize_keccak_phase0, FnSynthesize, KeccakChip},
    rlp::{
        builder::{parallelize_phase1, RlcThreadBuilder},
        max_rlp_len_len,
        rlc::{RlcChip, RlcContextPair},
        RlpChip,
    },
    transaction::TRANSACTION_IDX_MAX_LEN,
    EthChip, Field, Network,
};

use ethers_core::utils::hex::FromHex;
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateChip, GateInstructions, RangeInstructions},
    safe_types::RangeChip,
    Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use lazy_static::lazy_static;

pub mod task;
mod types;
pub use types::*;

lazy_static! {
    static ref KECCAK_RLP_EMPTY_STRING: Vec<u8> =
        Vec::from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
}

pub const RECEIPT_NUM_FIELDS: usize = 4;
pub const RECEIPT_FIELDS_LOG_INDEX: usize = 3;
pub const RECEIPT_PROOF_MAX_DEPTH: usize = 6;
pub const RECEIPT_MAX_DATA_BYTES: usize = 128;
pub const RECEIPT_MAX_LOG_NUM: usize = 6;

// this depends on the max RLP encoding length that needs to be decoded, mainly comes from MPT leaf
const CACHE_BITS: usize = 12;

pub fn calc_max_val_len(
    max_data_byte_len: usize,
    max_log_num: usize,
    (_min_topic_num, max_topic_num): (usize, usize),
) -> usize {
    let max_log_len = calc_max_log_len(max_data_byte_len, max_topic_num);
    3 + 33 + 33 + 259 + 3 + max_log_num * max_log_len
}

fn calc_max_log_len(max_data_byte_len: usize, max_topic_num: usize) -> usize {
    3 + 21 + 3 + 33 * max_topic_num + 3 + max_data_byte_len + 1
}

pub struct EthReceiptChip<'chip, F: Field> {
    pub eth: &'chip EthChip<'chip, F>,
    pub max_data_byte_len: usize,
    pub max_log_num: usize,
    pub topic_num_bounds: (usize, usize),
}

impl<'chip, F: Field> EthReceiptChip<'chip, F> {
    pub fn new(
        eth: &'chip EthChip<'chip, F>,
        max_data_byte_len: usize,
        max_log_num: usize,
        topic_num_bounds: (usize, usize),
    ) -> Self {
        Self { eth, max_data_byte_len, max_log_num, topic_num_bounds }
    }
    pub fn gate(&self) -> &GateChip<F> {
        self.eth.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.eth.range()
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.eth.rlc()
    }

    pub fn rlp(&self) -> &RlpChip<F> {
        self.eth.rlp()
    }

    pub fn keccak_fixed_len_rlcs(&self) -> &keccak::FixedLenRLCs<F> {
        self.eth.keccak_fixed_len_rlcs()
    }

    pub fn keccak_var_len_rlcs(&self) -> &keccak::VarLenRLCs<F> {
        self.eth.keccak_var_len_rlcs()
    }

    pub fn parse_receipt_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        input: EthReceiptInputAssigned<F>,
    ) -> EthReceiptTraceWitness<F> {
        let EthReceiptInputAssigned { tx_idx: transaction_index, proof } = input;
        // Load value early to avoid borrow errors
        let slot_is_empty = proof.slot_is_empty;
        // check key is rlp(idx)
        let idx_witness = self.rlp().decompose_rlp_field_phase0(
            ctx,
            proof.key_bytes.clone(),
            TRANSACTION_IDX_MAX_LEN,
        );
        let tx_idx = ByteArray::from(&idx_witness.witness);
        let tx_idx = tx_idx.evaluate(ctx, self.gate());
        ctx.constrain_equal(&tx_idx, &transaction_index);
        // check MPT inclusion
        let mpt_witness = self.eth.parse_mpt_inclusion_phase0(ctx, keccak, proof);

        // parse receipt
        // when we disable all types, we use that as a flag to parse dummy values which are two bytes long
        let type_is_not_zero =
            self.range().is_less_than(ctx, mpt_witness.value_bytes[0], Constant(F::from(128)), 8);
        // if the first byte is greater than 0xf7, the type is zero. Otherwise, the type is the first byte.
        let mut tx_type = self.gate().mul(ctx, type_is_not_zero, mpt_witness.value_bytes[0]);
        let max_val_len =
            calc_max_val_len(self.max_data_byte_len, self.max_log_num, self.topic_num_bounds);
        let mut new_value_witness = Vec::with_capacity(max_val_len);
        let slot_is_full = self.gate().not(ctx, slot_is_empty);
        tx_type = self.gate().mul(ctx, tx_type, slot_is_full);
        // tx_type = -1 if and only if the slot is empty, serves as a flag
        tx_type = self.gate().sub(ctx, tx_type, slot_is_empty);
        // parse the zeroes string if the slot is empty so that we don't run into errors
        for i in 0..max_val_len - 1 {
            let mut val_byte = self.gate().select(
                ctx,
                mpt_witness.value_bytes[i + 1],
                mpt_witness.value_bytes[i],
                type_is_not_zero,
            );
            val_byte = self.gate().mul(ctx, val_byte, slot_is_full);
            if i == 0 {
                val_byte =
                    self.gate().mul_add(ctx, Constant(F::from(193)), slot_is_empty, val_byte);
            }
            new_value_witness.push(val_byte);
        }
        let zero = ctx.load_zero();
        let mut val_byte = self.gate().select(
            ctx,
            zero,
            mpt_witness.value_bytes[max_val_len - 1],
            type_is_not_zero,
        );
        val_byte = self.gate().mul(ctx, val_byte, slot_is_full);
        new_value_witness.push(val_byte);
        // max byte length of each log
        let max_log_len = calc_max_log_len(self.max_data_byte_len, self.topic_num_bounds.1);
        // max byte length of rlp encoding of all logs
        let max_logs_rlp_len =
            1 + max_rlp_len_len(max_log_len * self.max_log_num) + max_log_len * self.max_log_num;
        let max_field_lens = [33, 33, 259, max_logs_rlp_len];
        let value =
            self.rlp().decompose_rlp_array_phase0(ctx, new_value_witness, &max_field_lens, true);
        let max_log_lens = vec![max_log_len; self.max_log_num];
        let logs = self.rlp().decompose_rlp_array_phase0(
            ctx,
            value.field_witness[RECEIPT_FIELDS_LOG_INDEX].rlp_field.clone(),
            &max_log_lens,
            true,
        );

        EthReceiptTraceWitness {
            receipt_type: tx_type,
            tx_idx,
            idx_witness,
            value,
            logs,
            mpt_witness,
        }
    }

    pub fn parse_receipt_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        w: EthReceiptTraceWitness<F>,
    ) -> EthReceiptTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), w.idx_witness);
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.eth.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), w.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let trace = self.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), w.value, true);
        let value_trace = trace.field_trace;
        self.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), w.logs, true);
        EthReceiptTrace { receipt_type: w.receipt_type, value_trace }
    }

    pub fn parse_single_receipt_field_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        input: SingleReceiptFieldInputAssigned<F>,
    ) -> EthReceiptFieldTraceWitness<F> {
        let SingleReceiptFieldInputAssigned { field_idx, log_idx, receipt: rc } = input;
        let max_log_num = self.max_log_num;
        let w = self.parse_receipt_proof_phase0(ctx, keccak, rc);
        let field_witness = w.value.field_witness.clone();
        assert_eq!(field_witness.len(), RECEIPT_NUM_FIELDS);
        let slot_is_empty = w.mpt_witness.slot_is_empty;
        let indicator = self.gate().idx_to_indicator(ctx, field_idx, RECEIPT_NUM_FIELDS);
        let zero = ctx.load_constant(F::zero());
        ctx.constrain_equal(&slot_is_empty, &zero);
        let ans_len = field_witness.iter().map(|w| w.field_cells.len()).max().unwrap();
        let mut field_bytes = Vec::with_capacity(ans_len);
        for i in 0..ans_len {
            let entries =
                field_witness.iter().map(|w| *w.field_cells.get(i).unwrap_or(&zero)).collect_vec();
            let field_byte = self.gate().select_by_indicator(ctx, entries, indicator.clone());
            field_bytes.push(field_byte);
        }
        let lens = field_witness.iter().map(|w| w.field_len).collect_vec();
        let len = self.gate().select_by_indicator(ctx, lens, indicator);

        // select log by log_idx
        let log_ind = self.gate().idx_to_indicator(ctx, log_idx, max_log_num);
        assert_eq!(w.logs.field_witness.len(), max_log_num);
        let max_log_len = w.logs.field_witness[0].max_field_len;
        let mut log = vec![];
        for i in 0..max_log_len {
            let byte = self.gate().select_by_indicator(
                ctx,
                w.logs.field_witness.iter().map(|w| w.rlp_field[i]),
                log_ind.clone(),
            );
            log.push(byte);
        }
        let log_len = self.gate().select_by_indicator(
            ctx,
            w.logs.field_witness.iter().map(|w| w.rlp_field_len),
            log_ind,
        );

        let val_len = max(field_bytes.len(), log.len());
        field_bytes.resize(val_len, zero);
        log.resize(val_len, zero);
        let sel_log = self.gate().is_equal(
            ctx,
            field_idx,
            Constant(F::from(RECEIPT_FIELDS_LOG_INDEX as u64)),
        );

        // value = field_idx == LOG_INDEX ? log : field_bytes
        let value_len = self.gate().select(ctx, log_len, len, sel_log);
        let value_bytes = log
            .into_iter()
            .zip(field_bytes)
            .map(|(log, val)| self.gate().select(ctx, log, val, sel_log))
            .collect_vec();

        EthReceiptFieldTraceWitness {
            receipt_witness: w,
            field_idx,
            log_idx,
            value_bytes,
            value_len,
            max_len: ans_len,
        }
    }

    pub fn parse_single_receipt_field_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthReceiptFieldTraceWitness<F>,
    ) {
        let _transaction_trace =
            self.parse_receipt_proof_phase1((ctx_gate, ctx_rlc), witness.receipt_witness);
    }

    pub fn parse_single_receipt_field_from_block_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        input: BlockReceiptFieldInputAssigned<F>,
        network: Network,
    ) -> EthBlockReceiptFieldTraceWitness<F> {
        // let (header_max_len, _) = get_block_header_rlp_max_lens(network);
        // let mut block_header_rlp = input.block_header_rlp.to_vec();
        // block_header_rlp.resize(header_max_len, 0u8);
        let block_header_rlp = input.block_header_rlp.to_vec();
        let block = self.eth.decompose_block_header_phase0(ctx, keccak, &block_header_rlp, network);
        let receipt_root = &block.get_receipts_root().field_cells;
        for (pf_byte, byte) in
            input.single_field.receipt.proof.root_hash_bytes.iter().zip_eq(receipt_root.iter())
        {
            ctx.constrain_equal(pf_byte, byte);
        }
        let receipt = self.parse_single_receipt_field_phase0(ctx, keccak, input.single_field);
        EthBlockReceiptFieldTraceWitness { block, receipt }
    }

    pub fn parse_single_receipt_field_from_block_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthBlockReceiptFieldTraceWitness<F>,
    ) -> EthBlockReceiptFieldTrace<F> {
        let block_trace =
            self.eth.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness.block);
        let rc_witness = witness.receipt;
        self.parse_single_receipt_field_phase1((ctx_gate, ctx_rlc), rc_witness);
        EthBlockReceiptFieldTrace { block_trace }
    }

    pub fn parse_receipt_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        receipt_witness: Vec<EthReceiptTraceWitness<F>>,
    ) -> Vec<EthReceiptTrace<F>> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);
        parallelize_phase1(thread_pool, receipt_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_receipt_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    pub fn parse_receipt_field_from_blocks_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: Vec<BlockReceiptFieldInputAssigned<F>>,
        network: Network,
    ) -> Vec<EthBlockReceiptFieldTraceWitness<F>> {
        parallelize_keccak_phase0(thread_pool, keccak, input, |ctx, keccak, input| {
            self.parse_single_receipt_field_from_block_phase0(ctx, keccak, input, network)
        })
    }

    pub fn parse_receipt_field_from_blocks_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: Vec<EthBlockReceiptFieldTraceWitness<F>>,
    ) {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);
        parallelize_phase1(thread_pool, witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_single_receipt_field_from_block_phase1((ctx_gate, ctx_rlc), witness)
        });
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptCircuit {
    pub inputs: EthBlockReceiptInput, // public and private inputs
    pub network: Network,
}
