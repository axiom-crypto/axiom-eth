//! See https://hackmd.io/@axiom/H1TYkiBt2 for receipt data format

use crate::{
    block_header::EthBlockHeaderChip,
    keccak::KeccakChip,
    mpt::MPTChip,
    rlc::{
        chip::RlcChip,
        circuit::builder::{RlcCircuitBuilder, RlcContextPair},
    },
    rlp::{evaluate_byte_array, max_rlp_len_len, RlpChip},
    transaction::TRANSACTION_IDX_MAX_LEN,
    utils::circuit_utils::constrain_no_leading_zeros,
};

use ethers_core::types::Chain;
use halo2_base::{
    gates::{
        flex_gate::threads::parallelize_core, GateChip, GateInstructions, RangeChip,
        RangeInstructions,
    },
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use itertools::Itertools;

//pub mod task;
#[cfg(all(test, feature = "providers"))]
pub mod tests;
mod types;
use crate::Field;
use serde::{Deserialize, Serialize};
pub use types::*;

pub const RECEIPT_NUM_FIELDS: usize = 4;
pub const RECEIPT_FIELDS_LOG_INDEX: usize = 3;

pub fn calc_max_val_len(
    max_data_byte_len: usize,
    max_log_num: usize,
    (_min_topic_num, max_topic_num): (usize, usize),
) -> usize {
    let max_log_len = calc_max_log_len(max_data_byte_len, max_topic_num);
    4 + 33 + 33 + 259 + 4 + max_log_num * max_log_len
}

fn calc_max_log_len(max_data_byte_len: usize, max_topic_num: usize) -> usize {
    3 + 21 + 3 + 33 * max_topic_num + 3 + max_data_byte_len + 1
}

/// Configuration parameters for [EthReceiptChip]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Hash, Default)]
pub struct EthReceiptChipParams {
    pub max_data_byte_len: usize,
    pub max_log_num: usize,
    pub topic_num_bounds: (usize, usize), // min, max
    /// Must be provided if using functions involving block header
    pub network: Option<Chain>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptChip<'chip, F: Field> {
    pub mpt: &'chip MPTChip<'chip, F>,
    pub params: EthReceiptChipParams,
}

impl<'chip, F: Field> EthReceiptChip<'chip, F> {
    pub fn new(mpt: &'chip MPTChip<'chip, F>, params: EthReceiptChipParams) -> Self {
        Self { mpt, params }
    }
    pub fn gate(&self) -> &GateChip<F> {
        self.mpt.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.mpt.range()
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.mpt.rlc()
    }

    pub fn rlp(&self) -> RlpChip<F> {
        self.mpt.rlp()
    }

    pub fn keccak(&self) -> &KeccakChip<F> {
        self.mpt.keccak()
    }

    pub fn mpt(&self) -> &'chip MPTChip<'chip, F> {
        self.mpt
    }

    pub fn network(&self) -> Option<Chain> {
        self.params.network
    }

    pub fn block_header_chip(&self) -> EthBlockHeaderChip<F> {
        EthBlockHeaderChip::new_from_network(
            self.rlp(),
            self.network().expect("Must provide network to access block header chip"),
        )
    }

    /// FirstPhase of proving the inclusion **or** exclusion of a transaction index within a receipt root.
    /// In the case of
    /// - inclusion: then parses the receipt
    /// - exclusion: `input.proof.slot_is_empty` is true, and we return `tx_type = -1, value = rlp(0x00)`.
    pub fn parse_receipt_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        input: EthReceiptInputAssigned<F>,
    ) -> EthReceiptWitness<F> {
        let EthReceiptChipParams { max_data_byte_len, max_log_num, topic_num_bounds, .. } =
            self.params;
        let EthReceiptInputAssigned { tx_idx: transaction_index, proof } = input;
        // Load value early to avoid borrow errors
        let slot_is_empty = proof.slot_is_empty;
        // check key is rlp(idx)
        let idx_witness = self.rlp().decompose_rlp_field_phase0(
            ctx,
            proof.key_bytes.clone(),
            TRANSACTION_IDX_MAX_LEN,
        );
        let tx_idx =
            evaluate_byte_array(ctx, self.gate(), &idx_witness.field_cells, idx_witness.field_len);
        ctx.constrain_equal(&tx_idx, &transaction_index);
        constrain_no_leading_zeros(
            ctx,
            self.gate(),
            &idx_witness.field_cells,
            idx_witness.field_len,
        );

        // check MPT inclusion
        let mpt_witness = self.mpt.parse_mpt_inclusion_phase0(ctx, proof);

        // parse receipt
        // when we disable all types, we use that as a flag to parse dummy values which are two bytes long
        let type_is_not_zero =
            self.range().is_less_than(ctx, mpt_witness.value_bytes[0], Constant(F::from(128)), 8);
        // if the first byte is greater than 0xf7, the type is zero. Otherwise, the type is the first byte.
        let mut tx_type = self.gate().mul(ctx, type_is_not_zero, mpt_witness.value_bytes[0]);
        let max_val_len = calc_max_val_len(max_data_byte_len, max_log_num, topic_num_bounds);
        let mut new_value_witness = Vec::with_capacity(max_val_len);
        let slot_is_full = self.gate().not(ctx, slot_is_empty);
        tx_type = self.gate().mul(ctx, tx_type, slot_is_full);
        // tx_type = -1 if and only if the slot is empty, serves as a flag
        tx_type = self.gate().sub(ctx, tx_type, slot_is_empty);
        // parse the zeroes string if the slot is empty so that we don't run into errors
        for i in 0..max_val_len {
            let mut val_byte = self.gate().select(
                ctx,
                mpt_witness
                    .value_bytes
                    .get(i + 1)
                    .map(|a| Existing(*a))
                    .unwrap_or(Constant(F::ZERO)),
                mpt_witness.value_bytes[i],
                type_is_not_zero,
            );
            val_byte = if i == 0 {
                // 0xc100 = rlp(0x00)
                self.gate().select(ctx, val_byte, Constant(F::from(0xc1)), slot_is_full)
            } else {
                self.gate().mul(ctx, val_byte, slot_is_full)
            };
            new_value_witness.push(val_byte);
        }
        // max byte length of each log
        let max_log_len = calc_max_log_len(max_data_byte_len, topic_num_bounds.1);
        // max byte length of rlp encoding of all logs
        let max_logs_rlp_len =
            1 + max_rlp_len_len(max_log_len * max_log_num) + max_log_len * max_log_num;
        let max_field_lens = [33, 33, 259, max_logs_rlp_len];
        let value =
            self.rlp().decompose_rlp_array_phase0(ctx, new_value_witness, &max_field_lens, true);
        let max_log_lens = vec![max_log_len; max_log_num];
        let logs = self.rlp().decompose_rlp_array_phase0(
            ctx,
            value.field_witness[RECEIPT_FIELDS_LOG_INDEX].encoded_item.clone(),
            &max_log_lens,
            true,
        );

        EthReceiptWitness { receipt_type: tx_type, tx_idx, idx_witness, value, logs, mpt_witness }
    }

    /// SecondPhase of proving inclusion **or** exclusion of a transaction index in receipt root, and then parses
    /// the receipt. See [`parse_receipt_proof_phase0`] for more details.
    pub fn parse_receipt_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthReceiptWitness<F>,
    ) -> EthReceiptTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness.idx_witness);
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.mpt.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let trace = self.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.value, true);
        let value_trace = trace.field_trace;
        self.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.logs, true);
        EthReceiptTrace { receipt_type: witness.receipt_type, value_trace }
    }

    /// Parallelizes `parse_receipt_proof_phase0`.
    pub fn parse_receipt_proofs_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<EthReceiptInputAssigned<F>>,
    ) -> Vec<EthReceiptWitness<F>> {
        parallelize_core(builder.base.pool(0), input, |ctx, input| {
            self.parse_receipt_proof_phase0(ctx, input)
        })
    }

    /// Parallelizes `parse_receipt_proof_phase1`
    pub fn parse_receipt_proofs_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        receipt_witness: Vec<EthReceiptWitness<F>>,
    ) -> Vec<EthReceiptTrace<F>> {
        // load rlc cache should be done globally; no longer done here
        builder.parallelize_phase1(receipt_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_receipt_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    /// Extracts the field at `field_idx` from the given rlp decomposition of a receipt.
    pub fn extract_receipt_field(
        &self,
        ctx: &mut Context<F>,
        witness: &EthReceiptWitness<F>,
        field_idx: AssignedValue<F>,
    ) -> EthReceiptFieldWitness<F> {
        let zero = ctx.load_zero();
        let field_witness = &witness.value.field_witness;
        assert_eq!(field_witness.len(), RECEIPT_NUM_FIELDS);
        let ans_len = field_witness.iter().map(|w| w.field_cells.len()).max().unwrap();
        let mut value_bytes = Vec::with_capacity(ans_len);
        let indicator = self.gate().idx_to_indicator(ctx, field_idx, RECEIPT_NUM_FIELDS);
        for i in 0..ans_len {
            let entries =
                field_witness.iter().map(|w| *w.field_cells.get(i).unwrap_or(&zero)).collect_vec();
            let byte = self.gate().select_by_indicator(ctx, entries, indicator.clone());
            value_bytes.push(byte);
        }
        let lens = field_witness.iter().map(|w| w.field_len).collect_vec();
        let value_len = self.gate().select_by_indicator(ctx, lens, indicator);
        EthReceiptFieldWitness { field_idx, value_bytes, value_len }
    }

    /// Extracts the log at `log_idx` from the given rlp decomposition of a receipt.
    pub fn extract_receipt_log(
        &self,
        ctx: &mut Context<F>,
        witness: &EthReceiptWitness<F>,
        log_idx: AssignedValue<F>,
    ) -> EthReceiptLogWitness<F> {
        let zero = ctx.load_zero();
        let max_log_num = self.params.max_log_num;
        // select log by log_idx
        let log_ind = self.gate().idx_to_indicator(ctx, log_idx, max_log_num);
        let logs = &witness.logs.field_witness;
        assert_eq!(witness.logs.field_witness.len(), max_log_num);
        let max_log_len = logs.iter().map(|w| w.max_field_len).max().unwrap();
        let mut log_bytes = Vec::with_capacity(max_log_len);
        for i in 0..max_log_len {
            let byte = self.gate().select_by_indicator(
                ctx,
                logs.iter().map(|w| *w.encoded_item.get(i).unwrap_or(&zero)),
                log_ind.clone(),
            );
            log_bytes.push(byte);
        }
        let log_len =
            self.gate().select_by_indicator(ctx, logs.iter().map(|w| w.encoded_item_len), log_ind);

        EthReceiptLogWitness { log_idx, log_len, log_bytes }
    }
}
