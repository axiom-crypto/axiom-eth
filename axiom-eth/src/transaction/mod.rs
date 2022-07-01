use crate::{
    batch_query::response::ByteArray,
    block_header::{
        get_block_header_rlp_max_lens, EthBlockHeaderChip, EthBlockHeaderTrace,
        EthBlockHeaderTraceWitness,
    },
    keccak::{
        self, parallelize_keccak_phase0, ContainsParallelizableKeccakQueries, FixedLenRLCs,
        FnSynthesize, KeccakChip, VarLenRLCs,
    },
    mpt::{MPTInput, MPTProof, MPTProofWitness},
    rlp::{
        builder::{parallelize_phase1, RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::{RlcChip, RlcContextPair, FIRST_PHASE},
        RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldTraceWitness,
    },
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, Network, ETH_LOOKUP_BITS,
};
use ethers_core::{
    types::{Block, Transaction, H256},
    utils::hex::FromHex,
};
#[cfg(feature = "providers")]
use ethers_providers::{JsonRpcClient, Provider};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    utils::bit_length,
    AssignedValue, Context,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, cmp::max};

pub mod helpers;
#[cfg(all(test, feature = "providers"))]
mod tests;
mod types;

pub use types::*;

lazy_static! {
    static ref KECCAK_RLP_EMPTY_STRING: Vec<u8> =
        Vec::from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
}

pub(crate) const TRANSACTION_PROOF_VALUE_MAX_BYTE_LEN_BASE: usize = 400;
pub(crate) const TRANSACTION_TYPE_0_FIELDS: usize = 9;
pub(crate) const TRANSACTION_TYPE_0_FIELDS_MAX_BYTES: [usize; TRANSACTION_TYPE_2_FIELDS] =
    [32, 32, 32, 20, 32, 0, 8, 32, 32, 1, 1, 1];
pub(crate) const TRANSACTION_TYPE_1_FIELDS: usize = 11;
pub(crate) const TRANSACTION_TYPE_1_FIELDS_MAX_BYTES: [usize; TRANSACTION_TYPE_2_FIELDS] =
    [8, 32, 32, 32, 20, 32, 0, 0, 1, 32, 32, 1];
pub(crate) const TRANSACTION_TYPE_2_FIELDS: usize = 12;
pub(crate) const TRANSACTION_TYPE_2_FIELDS_MAX_BYTES: [usize; TRANSACTION_TYPE_2_FIELDS] =
    [8, 8, 8, 8, 32, 20, 32, 0, 0, 1, 32, 32];
pub(crate) const TRANSACTION_FIELDS_MAX_BYTES: [usize; TRANSACTION_TYPE_2_FIELDS] =
    [32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32];
pub(crate) const TRANSACTION_FIELD_IS_VAR_LEN: [bool; TRANSACTION_TYPE_2_FIELDS] =
    [true; TRANSACTION_TYPE_2_FIELDS];
pub(crate) const TRANSACTION_IDX_MAX_LEN: usize = 2;

// This depends on the max RLP encoding length that needs to be decoded, mainly comes from MPT leaf
const CACHE_BITS: usize = 12; // 10 is enough for current configuration, 12 for safety

pub const TRANSACTION_PROOF_MAX_DEPTH: usize = 6;
/// Hardcoded (for now) max calldata size supported by the circuit
pub const TRANSACTION_MAX_DATA_BYTES: usize = 768;

pub fn calc_max_val_len(
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> usize {
    let mut t0_len = 2;
    let prefix_tot_max = 1 + 3 + 10 + 3 * 2;
    let mut field_len_sum = max_data_byte_len;
    for i in 0..TRANSACTION_TYPE_2_FIELDS {
        field_len_sum += TRANSACTION_TYPE_0_FIELDS_MAX_BYTES[i];
    }
    if enable_types[0] {
        t0_len = max(t0_len, prefix_tot_max + field_len_sum);
    }
    field_len_sum = max_data_byte_len + max_access_list_len;
    for i in 0..TRANSACTION_TYPE_2_FIELDS {
        field_len_sum += TRANSACTION_TYPE_1_FIELDS_MAX_BYTES[i];
    }
    if enable_types[1] {
        t0_len = max(t0_len, prefix_tot_max + field_len_sum);
    }
    field_len_sum = max_data_byte_len + max_access_list_len;
    for i in 0..TRANSACTION_TYPE_2_FIELDS {
        field_len_sum += TRANSACTION_TYPE_2_FIELDS_MAX_BYTES[i];
    }
    if enable_types[2] {
        t0_len = max(t0_len, prefix_tot_max + field_len_sum);
    }
    // Transaction and variable len fields have a prefix at most 3, others have prefix at most 1.
    // Add 1 for the transaction type byte
    t0_len
}

fn calc_max_field_len(
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> Vec<usize> {
    let mut base = vec![0; TRANSACTION_TYPE_2_FIELDS];
    base[0] = 1;
    for i in 0..TRANSACTION_TYPE_2_FIELDS {
        if enable_types[0] {
            if i == 5 {
                base[i] = max(base[i], max_data_byte_len);
            } else {
                base[i] = max(base[i], TRANSACTION_TYPE_0_FIELDS_MAX_BYTES[i]);
            }
        }
        if enable_types[1] {
            if i == 6 {
                base[i] = max(base[i], max_data_byte_len);
            } else if i == 7 {
                base[i] = max(base[i], max_access_list_len);
            } else {
                base[i] = max(base[i], TRANSACTION_TYPE_1_FIELDS_MAX_BYTES[i]);
            }
        }
        if enable_types[2] {
            if i == 7 {
                base[i] = max(base[i], max_data_byte_len);
            } else if i == 8 {
                base[i] = max(base[i], max_access_list_len);
            } else {
                base[i] = max(base[i], TRANSACTION_TYPE_2_FIELDS_MAX_BYTES[i]);
            }
        }
    }
    base
}

pub struct EthTransactionChip<'chip, F: Field> {
    pub eth: &'chip EthChip<'chip, F>,
    pub max_data_byte_len: usize,
    pub max_access_list_len: usize,
    pub enable_types: [bool; 3],
}

impl<'chip, F: Field> EthTransactionChip<'chip, F> {
    pub fn new(
        eth: &'chip EthChip<'chip, F>,
        max_data_byte_len: usize,
        max_access_list_len: usize,
        enable_types: [bool; 3],
    ) -> Self {
        Self { eth, max_data_byte_len, max_access_list_len, enable_types }
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
    pub fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        input: EthTransactionInputAssigned<F>,
    ) -> EthTransactionTraceWitness<F> {
        let max_data_byte_len = self.max_data_byte_len;
        let max_access_list_len = self.max_access_list_len;
        let EthTransactionInputAssigned { transaction_index, proof } = input;
        let enable_types = self.enable_types;
        // Load value early to avoid borrow errors
        let slot_is_empty = proof.slot_is_empty;

        let all_disabled = !(enable_types[0] || enable_types[1] || enable_types[2]);
        // check key is rlp(idx)
        let idx_witness = self.eth.rlp().decompose_rlp_field_phase0(
            ctx,
            proof.key_bytes.clone(),
            TRANSACTION_IDX_MAX_LEN,
        );
        let tx_idx = ByteArray::from(&idx_witness.witness);
        let tx_idx = tx_idx.evaluate(ctx, self.eth.gate());
        ctx.constrain_equal(&tx_idx, &transaction_index);
        // check MPT inclusion
        let mpt_witness = self.eth.parse_mpt_inclusion_phase0(ctx, keccak, proof);
        // parse transaction
        // when we disable all types, we use that as a flag to parse dummy values which are two bytes long
        let max_field_lens =
            calc_max_field_len(max_data_byte_len, max_access_list_len, enable_types);
        if !all_disabled {
        } else {
            let one = ctx.load_constant(F::from(1));
            ctx.constrain_equal(&slot_is_empty, &one);
        }
        let one_two_eight = ctx.load_constant(F::from(128));
        let one_nine_three = ctx.load_constant(F::from(193));
        let type_is_not_zero =
            self.range().is_less_than(ctx, mpt_witness.value_bytes[0], one_two_eight, 8);
        // if the first byte is greater than 0xf7, the type is zero. Otherwise, the type is the first byte.
        let mut tx_type = self.gate().mul(ctx, type_is_not_zero, mpt_witness.value_bytes[0]);
        let max_val_len = if all_disabled {
            2_usize
        } else {
            calc_max_val_len(max_data_byte_len, max_access_list_len, enable_types)
        };
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
                val_byte = self.gate().mul_add(ctx, one_nine_three, slot_is_empty, val_byte);
            }
            new_value_witness.push(val_byte);
        }
        let zero = ctx.load_constant(F::from(0));
        let mut val_byte = self.gate().select(
            ctx,
            zero,
            mpt_witness.value_bytes[max_val_len - 1],
            type_is_not_zero,
        );
        val_byte = self.gate().mul(ctx, val_byte, slot_is_full);
        new_value_witness.push(val_byte);
        let value_witness =
            self.rlp().decompose_rlp_array_phase0(ctx, new_value_witness, &max_field_lens, true);
        EthTransactionTraceWitness {
            transaction_type: tx_type,
            idx: tx_idx,
            idx_witness,
            value_witness,
            mpt_witness,
        }
    }

    pub fn parse_transaction_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness.idx_witness);
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.eth.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let value_trace =
            self.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.value_witness, true);
        let value_trace = value_trace.field_trace;
        //debug_assert_eq!(value_trace.max_len, TRANSACTION_PROOF_VALUE_MAX_BYTE_LEN);
        EthTransactionTrace { transaction_type: witness.transaction_type, value_trace }
    }

    pub fn parse_single_transaction_field_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        input: EthTransactionFieldInputAssigned<F>,
    ) -> EthTransactionFieldTraceWitness<F> {
        let EthTransactionFieldInputAssigned { transaction, field_idx } = input;
        let witness = self.parse_transaction_proof_phase0(ctx, keccak, transaction);
        let field_witness = &witness.value_witness.field_witness;
        let slot_is_empty = witness.mpt_witness.slot_is_empty;
        let ans_len = field_witness.iter().map(|w| w.field_cells.len()).max().unwrap();
        let indicator = self.gate().idx_to_indicator(ctx, field_idx, TRANSACTION_TYPE_2_FIELDS);
        assert_eq!(field_witness.len(), TRANSACTION_TYPE_2_FIELDS);
        let mut field_bytes = Vec::new();
        let zero = ctx.load_zero();
        ctx.constrain_equal(&slot_is_empty, &zero);
        for i in 0..ans_len {
            let entries = field_witness.iter().map(|w| *w.field_cells.get(i).unwrap_or(&zero));
            let field_byte = self.gate().select_by_indicator(ctx, entries, indicator.clone());
            field_bytes.push(field_byte);
        }
        let lens = field_witness.iter().map(|w| w.field_len);
        let len = self.gate().select_by_indicator(ctx, lens, indicator);
        EthTransactionFieldTraceWitness {
            transaction_type: witness.transaction_type,
            transaction_witness: witness,
            field_idx,
            field_bytes,
            len,
            max_len: ans_len,
        }
    }

    pub fn parse_single_transaction_field_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthTransactionFieldTraceWitness<F>,
    ) -> EthTransactionFieldTrace<F> {
        let _transaction_trace =
            self.parse_transaction_proof_phase1((ctx_gate, ctx_rlc), witness.transaction_witness);
        EthTransactionFieldTrace {
            transaction_type: witness.transaction_type,
            field_idx: witness.field_idx,
            field_bytes: witness.field_bytes,
            len: witness.len,
            max_len: witness.max_len,
        }
    }

    pub fn parse_transaction_fields_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        transaction_witness: Vec<EthTransactionFieldTraceWitness<F>>,
    ) -> Vec<EthTransactionFieldTrace<F>> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);
        parallelize_phase1(thread_pool, transaction_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_single_transaction_field_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    pub fn parse_transaction_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        transaction_witness: Vec<EthTransactionTraceWitness<F>>,
    ) -> Vec<EthTransactionTrace<F>> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);
        parallelize_phase1(thread_pool, transaction_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_transaction_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    pub fn parse_transaction_proofs_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        network: Network,
    ) -> EthBlockTransactionTraceWitness<F> {
        let mut idx_queries = Vec::new();
        let block_witness = {
            let ctx = thread_pool.main(FIRST_PHASE);
            let block_header = input.block_header;
            self.eth.decompose_block_header_phase0(ctx, keccak, &block_header, network)
        };
        let ctx = thread_pool.main(FIRST_PHASE);
        let transactions_root = &block_witness.get_transactions_root().field_cells;
        let is_empty = {
            let mut is_empty = ctx.load_constant(F::from(1));
            let mut empty_hash = Vec::with_capacity(32);
            for i in 0..32 {
                let empty_hash_byte = ctx.load_constant(F::from(KECCAK_RLP_EMPTY_STRING[i] as u64));
                empty_hash.push(empty_hash_byte);
            }
            for (pf_byte, byte) in empty_hash.iter().zip(transactions_root.iter()) {
                let byte_match = self.gate().is_equal(ctx, *pf_byte, *byte);
                is_empty = self.gate().and(ctx, is_empty, byte_match);
            }
            is_empty
        };
        // verify transaction proofs
        // check MPT root of transaction_witness is block_witness.transaction_root

        let transaction_witness = {
            parallelize_keccak_phase0(thread_pool, keccak, input.txs, |ctx, keccak, input| {
                let witness = self.parse_transaction_proof_phase0(ctx, keccak, input);
                // check MPT root is transactions_root
                for (pf_byte, byte) in
                    witness.mpt_witness.root_hash_bytes.iter().zip(transactions_root.iter())
                {
                    ctx.constrain_equal(pf_byte, byte);
                }
                witness
            })
        };
        for w in &transaction_witness {
            idx_queries.push(w.idx);
        }
        // ctx dropped
        let (len, len_witness) = {
            let ctx = thread_pool.main(FIRST_PHASE);
            match input.len_proof {
                Some(len_proof) => {
                    let one = ctx.load_constant(F::from(1));
                    let inclusion_idx = len_proof[0].0;
                    let noninclusion_idx = len_proof[1].0;
                    let diff = self.gate().sub(ctx, noninclusion_idx, inclusion_idx);
                    // If non_empty, the difference should be equal to 1
                    let correct_diff = self.gate().is_equal(ctx, diff, one);
                    // If empty, the second index should be 0
                    let correct_empty = self.gate().is_zero(ctx, noninclusion_idx);
                    let correct = self.gate().or(ctx, correct_diff, correct_empty);
                    ctx.constrain_equal(&correct, &one);
                    // Constrains that the first is an inclusion proof and that the latter is a noninclusion proof
                    // If empty, the first can be a noninclusion proof
                    let slot_is_full = self.gate().not(ctx, len_proof[0].1.slot_is_empty);
                    let inclusion_constraint = self.gate().or(ctx, is_empty, slot_is_full);
                    ctx.constrain_equal(&inclusion_constraint, &one);
                    ctx.constrain_equal(&len_proof[1].1.slot_is_empty, &one);
                    // Checks that the proofs are correct
                    (
                        Some(noninclusion_idx),
                        Some(parallelize_keccak_phase0(
                            thread_pool,
                            keccak,
                            len_proof.to_vec(),
                            |ctx, keccak, (transaction_index, proof)| {
                                let witness = self.parse_transaction_proof_phase0(
                                    ctx,
                                    keccak,
                                    EthTransactionInputAssigned { transaction_index, proof },
                                );
                                // check MPT root is transactions_root
                                for (pf_byte, byte) in witness
                                    .mpt_witness
                                    .root_hash_bytes
                                    .iter()
                                    .zip(transactions_root.iter())
                                {
                                    ctx.constrain_equal(pf_byte, byte);
                                }
                                witness
                            },
                        )),
                    )
                }
                None => (None, None),
            }
        };

        EthBlockTransactionTraceWitness { block_witness, transaction_witness, len, len_witness }
    }

    pub fn parse_single_transaction_proof_from_block_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        network: Network,
    ) -> EthBlockTransactionTraceWitness<F> {
        let block_witness = {
            let block_header = input.block_header;
            self.eth.decompose_block_header_phase0(ctx, keccak, &block_header, network)
        };
        let transactions_root = &block_witness.get_transactions_root().field_cells;
        // verify transaction proofs
        // check MPT root of transaction_witness is block_witness.transaction_root

        let transaction_witness = {
            let witness = self.parse_transaction_proof_phase0(ctx, keccak, input.txs[0].clone());
            // check MPT root is transactions_root
            for (pf_byte, byte) in
                witness.mpt_witness.root_hash_bytes.iter().zip(transactions_root.iter())
            {
                ctx.constrain_equal(pf_byte, byte);
            }
            witness
        };
        // ctx dropped
        EthBlockTransactionTraceWitness {
            block_witness,
            transaction_witness: vec![transaction_witness],
            len: None,
            len_witness: None,
        }
    }

    pub fn parse_single_transaction_field_from_block_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionFieldInputAssigned<F>,
        network: Network,
    ) -> EthBlockTransactionFieldTraceWitness<F> {
        let block_header_rlp = input.block_header;
        let block = self.eth.decompose_block_header_phase0(ctx, keccak, &block_header_rlp, network);
        let tx_root = &block.get_transactions_root().field_cells;
        for (pf_byte, byte) in
            input.single_field.transaction.proof.root_hash_bytes.iter().zip_eq(tx_root.iter())
        {
            ctx.constrain_equal(pf_byte, byte);
        }
        let tx = self.parse_single_transaction_field_phase0(ctx, keccak, input.single_field);
        EthBlockTransactionFieldTraceWitness { txs: vec![tx], block, len: None, len_witness: None }
    }

    pub fn parse_transaction_proofs_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F> {
        let block_trace = self
            .eth
            .decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let transaction_trace =
            self.parse_transaction_proofs_phase1(thread_pool, witness.transaction_witness);
        let len_trace = witness
            .len_witness
            .map(|len_witness| self.parse_transaction_proofs_phase1(thread_pool, len_witness));
        EthBlockTransactionTrace { block_trace, transaction_trace, len: witness.len, len_trace }
    }

    pub fn parse_single_transaction_proof_from_block_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F> {
        let block_trace =
            self.eth.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness.block_witness);
        let tx_witness = witness.transaction_witness[0].clone();
        let transaction_trace =
            self.parse_transaction_proof_phase1((ctx_gate, ctx_rlc), tx_witness);
        EthBlockTransactionTrace {
            block_trace,
            transaction_trace: vec![transaction_trace],
            len: None,
            len_trace: None,
        }
    }

    pub fn parse_single_transaction_field_from_block_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthBlockTransactionFieldTraceWitness<F>,
    ) -> EthBlockTransactionFieldTrace<F> {
        let block_trace =
            self.eth.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness.block);
        let tx_witness = witness.txs[0].clone();
        let transaction_trace =
            self.parse_single_transaction_field_phase1((ctx_gate, ctx_rlc), tx_witness);
        EthBlockTransactionFieldTrace { block_trace, transaction_trace: vec![transaction_trace] }
    }

    /// FirstPhase of extracting a field from a transaction
    pub fn parse_transaction_fields_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionFieldsInputAssigned<F>,
        network: Network,
    ) -> EthBlockTransactionFieldTraceWitness<F> {
        let block_witness = {
            let ctx = thread_pool.main(FIRST_PHASE);
            let block_header = input.block_header;
            self.eth.decompose_block_header_phase0(ctx, keccak, &block_header, network)
        };
        let transactions_root = &block_witness.get_transactions_root().field_cells;
        // verify transaction proofs
        // check MPT root of transaction_witness is block_witness.transaction_root

        let tf_witness = {
            parallelize_keccak_phase0(thread_pool, keccak, input.txs, |ctx, keccak, tx| {
                let witness = self.parse_single_transaction_field_phase0(ctx, keccak, tx);
                // check MPT root is transactions_root
                for (pf_byte, byte) in witness
                    .transaction_witness
                    .mpt_witness
                    .root_hash_bytes
                    .iter()
                    .zip(transactions_root.iter())
                {
                    ctx.constrain_equal(pf_byte, byte);
                }
                witness
            })
        };
        let mut idx_queries = Vec::new();
        for w in &tf_witness {
            idx_queries.push(w.transaction_witness.idx);
        }
        EthBlockTransactionFieldTraceWitness {
            block: block_witness,
            txs: tf_witness,
            len: None,
            len_witness: None,
        }
    }

    /// SecondPhase of extracting a field from a transaction
    pub fn parse_transaction_fields_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionFieldTraceWitness<F>,
    ) -> EthBlockTransactionFieldTrace<F> {
        let block_trace =
            self.eth.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block);
        let transaction_trace = self.parse_transaction_fields_phase1(thread_pool, witness.txs);
        EthBlockTransactionFieldTrace { block_trace, transaction_trace }
    }

    pub fn parse_transaction_field_from_blocks_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: Vec<EthBlockTransactionFieldInputAssigned<F>>,
        network: Network,
    ) -> Vec<EthBlockTransactionFieldTraceWitness<F>> {
        parallelize_keccak_phase0(thread_pool, keccak, input, |ctx, keccak, input| {
            self.parse_single_transaction_field_from_block_phase0(ctx, keccak, input, network)
        })
    }

    pub fn parse_transaction_field_from_blocks_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: Vec<EthBlockTransactionFieldTraceWitness<F>>,
    ) -> Vec<EthBlockTransactionFieldTrace<F>> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        // pre-load rlc cache so later parallelization is deterministic
        let mut cache_bits = bit_length(witness[0].block.rlp_witness.rlp_array.len() as u64);
        let cache_bits2 =
            bit_length(witness[0].txs[0].transaction_witness.value_witness.rlp_array.len() as u64);
        cache_bits = max(cache_bits, cache_bits2);
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), cache_bits);
        parallelize_phase1(thread_pool, witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_single_transaction_field_from_block_phase1((ctx_gate, ctx_rlc), witness)
        })
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionCircuit {
    pub inputs: EthBlockTransactionInput, // public and private inputs
    pub network: Network,
    pub max_data_byte_len: usize,
    pub max_access_list_len: usize,
    pub enable_types: [bool; 3],
}

impl EthBlockTransactionCircuit {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        idxs: Vec<usize>,
        block_number: u32,
        transaction_pf_max_depth: usize,
        network: Network,
        max_data_byte_len: usize,
        max_access_list_len: usize,
        enable_types: [bool; 3],
        constrain_len: bool,
    ) -> Self {
        use crate::providers::get_block_transaction_input;

        let inputs = get_block_transaction_input(
            provider,
            idxs,
            block_number,
            transaction_pf_max_depth,
            max_data_byte_len,
            max_access_list_len,
            enable_types,
            constrain_len,
        );
        Self { inputs, network, max_data_byte_len, max_access_list_len, enable_types }
    }
}

impl EthPreCircuit for EthBlockTransactionCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let eth = EthChip::new(RlpChip::new(&range, None), None);
        let chip = EthTransactionChip::new(
            &eth,
            self.max_data_byte_len,
            self.max_access_list_len,
            self.enable_types,
        );
        let mut keccak = KeccakChip::default();
        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let input = self.inputs.assign(ctx, self.network);
        let witness = chip.parse_transaction_proofs_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            self.network,
        );

        EthCircuitBuilder::new(
            vec![], // assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<Fr>,
                  rlp: RlpChip<Fr>,
                  keccak_rlcs: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {
                // ======== SECOND PHASE ===========
                let eth = EthChip::new(rlp, Some(keccak_rlcs));
                let chip = EthTransactionChip::new(
                    &eth,
                    self.max_data_byte_len,
                    self.max_access_list_len,
                    self.enable_types,
                );
                let _trace = chip.parse_transaction_proofs_from_block_phase1(builder, witness);
            },
        )
    }
}
