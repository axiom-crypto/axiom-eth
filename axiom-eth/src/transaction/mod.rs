use std::cmp::max;

use ethers_core::{
    types::{Block, Chain, Transaction, H256},
    utils::hex::FromHex,
};
use halo2_base::{
    gates::{
        flex_gate::threads::parallelize_core, GateChip, GateInstructions, RangeChip,
        RangeInstructions,
    },
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::{
    block_header::{
        get_block_header_rlp_max_lens, EthBlockHeaderChip, EthBlockHeaderTrace,
        EthBlockHeaderWitness,
    },
    keccak::KeccakChip,
    mpt::{MPTChip, MPTInput, MPTProof, MPTProofWitness},
    rlc::{
        chip::RlcChip,
        circuit::builder::{RlcCircuitBuilder, RlcContextPair},
        FIRST_PHASE,
    },
    rlp::{evaluate_byte_array, RlpChip},
    utils::circuit_utils::constrain_no_leading_zeros,
    Field,
};

// pub mod helpers;
#[cfg(all(test, feature = "providers"))]
mod tests;
mod types;

pub use types::*;

lazy_static! {
    static ref KECCAK_RLP_EMPTY_STRING: Vec<u8> =
        Vec::from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
}

// type 0 tx has 9 fields
// type 1 tx has 11 fields
// type 2 tx has 12 fields
pub const TRANSACTION_MAX_FIELDS: usize = 12;
pub(crate) const TRANSACTION_TYPE_0_FIELDS_MAX_BYTES: [usize; TRANSACTION_MAX_FIELDS] =
    [32, 32, 32, 20, 32, 0, 8, 32, 32, 1, 1, 1];
pub(crate) const TRANSACTION_TYPE_1_FIELDS_MAX_BYTES: [usize; TRANSACTION_MAX_FIELDS] =
    [8, 32, 32, 32, 20, 32, 0, 0, 1, 32, 32, 1];
pub(crate) const TRANSACTION_TYPE_2_FIELDS_MAX_BYTES: [usize; TRANSACTION_MAX_FIELDS] =
    [8, 8, 8, 8, 32, 20, 32, 0, 0, 1, 32, 32];
pub(crate) const TRANSACTION_IDX_MAX_LEN: usize = 2;
pub const TX_IDX_MAX_BYTES: usize = TRANSACTION_IDX_MAX_LEN;

/// Calculate max rlp length of a transaction given some parameters
pub fn calc_max_val_len(
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> usize {
    let mut t0_len = 2;
    // TODO: do not hardcode
    let prefix_tot_max = 1 + 4 + 10 + 4 * 2;
    let mut field_len_sum = max_data_byte_len;
    for field_len in TRANSACTION_TYPE_0_FIELDS_MAX_BYTES {
        field_len_sum += field_len;
    }
    if enable_types[0] {
        t0_len = max(t0_len, prefix_tot_max + field_len_sum);
    }
    field_len_sum = max_data_byte_len + max_access_list_len;
    for field_len in TRANSACTION_TYPE_1_FIELDS_MAX_BYTES {
        field_len_sum += field_len;
    }
    if enable_types[1] {
        t0_len = max(t0_len, prefix_tot_max + field_len_sum);
    }
    field_len_sum = max_data_byte_len + max_access_list_len;
    for field_len in TRANSACTION_TYPE_2_FIELDS_MAX_BYTES {
        field_len_sum += field_len;
    }
    if enable_types[2] {
        t0_len = max(t0_len, prefix_tot_max + field_len_sum);
    }
    // Transaction and variable len fields have a prefix at most 3, others have prefix at most 1.
    // Add 1 for the transaction type byte
    t0_len
}

/// Calculate the max capacity needed to contain fields at all positions across all transaction types.
fn calc_max_field_len(
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> Vec<usize> {
    let mut base = vec![0; TRANSACTION_MAX_FIELDS];
    base[0] = 1;
    for i in 0..TRANSACTION_MAX_FIELDS {
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

/// Configuration parameters to construct [EthTransactionChip]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Hash, Default)]
pub struct EthTransactionChipParams {
    /// Sets the `max_field_length` for possible positions for the `data` field.
    pub max_data_byte_len: usize,
    /// Sets the `max_field_length` for possible positions for the `accessList` field.
    pub max_access_list_len: usize,
    /// Specifies which transaction types [0x0, 0x1, 0x2] this chip supports
    pub enable_types: [bool; 3],
    /// Must provide network to use functions involving block header
    pub network: Option<Chain>,
}

/// Chip that supports functions that prove transactions and transaction fields
#[derive(Clone, Debug)]
pub struct EthTransactionChip<'chip, F: Field> {
    pub mpt: &'chip MPTChip<'chip, F>,
    pub params: EthTransactionChipParams,
}

impl<'chip, F: Field> EthTransactionChip<'chip, F> {
    pub fn new(mpt: &'chip MPTChip<'chip, F>, params: EthTransactionChipParams) -> Self {
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

    /// FirstPhase of proving the inclusion **or** exclusion of a transaction index within a transaction root.
    /// In the case of
    /// - inclusion: then parses the transaction
    /// - exclusion: `input.proof.slot_is_empty` is true, and we return `tx_type = -1, value = rlp(0x00)`.
    pub fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        input: EthTransactionInputAssigned<F>,
    ) -> EthTransactionWitness<F> {
        let EthTransactionChipParams {
            max_data_byte_len, max_access_list_len, enable_types, ..
        } = self.params;
        let EthTransactionInputAssigned { transaction_index, proof } = input;
        // Load value early to avoid borrow errors
        let slot_is_empty = proof.slot_is_empty;

        let all_disabled = !(enable_types[0] || enable_types[1] || enable_types[2]);
        // check key is rlp(idx):
        // given rlp(idx), parse idx as var len bytes
        let idx_witness = self.rlp().decompose_rlp_field_phase0(
            ctx,
            proof.key_bytes.clone(),
            TRANSACTION_IDX_MAX_LEN,
        );
        // evaluate idx to number
        let tx_idx =
            evaluate_byte_array(ctx, self.gate(), &idx_witness.field_cells, idx_witness.field_len);
        // check idx equals provided transaction_index from input
        ctx.constrain_equal(&tx_idx, &transaction_index);
        constrain_no_leading_zeros(
            ctx,
            self.gate(),
            &idx_witness.field_cells,
            idx_witness.field_len,
        );

        // check MPT inclusion
        let mpt_witness = self.mpt.parse_mpt_inclusion_phase0(ctx, proof);
        // parse transaction
        // when we disable all types, we use that as a flag to parse dummy values which are two bytes long
        let max_field_lens =
            calc_max_field_len(max_data_byte_len, max_access_list_len, enable_types);
        if all_disabled {
            let one = ctx.load_constant(F::ONE);
            ctx.constrain_equal(&slot_is_empty, &one);
        }
        // type > 0 are stored as {0x01, 0x02} . encode(tx)
        let type_is_not_zero =
            self.range().is_less_than(ctx, mpt_witness.value_bytes[0], Constant(F::from(128)), 8);
        // if the first byte is greater than 0xf7, the type is zero. Otherwise, the type is the first byte.
        let mut tx_type = self.gate().mul(ctx, type_is_not_zero, mpt_witness.value_bytes[0]);
        let max_val_len = if all_disabled {
            2_usize
        } else {
            calc_max_val_len(max_data_byte_len, max_access_list_len, enable_types)
        };
        debug_assert!(max_val_len > 1);
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
        let value_witness =
            self.rlp().decompose_rlp_array_phase0(ctx, new_value_witness, &max_field_lens, true);
        EthTransactionWitness {
            transaction_type: tx_type,
            idx: tx_idx,
            idx_witness,
            value_witness,
            mpt_witness,
        }
    }

    /// SecondPhase of proving inclusion **or** exclusion of a transaction index in transaction root, and then parses
    /// the transaction. See [`parse_transaction_proof_phase0`] for more details.
    pub fn parse_transaction_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthTransactionWitness<F>,
    ) -> EthTransactionTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness.idx_witness);
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.mpt.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let value_trace =
            self.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.value_witness, true);
        let value_trace = value_trace.field_trace;
        EthTransactionTrace { transaction_type: witness.transaction_type, value_trace }
    }

    /// Parallelizes `parse_transaction_proof_phase0`.
    pub fn parse_transaction_proofs_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<EthTransactionInputAssigned<F>>,
    ) -> Vec<EthTransactionWitness<F>> {
        parallelize_core(builder.base.pool(0), input, |ctx, input| {
            self.parse_transaction_proof_phase0(ctx, input)
        })
    }

    /// Parallelizes `parse_transaction_proof_phase1`
    pub fn parse_transaction_proofs_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        transaction_witness: Vec<EthTransactionWitness<F>>,
    ) -> Vec<EthTransactionTrace<F>> {
        // rlc cache should be loaded globally, no longer done here
        builder.parallelize_phase1(transaction_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_transaction_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    /// FirstPhase of proving the inclusion **or** exclusion of transactions into the block header of a given block.
    /// Also parses the transaction into fields.
    ///
    /// If `input.len_proof` is Some, then we prove the total number of transactions in this block.
    ///
    /// This performs [`EthBlockHeaderChip::decompose_block_header_phase0`] (single-threaded) and then multi-threaded `parse_transaction_proof_phase0`.
    pub fn parse_transaction_proofs_from_block_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        input: EthBlockTransactionsInputAssigned<F>,
    ) -> EthBlockTransactionsWitness<F> {
        let block_witness = {
            let ctx = builder.base.main(FIRST_PHASE);
            let block_header = input.block_header;
            self.block_header_chip().decompose_block_header_phase0(
                ctx,
                self.keccak(),
                &block_header,
            )
        };
        let transactions_root = &block_witness.get_transactions_root().field_cells;

        // verify transaction proofs
        let transaction_witness = {
            parallelize_core(builder.base.pool(FIRST_PHASE), input.tx_inputs, |ctx, input| {
                let witness = self.parse_transaction_proof_phase0(ctx, input);
                // check MPT root is transactions_root
                for (pf_byte, byte) in
                    witness.mpt_witness.root_hash_bytes.iter().zip_eq(transactions_root.iter())
                {
                    ctx.constrain_equal(pf_byte, byte);
                }
                witness
            })
        };
        // ctx dropped
        let (len, len_witness) = if let Some(len_proof) = input.len_proof {
            // we calculate and prove the total number of transactions in this block
            let ctx = builder.base.main(FIRST_PHASE);
            let one = ctx.load_constant(F::ONE);
            let is_empty = {
                let mut is_empty = one;
                let mut empty_hash = Vec::with_capacity(32);
                for i in 0..32 {
                    empty_hash.push(ctx.load_constant(F::from(KECCAK_RLP_EMPTY_STRING[i] as u64)));
                }
                for (pf_byte, byte) in empty_hash.iter().zip(transactions_root.iter()) {
                    let byte_match = self.gate().is_equal(ctx, *pf_byte, *byte);
                    is_empty = self.gate().and(ctx, is_empty, byte_match);
                }
                is_empty
            };
            let inclusion_idx = len_proof[0].transaction_index;
            let noninclusion_idx = len_proof[1].transaction_index;
            let diff = self.gate().sub(ctx, noninclusion_idx, inclusion_idx);
            // If non_empty, the difference should be equal to 1
            let correct_diff = self.gate().is_equal(ctx, diff, one);
            // If empty, the second index should be 0
            let correct_empty = self.gate().is_zero(ctx, noninclusion_idx);
            let correct = self.gate().or(ctx, correct_diff, correct_empty);
            ctx.constrain_equal(&correct, &one);
            // Constrains that the first is an inclusion proof and that the latter is a noninclusion proof
            // If empty, the first can be a noninclusion proof
            let slot_is_full = self.gate().not(ctx, len_proof[0].proof.slot_is_empty);
            // If transaction trie is empty, then `noninclusion_idx` must equal `0`.
            // Otherwise the proof for `inclusion_idx` must be an inclusion proof.
            let inclusion_constraint =
                self.gate().select(ctx, correct_empty, slot_is_full, is_empty);
            ctx.constrain_equal(&inclusion_constraint, &one);
            ctx.constrain_equal(&len_proof[1].proof.slot_is_empty, &one);
            // Checks that the proofs are correct
            (
                Some(noninclusion_idx),
                Some(len_proof.map(|tx_input| {
                    let witness = self.parse_transaction_proof_phase0(ctx, tx_input);
                    // check MPT root is transactions_root
                    for (pf_byte, byte) in
                        witness.mpt_witness.root_hash_bytes.iter().zip(transactions_root.iter())
                    {
                        ctx.constrain_equal(pf_byte, byte);
                    }
                    witness
                })),
            )
        } else {
            (None, None)
        };

        EthBlockTransactionsWitness { block_witness, transaction_witness, len, len_witness }
    }

    /// SecondPhase of proving the inclusion of transactions into the transaction root of a given block.
    /// Also parses the transaction into fields.
    pub fn parse_transaction_proofs_from_block_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        witness: EthBlockTransactionsWitness<F>,
    ) -> EthBlockTransactionsTrace<F> {
        let block_trace = self
            .block_header_chip()
            .decompose_block_header_phase1(builder.rlc_ctx_pair(), witness.block_witness);
        let transaction_trace =
            self.parse_transaction_proofs_phase1(builder, witness.transaction_witness);
        let len_trace = witness
            .len_witness
            .map(|len_witness| self.parse_transaction_proofs_phase1(builder, len_witness.to_vec()));
        EthBlockTransactionsTrace { block_trace, transaction_trace, len: witness.len, len_trace }
    }

    /// Combination of `decompose_block_header_phase0` and `parse_transaction_proof_phase0`.
    /// Constrains that the `transaction_root` is contained in the `block_header`.
    ///
    /// The difference between this function and `parse_transaction_proofs_from_block_phase0` is that this function
    /// is entirely single-threaded, so you can then further parallelize the entire function.
    ///
    /// This _will_ range check `block_header` to be bytes.
    pub fn parse_transaction_proof_from_block_phase0(
        &self,
        ctx: &mut Context<F>,
        block_header: &[AssignedValue<F>],
        tx_input: EthTransactionInputAssigned<F>,
    ) -> (EthBlockHeaderWitness<F>, EthTransactionWitness<F>) {
        let block_witness = self.block_header_chip().decompose_block_header_phase0(
            ctx,
            self.keccak(),
            block_header,
        );
        let transactions_root = &block_witness.get_transactions_root().field_cells;
        // check MPT root of transaction_witness is block_witness.transaction_root
        let transaction_witness = {
            let witness = self.parse_transaction_proof_phase0(ctx, tx_input);
            // check MPT root is transactions_root
            for (pf_byte, byte) in
                witness.mpt_witness.root_hash_bytes.iter().zip_eq(transactions_root.iter())
            {
                ctx.constrain_equal(pf_byte, byte);
            }
            witness
        };
        (block_witness, transaction_witness)
    }

    /// Combination of `decompose_block_header_phase1` and `parse_transaction_proof_phase1`. Single-threaded.
    pub fn parse_transaction_proof_from_block_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        block_witness: EthBlockHeaderWitness<F>,
        tx_witness: EthTransactionWitness<F>,
    ) -> (EthBlockHeaderTrace<F>, EthTransactionTrace<F>) {
        let block_trace = self
            .block_header_chip()
            .decompose_block_header_phase1((ctx_gate, ctx_rlc), block_witness);
        let transaction_trace =
            self.parse_transaction_proof_phase1((ctx_gate, ctx_rlc), tx_witness);
        (block_trace, transaction_trace)
    }

    /// Extracts the field at `field_idx` from the given rlp decomposition of a transaction.
    ///
    /// Constrains that `witness` must be an inclusion proof of the transaction into transaction root
    /// (a priori it could be exclusion proof).
    pub fn extract_field(
        &self,
        ctx: &mut Context<F>,
        witness: EthTransactionWitness<F>,
        field_idx: AssignedValue<F>,
    ) -> EthTransactionFieldWitness<F> {
        let field_witness = &witness.value_witness.field_witness;
        let slot_is_empty = witness.mpt_witness.slot_is_empty;
        let ans_len = field_witness.iter().map(|w| w.field_cells.len()).max().unwrap();
        let indicator = self.gate().idx_to_indicator(ctx, field_idx, TRANSACTION_MAX_FIELDS);
        assert_eq!(field_witness.len(), TRANSACTION_MAX_FIELDS);
        let zero = ctx.load_zero();
        ctx.constrain_equal(&slot_is_empty, &zero);
        let mut field_bytes = Vec::with_capacity(ans_len);
        for i in 0..ans_len {
            let entries = field_witness.iter().map(|w| *w.field_cells.get(i).unwrap_or(&zero));
            let field_byte = self.gate().select_by_indicator(ctx, entries, indicator.clone());
            field_bytes.push(field_byte);
        }
        let lens = field_witness.iter().map(|w| w.field_len);
        let len = self.gate().select_by_indicator(ctx, lens, indicator);
        EthTransactionFieldWitness {
            transaction_type: witness.transaction_type,
            transaction_witness: witness,
            field_idx,
            field_bytes,
            len,
            max_len: ans_len,
        }
    }
}
