use crate::{
    block_header::{
        assign_vec, get_block_header_rlp_max_lens, EthBlockHeaderTrace, EthBlockHeaderTraceWitness,
    },
    keccak::ContainsParallelizableKeccakQueries,
    mpt::{MPTInput, MPTProof, MPTProofWitness},
    rlp::{RlpArrayTraceWitness, RlpFieldTrace, RlpFieldTraceWitness},
    Field, Network,
};
use ethers_core::types::H256;
use halo2_base::{safe_types::RangeInstructions, AssignedValue, Context};
use serde::{Deserialize, Serialize};

use super::RECEIPT_NUM_FIELDS;

#[derive(Clone, Debug)]
pub struct EthReceiptTrace<F: Field> {
    pub receipt_type: AssignedValue<F>,
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptFieldTraceWitness<F: Field> {
    pub receipt_witness: EthReceiptTraceWitness<F>,
    pub field_idx: AssignedValue<F>,
    pub log_idx: AssignedValue<F>,
    pub value_bytes: Vec<AssignedValue<F>>,
    pub value_len: AssignedValue<F>,
    pub max_len: usize,
}

#[derive(Clone, Debug)]
pub struct EthReceiptFieldTrace<F: Field> {
    pub receipt_type: AssignedValue<F>,
    pub field_idx: AssignedValue<F>,
    pub field_bytes: Vec<AssignedValue<F>>,
    pub len: AssignedValue<F>,
    pub max_len: usize,
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptFieldTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    //pub receipt_trace: Vec<EthReceiptFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptTraceWitness<F: Field> {
    pub receipt_type: AssignedValue<F>,
    pub tx_idx: AssignedValue<F>,
    pub idx_witness: RlpFieldTraceWitness<F>,
    pub(crate) value: RlpArrayTraceWitness<F>,
    pub logs: RlpArrayTraceWitness<F>,
    pub(crate) mpt_witness: MPTProofWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub receipt_trace: Vec<EthReceiptTrace<F>>,
    pub len: Option<AssignedValue<F>>,
    pub len_witness: Option<Vec<EthReceiptTrace<F>>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptFieldTraceWitness<F: Field> {
    pub block: EthBlockHeaderTraceWitness<F>,
    pub receipt: EthReceiptFieldTraceWitness<F>,
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthReceiptTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthReceiptFieldTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.receipt_witness.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthBlockReceiptFieldTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.block.shift_query_indices(fixed_shift, var_shift);
        self.receipt.shift_query_indices(fixed_shift, var_shift);
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptRequest {
    pub tx_hash: H256,
    pub field_idx: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_idx: Option<u8>,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthReceiptInput {
    pub idx: usize,
    pub proof: MPTInput,
}

#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct EthBlockReceiptInput {
    pub block_number: u32,
    pub block_hash: H256, // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub receipt: EthReceiptInput,
}

#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct EthBlockReceiptFieldInput {
    pub input: EthBlockReceiptInput,
    pub field_idx: u8,
    pub log_idx: u8,
}

#[derive(Clone, Debug)]
pub struct EthReceiptInputAssigned<F: Field> {
    pub tx_idx: AssignedValue<F>,
    pub proof: MPTProof<F>,
}

#[derive(Clone, Debug)]
pub struct SingleReceiptFieldInputAssigned<F: Field> {
    pub receipt: EthReceiptInputAssigned<F>,
    pub field_idx: AssignedValue<F>,
    pub log_idx: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct BlockReceiptFieldInputAssigned<F: Field> {
    pub block_header_rlp: Vec<AssignedValue<F>>,
    pub single_field: SingleReceiptFieldInputAssigned<F>,
}

impl EthBlockReceiptFieldInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
        range: &impl RangeInstructions<F>,
        network: Network,
    ) -> BlockReceiptFieldInputAssigned<F> {
        let tx_idx = ctx.load_witness(F::from(self.input.receipt.idx as u64));
        let field_idx = ctx.load_witness(F::from(self.field_idx as u64));
        range.check_less_than_safe(ctx, field_idx, RECEIPT_NUM_FIELDS as u64);
        let log_idx = ctx.load_witness(F::from(self.log_idx as u64));
        let proof = self.input.receipt.proof.assign(ctx);
        let single_field = SingleReceiptFieldInputAssigned {
            receipt: EthReceiptInputAssigned { tx_idx, proof },
            field_idx,
            log_idx,
        };

        let block_header_rlp =
            assign_vec(ctx, self.input.block_header, get_block_header_rlp_max_lens(network).0);
        BlockReceiptFieldInputAssigned { block_header_rlp, single_field }
    }
}
