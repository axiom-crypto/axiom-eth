use crate::Field;
use crate::{
    mpt::{MPTInput, MPTProof, MPTProofWitness},
    rlp::types::{RlpArrayWitness, RlpFieldTrace, RlpFieldWitness},
};
use ethers_core::types::H256;
use getset::Getters;
use halo2_base::{AssignedValue, Context};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct EthReceiptInputAssigned<F: Field> {
    pub tx_idx: AssignedValue<F>,
    pub proof: MPTProof<F>,
}

#[derive(Clone, Debug, Getters)]
pub struct EthReceiptWitness<F: Field> {
    pub receipt_type: AssignedValue<F>,
    pub tx_idx: AssignedValue<F>,
    pub idx_witness: RlpFieldWitness<F>,
    #[getset(get = "pub")]
    pub(crate) value: RlpArrayWitness<F>,
    pub logs: RlpArrayWitness<F>,
    #[getset(get = "pub")]
    pub(crate) mpt_witness: MPTProofWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptTrace<F: Field> {
    pub receipt_type: AssignedValue<F>,
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptFieldWitness<F: Field> {
    pub field_idx: AssignedValue<F>,
    /// Value of the field, right padded to some max length
    pub value_bytes: Vec<AssignedValue<F>>,
    pub value_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptLogWitness<F: Field> {
    pub log_idx: AssignedValue<F>,
    /// Log in bytes, right padded to some max length
    pub log_bytes: Vec<AssignedValue<F>>,
    pub log_len: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptLogFieldWitness<F: Field> {
    /// Witness for parsed log list
    pub log_list: RlpArrayWitness<F>,
    /// Witness for parsed topics list
    pub topics_list: RlpArrayWitness<F>,
}

impl<F: Field> EthReceiptLogFieldWitness<F> {
    /// Variable number of topics.
    pub fn num_topics(&self) -> AssignedValue<F> {
        self.topics_list.list_len.unwrap()
    }
    /// List of topics, each topic as bytes. The list is padded to fixed length.
    pub fn topics_bytes(&self) -> Vec<Vec<AssignedValue<F>>> {
        self.topics_list.field_witness.iter().map(|h| h.field_cells.clone()).collect()
    }
    pub fn address(&self) -> &[AssignedValue<F>] {
        &self.log_list.field_witness[0].field_cells
    }
    pub fn data_bytes(&self) -> &[AssignedValue<F>] {
        &self.log_list.field_witness[2].field_cells
    }
    pub fn data_len(&self) -> AssignedValue<F> {
        self.log_list.field_witness[2].field_len
    }
}

// rust native types

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

impl EthReceiptInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthReceiptInputAssigned<F> {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let tx_idx = ctx.load_witness(F::from(self.idx as u64));
        let proof = self.proof.assign(ctx);
        EthReceiptInputAssigned { tx_idx, proof }
    }
}
