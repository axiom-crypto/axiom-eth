use getset::Getters;

use crate::{
    rlp::types::{RlpArrayWitness, RlpFieldTrace, RlpFieldWitness},
    utils::assign_vec,
};

use super::*;

/// Assigned version of [`EthTransactionInput`]
#[derive(Clone, Debug)]
pub struct EthTransactionInputAssigned<F: Field> {
    /// idx is the transaction index, varying from 0 to around 500
    pub transaction_index: AssignedValue<F>,
    pub proof: MPTProof<F>,
}

#[derive(Clone, Debug, Getters)]
pub struct EthTransactionWitness<F: Field> {
    pub transaction_type: AssignedValue<F>,
    pub idx: AssignedValue<F>,
    pub(crate) idx_witness: RlpFieldWitness<F>,
    #[getset(get = "pub")]
    pub(crate) value_witness: RlpArrayWitness<F>,
    #[getset(get = "pub")]
    pub(crate) mpt_witness: MPTProofWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionTrace<F: Field> {
    pub transaction_type: AssignedValue<F>,
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

/// Container for extracting a specific field from a single transaction
#[derive(Clone, Debug)]
pub struct EthTransactionFieldWitness<F: Field> {
    pub transaction_witness: EthTransactionWitness<F>,
    pub transaction_type: AssignedValue<F>,
    pub field_idx: AssignedValue<F>,
    pub field_bytes: Vec<AssignedValue<F>>,
    pub len: AssignedValue<F>,
    pub max_len: usize,
}

/// Assigned version of [`EthBlockTransactionsInput`]
#[derive(Clone, Debug)]
pub struct EthBlockTransactionsInputAssigned<F: Field> {
    // block_hash: AssignedH256<F>, // H256 as (u128, u128)
    pub block_header: Vec<AssignedValue<F>>,
    pub tx_inputs: Vec<EthTransactionInputAssigned<F>>,
    // Inclusion and noninclusion proof pair of neighboring indices
    pub len_proof: Option<[EthTransactionInputAssigned<F>; 2]>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionsWitness<F: Field> {
    pub block_witness: EthBlockHeaderWitness<F>,
    pub transaction_witness: Vec<EthTransactionWitness<F>>,
    pub len: Option<AssignedValue<F>>,
    pub len_witness: Option<[EthTransactionWitness<F>; 2]>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionsTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub transaction_trace: Vec<EthTransactionTrace<F>>,
    pub len: Option<AssignedValue<F>>,
    pub len_trace: Option<Vec<EthTransactionTrace<F>>>,
}

// rust native types

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthTransactionProof {
    pub tx_index: usize,
    pub proof: MPTInput,
}

/// Used to prove total number of transactions in a block
#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthTransactionLenProof {
    pub inclusion: EthTransactionProof,
    pub noninclusion: EthTransactionProof,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
/// Contains an index, a proof, the desired field_idx to be queried.
pub struct EthTransactionFieldInput {
    pub transaction_index: usize,
    pub proof: MPTInput,
    pub field_idx: usize,
}

/// Contains block information, multiple `EthTransactionInput` for transactions we want to prove in the block,
/// and a `constrain_len` flag that decides whether the number of transactions in the block should be proved as well.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EthBlockTransactionsInput {
    pub block: Block<Transaction>,
    pub block_number: u32,
    pub block_hash: H256, // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub tx_proofs: Vec<EthTransactionProof>,
    /// Inclusion and noninclusion proof pair of neighboring indices
    pub len_proof: Option<EthTransactionLenProof>,
}

impl EthTransactionProof {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTransactionInputAssigned<F> {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let transaction_index = ctx.load_witness(F::from(self.tx_index as u64));
        let proof = self.proof.assign(ctx);
        EthTransactionInputAssigned { transaction_index, proof }
    }
}

impl EthBlockTransactionsInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
        network: Chain,
    ) -> EthBlockTransactionsInputAssigned<F> {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let tx_inputs = self.tx_proofs.into_iter().map(|pf| pf.assign(ctx)).collect();
        let len_proof =
            self.len_proof.map(|pf| [pf.inclusion.assign(ctx), pf.noninclusion.assign(ctx)]);
        let max_len = get_block_header_rlp_max_lens(network).0;
        let block_header = assign_vec(ctx, self.block_header, max_len);
        EthBlockTransactionsInputAssigned { block_header, tx_inputs, len_proof }
    }
}
