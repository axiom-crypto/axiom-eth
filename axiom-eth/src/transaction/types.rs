use crate::block_header::assign_vec;

use super::*;

#[derive(Clone, Debug)]
pub struct EthTransactionTrace<F: Field> {
    pub transaction_type: AssignedValue<F>,
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionFieldTraceWitness<F: Field> {
    pub transaction_witness: EthTransactionTraceWitness<F>,
    pub transaction_type: AssignedValue<F>,
    pub field_idx: AssignedValue<F>,
    pub field_bytes: Vec<AssignedValue<F>>,
    pub len: AssignedValue<F>,
    pub max_len: usize,
}

#[derive(Clone, Debug)]
pub struct EthTransactionFieldTrace<F: Field> {
    pub transaction_type: AssignedValue<F>,
    pub field_idx: AssignedValue<F>,
    pub field_bytes: Vec<AssignedValue<F>>,
    pub len: AssignedValue<F>,
    pub max_len: usize,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionFieldTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub transaction_trace: Vec<EthTransactionFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionTraceWitness<F: Field> {
    pub transaction_type: AssignedValue<F>,
    pub idx: AssignedValue<F>,
    pub idx_witness: RlpFieldTraceWitness<F>,
    pub(crate) value_witness: RlpArrayTraceWitness<F>,
    pub(crate) mpt_witness: MPTProofWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub transaction_trace: Vec<EthTransactionTrace<F>>,
    pub len: Option<AssignedValue<F>>,
    pub len_trace: Option<Vec<EthTransactionTrace<F>>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub transaction_witness: Vec<EthTransactionTraceWitness<F>>,
    pub len: Option<AssignedValue<F>>,
    pub len_witness: Option<Vec<EthTransactionTraceWitness<F>>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionFieldTraceWitness<F: Field> {
    pub block: EthBlockHeaderTraceWitness<F>,
    pub txs: Vec<EthTransactionFieldTraceWitness<F>>,
    pub len: Option<AssignedValue<F>>,
    pub len_witness: Option<Vec<EthTransactionTraceWitness<F>>>,
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthTransactionTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthTransactionFieldTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.transaction_witness.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthBlockTransactionTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        for tx in &mut self.transaction_witness {
            tx.shift_query_indices(fixed_shift, var_shift);
        }
        self.block_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthBlockTransactionFieldTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.block.shift_query_indices(fixed_shift, var_shift);
        for tx in &mut self.txs {
            tx.shift_query_indices(fixed_shift, var_shift);
        }
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthTransactionProof {
    pub idx: usize,
    pub proof: MPTInput,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthTransactionLenProof {
    pub inclusion: EthTransactionProof,
    pub noninclusion: EthTransactionProof,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionRequest {
    pub tx_hash: H256,
    pub field_idx: u8,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthTransactionInput {
    /// A vector of (idx, value, proof) tuples
    pub transaction_pfs: Vec<(usize, Vec<u8>, MPTInput)>,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthTransactionFieldInput {
    pub transaction_index: usize,
    pub proof: MPTInput,

    pub field_idx: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EthBlockTransactionInput {
    pub block: Block<Transaction>,
    pub block_number: u32,
    pub block_hash: H256, // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub txs: EthTransactionInput,
    pub constrain_len: bool,
    // Inclusion and noninclusion proof pair of neighboring indices
    pub len_proof: Option<EthTransactionLenProof>,
}

#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct EthBlockTransactionFieldInput {
    pub block_number: u32,
    pub block_hash: H256, // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,

    pub tx_input: EthTransactionFieldInput,
    pub constrain_len: bool,
    // Inclusion and noninclusion proof pair of neighboring indices
    pub len_proof: Option<EthTransactionLenProof>,
}

#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct EthBlockTransactionFieldsInput {
    pub block_number: u32,
    pub block_hash: H256, // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,

    pub txs: Vec<EthTransactionFieldInput>,
    pub constrain_len: bool,
    // Inclusion and noninclusion proof pair of neighboring indices
    pub len_proof: Option<EthTransactionLenProof>,
}

impl EthTransactionProof {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> (AssignedValue<F>, MPTProof<F>) {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let idx = ctx.load_witness(F::from(self.idx as u64));
        let proof = self.proof.assign(ctx);
        (idx, proof)
    }
}

impl EthTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> Vec<EthTransactionInputAssigned<F>> {
        self.transaction_pfs
            .into_iter()
            .map(|(idx, _, pf)| {
                let proof = pf.assign(ctx);
                let transaction_index = ctx.load_witness(F::from(idx as u64));
                EthTransactionInputAssigned { transaction_index, proof }
            })
            .collect()
    }
}

impl EthBlockTransactionInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
        network: Network,
    ) -> EthBlockTransactionInputAssigned<F> {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let txs = self.txs.assign(ctx);
        let len_proof = match self.len_proof {
            Some(_len_proof) => {
                assert!(self.constrain_len);
                let len_proof =
                    [_len_proof.inclusion.assign(ctx), _len_proof.noninclusion.assign(ctx)];
                Some(len_proof)
            }
            None => {
                assert!(!self.constrain_len);
                None
            }
        };
        let max_len = get_block_header_rlp_max_lens(network).0;
        let block_header = assign_vec(ctx, self.block_header, max_len);
        EthBlockTransactionInputAssigned {
            block_header,
            txs,
            constrain_len: self.constrain_len,
            len_proof,
        }
    }
}

impl EthTransactionFieldInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTransactionFieldInputAssigned<F> {
        let transaction = EthTransactionInputAssigned {
            transaction_index: ctx.load_witness(F::from(self.transaction_index as u64)),
            proof: self.proof.assign(ctx),
        };
        let field_idx = ctx.load_witness(F::from(self.field_idx as u64));
        EthTransactionFieldInputAssigned { transaction, field_idx }
    }
}

impl EthBlockTransactionFieldInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
        network: Network,
    ) -> EthBlockTransactionFieldInputAssigned<F> {
        let max_len = get_block_header_rlp_max_lens(network).0;
        let block_header = assign_vec(ctx, self.block_header, max_len);
        EthBlockTransactionFieldInputAssigned {
            block_header,
            single_field: self.tx_input.assign(ctx),
        }
    }
}

impl EthBlockTransactionFieldsInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
    ) -> EthBlockTransactionFieldsInputAssigned<F> {
        let block_header = self
            .block_header
            .clone()
            .into_iter()
            .map(|b| ctx.load_witness(F::from(b as u64)))
            .collect_vec();
        let txs = self.txs.into_iter().map(|input| input.assign(ctx)).collect_vec();
        let len_proof = if let Some(proof) = self.len_proof {
            let i_idx = ctx.load_witness(F::from(proof.inclusion.idx as u64));
            let i_proof = proof.inclusion.proof.assign(ctx);
            let e_idx = ctx.load_witness(F::from(proof.noninclusion.idx as u64));
            let e_proof = proof.noninclusion.proof.assign(ctx);
            Some([(i_idx, i_proof), (e_idx, e_proof)])
        } else {
            None
        };
        EthBlockTransactionFieldsInputAssigned {
            block_header,
            txs,
            constrain_len: self.constrain_len,
            len_proof,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthTransactionInputAssigned<F: Field> {
    /// idx is the transaction index, varying from 0 to around 500
    pub transaction_index: AssignedValue<F>,
    pub proof: MPTProof<F>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionFieldInputAssigned<F: Field> {
    pub transaction: EthTransactionInputAssigned<F>,
    pub field_idx: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionInputAssigned<F: Field> {
    // block_hash: AssignedH256<F>, // H256 as (u128, u128)
    pub block_header: Vec<AssignedValue<F>>,
    pub txs: Vec<EthTransactionInputAssigned<F>>,
    pub constrain_len: bool,
    // Inclusion and noninclusion proof pair of neighboring indices
    pub len_proof: Option<[(AssignedValue<F>, MPTProof<F>); 2]>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionFieldInputAssigned<F: Field> {
    // block_hash: AssignedH256<F>, // H256 as (u128, u128)
    pub block_header: Vec<AssignedValue<F>>,
    pub single_field: EthTransactionFieldInputAssigned<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionFieldsInputAssigned<F: Field> {
    pub block_header: Vec<AssignedValue<F>>,
    pub txs: Vec<EthTransactionFieldInputAssigned<F>>,
    pub constrain_len: bool,
    pub len_proof: Option<[(AssignedValue<F>, MPTProof<F>); 2]>,
}
