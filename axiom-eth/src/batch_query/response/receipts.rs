//! Receipts Response
use std::{cell::RefCell, iter, rc::Rc};

use super::{
    block_header::{assign_and_verify_block_mmr, BlockResponse},
    ByteArray, FixedByteArray,
};
use crate::{
    batch_query::{
        hash::{poseidon_packed, poseidon_tree_root, PoseidonWords},
        response::block_header::MMR_MAX_NUM_PEAKS,
        DummyEccChip, EccInstructions,
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    receipt::{EthBlockReceiptFieldInput, EthBlockReceiptFieldTraceWitness, EthReceiptChip},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::FIRST_PHASE,
        RlpChip,
    },
    util::{bytes_be_to_u128, num_to_bytes_be, AssignedH256},
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, Network, ETH_LOOKUP_BITS,
};
#[cfg(feature = "providers")]
use crate::{providers::get_block_receipt_input, receipt::ReceiptRequest};
use ethers_core::types::H256;
use ethers_providers::JsonRpcClient;
#[cfg(feature = "providers")]
use ethers_providers::Provider;
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::{
        bn256::{Fr, G1Affine},
        CurveAffine,
    },
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;

use serde::{Deserialize, Serialize};
use snark_verifier::{
    loader::halo2::{Halo2Loader, Scalar},
    util::hash::Poseidon,
};
use snark_verifier_sdk::halo2::POSEIDON_SPEC;

#[derive(Clone, Debug)]
pub struct ReceiptResponse<F: ScalarField> {
    pub block_num: FixedByteArray<F>,       // left pad with zeros
    pub transaction_idx: FixedByteArray<F>, // left pad with zeros
    pub field_idx: FixedByteArray<F>,       // left pad with zeros
    pub log_idx: FixedByteArray<F>,         // left pad with zeros
    pub value: ByteArray<F>,                // variable length
}

impl<F: Field> ReceiptResponse<F> {
    pub fn from_witness(
        witness: &EthBlockReceiptFieldTraceWitness<F>,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
    ) -> Self {
        let block_num = witness.block.get_number();
        let block_num = ByteArray::from(block_num).to_fixed(ctx, range.gate());
        let tx_idx = witness.receipt.receipt_witness.tx_idx;
        let transaction_idx = FixedByteArray(num_to_bytes_be(ctx, range, &tx_idx, 4));
        // single byte
        let field_idx = FixedByteArray(vec![witness.receipt.field_idx]);
        // single byte
        let log_idx = FixedByteArray(vec![witness.receipt.log_idx]);
        let value = ByteArray {
            bytes: witness.receipt.value_bytes.clone(),
            var_len: Some(witness.receipt.value_len),
        };
        Self { block_num, transaction_idx, field_idx, log_idx, value }
    }

    pub fn poseidon<C, EccChip, const T: usize, const RATE: usize>(
        &self,
        loader: &Rc<Halo2Loader<C, EccChip>>,
        poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
    ) -> Scalar<C, EccChip>
    where
        F: Field,
        C: CurveAffine<ScalarExt = F>,
        EccChip: EccInstructions<F, C>,
    {
        let [block_num, transaction_idx, field_idx, log_idx, value] = [
            &self.block_num,
            &self.transaction_idx,
            &self.field_idx,
            &self.log_idx,
            &FixedByteArray(self.value.bytes.clone()),
        ]
        .map(|x| x.to_poseidon_words(loader));
        poseidon_packed(
            poseidon,
            block_num
                .concat(&transaction_idx)
                .concat(&field_idx)
                .concat(&log_idx)
                .concat(&value)
                .concat(&PoseidonWords::from(
                    loader.scalar_from_assigned(self.value.var_len.unwrap()),
                )),
        )
    }
}

pub fn get_receipt_response_keccak_root<'a, F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    keccak: &mut KeccakChip<F>,
    responses: impl IntoIterator<Item = &'a ReceiptResponse<F>>,
) -> AssignedH256<F> {
    let leaves: Vec<_> = responses
        .into_iter()
        .map(|rc| {
            let response_chain = [
                rc.block_num.as_ref(),
                rc.transaction_idx.as_ref(),
                rc.field_idx.as_ref(),
                rc.log_idx.as_ref(),
                &rc.value.bytes[..],
            ]
            .concat();
            let var_len =
                range.gate().add(ctx, Constant(F::from(4 + 4 + 1 + 1)), rc.value.var_len.unwrap());
            let hash_id = keccak.keccak_var_len(ctx, range, response_chain, None, var_len, 10);
            keccak.var_len_queries[hash_id].output_assigned.clone()
        })
        .collect();
    let keccak_root = keccak.merkle_tree_root(ctx, range.gate(), &leaves);
    bytes_be_to_u128(ctx, range.gate(), &keccak_root).try_into().unwrap()
}

/// See [`MultiStorageCircuit`] for more details.
///
/// Assumptions:
/// * `block_responses`, `account_responses`, `storage_responses`, `not_empty` are all of the same length, which is a **power of two**.
pub fn get_receipt_response_poseidon_root<F, C, EccChip, const T: usize, const RATE: usize>(
    loader: &Rc<Halo2Loader<C, EccChip>>,
    poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
    responses: &[ReceiptResponse<F>],
) -> AssignedValue<F>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
    EccChip: EccInstructions<F, C>,
{
    let leaves: Vec<_> = responses
        .iter()
        .map(|rc| {
            let res = rc.poseidon(loader, poseidon);
            let hash = poseidon_packed(poseidon, res.into());
            PoseidonWords::from(hash)
        })
        .collect_vec();
    poseidon_tree_root(poseidon, leaves, &[]).into_assigned()
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct MultiReceiptCircuit {
    pub queries: Vec<EthBlockReceiptFieldInput>,
    pub network: Network,

    /// Merkle Mountain Range of block hashes for blocks `[0, mmr_list_len)`, in *increasing* order of peak size.
    /// Resized with 0x0 to a fixed length.
    pub mmr: [H256; MMR_MAX_NUM_PEAKS],
    /// `mmr_proofs[i]` is a Merkle proof of `block_hashes[i]` into `mmr`. Resized so `mmr_proofs[i].len() = mmr.len() - 1`
    pub mmr_proofs: Vec<[H256; MMR_MAX_NUM_PEAKS - 1]>,
    max_data_byte_len: usize,
    max_log_num: usize,
    topic_num_bounds: (usize, usize),
}

impl MultiReceiptCircuit {
    /// Creates circuit inputs from raw data. Does basic sanity checks. Number of queries must be a power of two.
    pub fn new(
        queries: Vec<EthBlockReceiptFieldInput>,
        network: Network,
        mut mmr: Vec<H256>,
        mmr_proofs: Vec<Vec<H256>>,
        max_data_byte_len: usize,
        max_log_num: usize,
        topic_num_bounds: (usize, usize),
    ) -> Self {
        assert!(queries.len().is_power_of_two(), "Number of queries must be a power of 2");
        mmr.resize(MMR_MAX_NUM_PEAKS, H256::zero());
        let mmr_proofs = mmr_proofs
            .into_iter()
            .map(|mut proof| {
                proof.resize(MMR_MAX_NUM_PEAKS - 1, H256::zero());
                proof.try_into().unwrap()
            })
            .collect();
        Self {
            queries,
            network,
            mmr: mmr.try_into().unwrap(),
            mmr_proofs,
            max_data_byte_len,
            max_log_num,
            topic_num_bounds,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        queries: Vec<ReceiptRequest>,
        network: Network,
        mmr: Vec<H256>,
        mmr_proofs: Vec<Vec<H256>>,
        max_data_byte_len: usize,
        max_log_num: usize,
        topic_num_bounds: (usize, usize),
    ) -> Self {
        use crate::receipt::{
            RECEIPT_MAX_DATA_BYTES, RECEIPT_MAX_LOG_NUM, RECEIPT_PROOF_MAX_DEPTH,
        };

        let mut inputs = Vec::new();
        for query in queries {
            let input = get_block_receipt_input(
                provider,
                query.tx_hash,
                RECEIPT_PROOF_MAX_DEPTH,
                RECEIPT_MAX_DATA_BYTES,
                RECEIPT_MAX_LOG_NUM,
                (0, 4),
            );
            let input = EthBlockReceiptFieldInput {
                input,
                field_idx: query.field_idx,
                log_idx: query.log_idx.unwrap_or(0),
            };
            inputs.push(input);
        }

        Self::new(
            inputs,
            network,
            mmr,
            mmr_proofs,
            max_data_byte_len,
            max_log_num,
            topic_num_bounds,
        )
    }
}

impl EthPreCircuit for MultiReceiptCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let eth = EthChip::new(RlpChip::new(&range, None), None);
        let chip = EthReceiptChip::new(
            &eth,
            self.max_data_byte_len,
            self.max_log_num,
            self.topic_num_bounds,
        );
        let mut keccak = KeccakChip::default();
        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let queries = self
            .queries
            .into_iter()
            .map(|query| query.assign(ctx, &range, self.network))
            .collect_vec();
        let witness = chip.parse_receipt_field_from_blocks_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            queries,
            self.network,
        );

        // process data into response formats
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let block_responses = witness
            .iter()
            .map(|w| BlockResponse::from_witness(&w.block, ctx, range.gate()))
            .collect_vec();
        let responses =
            witness.iter().map(|w| ReceiptResponse::from_witness(w, ctx, &range)).collect_vec();

        let one = ctx.load_constant(Fr::one());
        let mmr_keccaks = assign_and_verify_block_mmr(
            ctx,
            &range,
            &mut keccak,
            self.mmr,
            self.mmr_proofs,
            &block_responses,
            vec![one; block_responses.len()],
        );

        // hash responses
        let keccak_root = get_receipt_response_keccak_root(ctx, &range, &mut keccak, &responses);

        let loader =
            Halo2Loader::<G1Affine, _>::new(DummyEccChip(range.gate()), builder.gate_builder);
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());

        let assigned_instances = iter::empty()
            .chain(keccak_root)
            .chain([get_receipt_response_poseidon_root(&loader, &mut poseidon, &responses)])
            .chain(mmr_keccaks)
            .collect_vec();
        builder.gate_builder = loader.take_ctx();

        // ================= SECOND PHASE ================
        EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<Fr>,
                  rlp: RlpChip<Fr>,
                  keccak_rlcs: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {
                // ======== SECOND PHASE ===========
                let eth = EthChip::new(rlp, Some(keccak_rlcs));
                let chip = EthReceiptChip::new(
                    &eth,
                    self.max_data_byte_len,
                    self.max_log_num,
                    self.topic_num_bounds,
                );
                chip.parse_receipt_field_from_blocks_phase1(builder, witness);
            },
        )
    }
}
