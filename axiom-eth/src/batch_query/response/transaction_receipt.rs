//! Receipt Response
use std::cell::RefCell;

use super::{
    block_header::{assign_and_verify_block_mmr, BlockResponse, MMR_MAX_NUM_PEAKS},
    receipts::{
        get_receipt_response_keccak_root, get_receipt_response_poseidon_root, ReceiptResponse,
    },
    transaction::{
        get_transaction_response_keccak_root, get_transaction_response_poseidon_roots,
        TransactionResponse,
    },
    *,
};
#[cfg(feature = "providers")]
use crate::receipt::ReceiptRequest;
#[cfg(feature = "providers")]
use crate::transaction::TransactionRequest;
use crate::{
    batch_query::{DummyEccChip, EccInstructions},
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    receipt::{EthBlockReceiptFieldInput, EthReceiptChip},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::FIRST_PHASE,
        RlpChip,
    },
    transaction::{EthBlockTransactionFieldInput, EthTransactionChip},
    EthChip, EthCircuitBuilder, EthPreCircuit, Network, ETH_LOOKUP_BITS,
};

use ethers_core::types::H256;
use ethers_providers::JsonRpcClient;
#[cfg(feature = "providers")]
use ethers_providers::Provider;
use halo2_base::{
    gates::{RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::G1Affine,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::halo2::POSEIDON_SPEC;

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct MultiTransactionReceiptCircuit {
    /// The blockreceiptfield queries
    pub tx_queries: Vec<EthBlockTransactionFieldInput>,
    pub rc_queries: Vec<EthBlockReceiptFieldInput>,
    pub network: Network,

    /// Merkle Mountain Range of block hashes for blocks `[0, mmr_list_len)`, in *increasing* order of peak size.
    /// Resized with 0x0 to a fixed length.
    pub mmr: [H256; MMR_MAX_NUM_PEAKS],
    /// `mmr_proofs[i]` is a Merkle proof of `block_hashes[i]` into `mmr`. Resized so `mmr_proofs[i].len() = mmr.len() - 1`
    pub tx_mmr_proofs: Vec<[H256; MMR_MAX_NUM_PEAKS - 1]>,
    pub rc_mmr_proofs: Vec<[H256; MMR_MAX_NUM_PEAKS - 1]>,
    pub tx_max_data_byte_len: usize,
    pub tx_max_access_list_len: usize,
    pub tx_enable_types: [bool; 3],
    pub rc_max_data_byte_len: usize,
    pub rc_max_log_num: usize,
    pub rc_topic_num_bounds: (usize, usize),
}

impl MultiTransactionReceiptCircuit {
    /// Creates circuit inputs from raw data. Does basic sanity checks. Number of queries must be a power of two.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_queries: Vec<EthBlockTransactionFieldInput>,
        rc_queries: Vec<EthBlockReceiptFieldInput>,
        network: Network,
        mut mmr: Vec<H256>,
        tx_mmr_proofs: Vec<Vec<H256>>,
        rc_mmr_proofs: Vec<Vec<H256>>,
        tx_max_data_byte_len: usize,
        tx_max_access_list_len: usize,
        tx_enable_types: [bool; 3],
        rc_max_data_byte_len: usize,
        rc_max_log_num: usize,
        rc_topic_num_bounds: (usize, usize),
    ) -> Self {
        assert!(rc_queries.len().is_power_of_two(), "Number of queries must be a power of 2");
        // assert!(tx_queries.len().is_power_of_two(), "Number of queries must be a power of 2");
        mmr.resize(MMR_MAX_NUM_PEAKS, H256::zero());
        let [tx_mmr_proofs, rc_mmr_proofs] = [tx_mmr_proofs, rc_mmr_proofs].map(|pfs| {
            pfs.into_iter()
                .map(|mut proof| {
                    proof.resize(MMR_MAX_NUM_PEAKS - 1, H256::zero());
                    proof.try_into().unwrap()
                })
                .collect()
        });
        Self {
            tx_queries,
            rc_queries,
            network,
            mmr: mmr.try_into().unwrap(),
            tx_mmr_proofs,
            rc_mmr_proofs,
            tx_max_data_byte_len,
            tx_max_access_list_len,
            tx_enable_types,
            rc_max_data_byte_len,
            rc_max_log_num,
            rc_topic_num_bounds,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        tx_queries: Vec<TransactionRequest>,
        rc_queries: Vec<ReceiptRequest>,
        network: Network,
        mmr: Vec<H256>,
        tx_mmr_proofs: Vec<Vec<H256>>,
        rc_mmr_proofs: Vec<Vec<H256>>,
        tx_max_data_byte_len: usize,
        tx_max_access_list_len: usize,
        tx_enable_types: [bool; 3],
        rc_max_data_byte_len: usize,
        rc_max_log_num: usize,
        rc_topic_num_bounds: (usize, usize),
    ) -> Self {
        use ethers_providers::Middleware;
        use tokio::runtime::Runtime;

        use crate::{
            providers::{get_block_receipt_input, get_block_transaction_input},
            receipt::RECEIPT_PROOF_MAX_DEPTH,
            transaction::{EthTransactionFieldInput, TRANSACTION_PROOF_MAX_DEPTH},
        };
        let mut rc_inputs = Vec::new();
        for query in rc_queries {
            let input = get_block_receipt_input(
                provider,
                query.tx_hash,
                RECEIPT_PROOF_MAX_DEPTH,
                rc_max_data_byte_len,
                rc_max_log_num,
                rc_topic_num_bounds,
            );
            let input = EthBlockReceiptFieldInput {
                input,
                field_idx: query.field_idx,
                log_idx: query.log_idx.unwrap_or(0),
            };
            rc_inputs.push(input);
        }
        let rt = Runtime::new().unwrap();
        let mut tx_inputs = vec![];
        for query in tx_queries {
            let tx = rt
                .block_on(provider.get_transaction(query.tx_hash))
                .unwrap()
                .unwrap_or_else(|| panic!("Transaction {} not found", query.tx_hash));
            let block_number = tx.block_number.unwrap();
            let transaction_index = tx.transaction_index.unwrap().as_usize();
            let input = get_block_transaction_input(
                provider,
                vec![transaction_index],
                block_number.as_u32(),
                TRANSACTION_PROOF_MAX_DEPTH,
                tx_max_data_byte_len,
                tx_max_access_list_len, // no access list support for now
                tx_enable_types,        // only support legacy and EIP-1559
                false,
            );
            let tx_input = EthTransactionFieldInput {
                transaction_index,
                proof: input.txs.transaction_pfs[0].2.clone(),
                field_idx: query.field_idx as usize,
            };
            let input = EthBlockTransactionFieldInput {
                block_number: input.block_number,
                block_hash: input.block_hash,
                block_header: input.block_header,
                tx_input,
                constrain_len: input.constrain_len,
                len_proof: input.len_proof,
            };
            tx_inputs.push(input);
        }

        Self::new(
            tx_inputs,
            rc_inputs,
            network,
            mmr,
            tx_mmr_proofs,
            rc_mmr_proofs,
            tx_max_data_byte_len,
            tx_max_access_list_len,
            tx_enable_types,
            rc_max_data_byte_len,
            rc_max_log_num,
            rc_topic_num_bounds,
        )
    }
}

impl EthPreCircuit for MultiTransactionReceiptCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let eth = EthChip::new(RlpChip::new(&range, None), None);
        let tx_chip = EthTransactionChip::new(
            &eth,
            self.tx_max_data_byte_len,
            self.tx_max_access_list_len,
            self.tx_enable_types,
        );
        let rc_chip = EthReceiptChip::new(
            &eth,
            self.rc_max_data_byte_len,
            self.rc_max_log_num,
            self.rc_topic_num_bounds,
        );
        let mut keccak = KeccakChip::default();
        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let rc_queries = self
            .rc_queries
            .into_iter()
            .map(|query| query.assign(ctx, &range, self.network))
            .collect_vec();
        let tx_queries =
            self.tx_queries.into_iter().map(|query| query.assign(ctx, self.network)).collect_vec();

        let rc_witness = rc_chip.parse_receipt_field_from_blocks_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            rc_queries,
            self.network,
        );
        let tx_witness = tx_chip.parse_transaction_field_from_blocks_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            tx_queries,
            self.network,
        );

        // process data into response formats
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let rc_block_responses = rc_witness
            .iter()
            .map(|w| BlockResponse::from_witness(&w.block, ctx, range.gate()))
            .collect_vec();
        let receipt_responses =
            rc_witness.iter().map(|w| ReceiptResponse::from_witness(w, ctx, &range)).collect_vec();
        let tx_block_responses = tx_witness
            .iter()
            .map(|w| BlockResponse::from_witness(&w.block, ctx, range.gate()))
            .collect_vec();
        let tx_responses = tx_witness
            .iter()
            .map(|w| TransactionResponse::from_witness(w, ctx, &range))
            .collect_vec();

        // verify mmr
        let one = ctx.load_constant(Fr::one());
        let rc_mmr_keccaks = assign_and_verify_block_mmr(
            ctx,
            &range,
            &mut keccak,
            self.mmr,
            self.rc_mmr_proofs,
            &rc_block_responses,
            vec![one; rc_block_responses.len()],
        );
        let tx_mmr_keccaks = assign_and_verify_block_mmr(
            ctx,
            &range,
            &mut keccak,
            self.mmr,
            self.tx_mmr_proofs,
            &tx_block_responses,
            vec![one; tx_block_responses.len()],
        );
        for (b1, b2) in rc_mmr_keccaks.iter().zip_eq(tx_mmr_keccaks.iter()) {
            ctx.constrain_equal(b1, b2);
        }

        // hash responses
        let tx_keccak_root =
            get_transaction_response_keccak_root(ctx, &range, &mut keccak, &tx_responses);
        let rc_keccak_root =
            get_receipt_response_keccak_root(ctx, &range, &mut keccak, &receipt_responses);

        let loader =
            Halo2Loader::<G1Affine, _>::new(DummyEccChip(range.gate()), builder.gate_builder);
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());
        let assigned_instances = iter::empty()
            .chain(get_transaction_response_poseidon_roots(&loader, &mut poseidon, &tx_responses))
            .chain(tx_keccak_root)
            .chain([get_receipt_response_poseidon_root(&loader, &mut poseidon, &receipt_responses)])
            .chain(rc_keccak_root)
            .chain(rc_mmr_keccaks)
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
                let tx_chip = EthTransactionChip::new(
                    &eth,
                    self.tx_max_data_byte_len,
                    self.tx_max_access_list_len,
                    self.tx_enable_types,
                );
                let rc_chip = EthReceiptChip::new(
                    &eth,
                    self.rc_max_data_byte_len,
                    self.rc_max_log_num,
                    self.rc_topic_num_bounds,
                );
                rc_chip.parse_receipt_field_from_blocks_phase1(builder, rc_witness);
                tx_chip.parse_transaction_field_from_blocks_phase1(builder, tx_witness);
            },
        )
    }
}
