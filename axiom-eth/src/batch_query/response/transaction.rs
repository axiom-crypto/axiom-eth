//! Transaction Response
use std::cell::RefCell;

use super::{
    block_header::{assign_and_verify_block_mmr, BlockResponse},
    *,
};
use crate::{
    batch_query::{
        hash::{poseidon_packed, poseidon_tree_root},
        response::block_header::MMR_MAX_NUM_PEAKS,
        DummyEccChip, EccInstructions,
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::FIRST_PHASE,
        RlpChip,
    },
    transaction::{
        EthBlockTransactionFieldInput, EthBlockTransactionFieldTraceWitness, EthTransactionChip,
        EthTransactionFieldInput,
    },
    util::{bytes_be_to_u128, num_to_bytes_be, AssignedH256},
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, Network, ETH_LOOKUP_BITS,
};

use ethers_core::types::H256;
use ethers_providers::JsonRpcClient;
#[cfg(feature = "providers")]
use ethers_providers::Provider;
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::G1Affine,
    utils::ScalarField,
    Context,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::halo2::POSEIDON_SPEC;

#[derive(Clone, Debug)]
pub struct TransactionResponse<F: ScalarField> {
    pub block_num: FixedByteArray<F>,        // left pad with zeros
    pub transaction_idx: FixedByteArray<F>,  // left pad with zeros
    pub transaction_type: FixedByteArray<F>, // left pad with zeros
    pub field_idx: FixedByteArray<F>,        // left pad with zeros
    pub field_value: ByteArray<F>,           // variable length
}

impl<F: Field> TransactionResponse<F> {
    pub fn from_witness(
        witness: &EthBlockTransactionFieldTraceWitness<F>,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
    ) -> Self {
        let block_num = witness.block.get_number();
        let block_num = ByteArray::from(block_num).to_fixed(ctx, range.gate());
        let idx = witness.txs[0].transaction_witness.idx;
        let transaction_idx = num_to_bytes_be(ctx, range, &idx, 4);

        let field_idx = FixedByteArray(vec![witness.txs[0].field_idx]);
        let transaction_idx = FixedByteArray(transaction_idx);
        let transaction_type = FixedByteArray(vec![witness.txs[0].transaction_type]);

        let field_value = ByteArray {
            bytes: witness.txs[0].field_bytes.clone(),
            var_len: Some(witness.txs[0].len),
        };
        Self { block_num, transaction_idx, transaction_type, field_idx, field_value }
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
        //println!("RESPONSE: {:?}", self.field_value.var_len);
        //println!("RESPONSE: {:?}", &self.field_value.bytes[0..4]);
        let [block_num, transaction_idx, transaction_type, field_idx, field_value] = [
            &self.block_num,
            &self.transaction_idx,
            &self.transaction_type,
            &self.field_idx,
            &FixedByteArray(self.field_value.bytes.clone()),
        ]
        .map(|x| x.to_poseidon_words(loader));
        poseidon_packed(
            poseidon,
            block_num
                .concat(&transaction_idx)
                .concat(&transaction_type)
                .concat(&field_idx)
                .concat(&field_value)
                .concat(&PoseidonWords::from(
                    loader.scalar_from_assigned(self.field_value.var_len.unwrap()),
                )),
        )
    }
}

pub fn get_transaction_response_keccak_root<'a, F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    keccak: &mut KeccakChip<F>,
    transaction_responses: impl IntoIterator<Item = &'a TransactionResponse<F>>,
) -> AssignedH256<F> {
    let full_responses: Vec<_> = transaction_responses
        .into_iter()
        .map(|transaction| {
            let response_chain = transaction
                .block_num
                .0
                .clone()
                .into_iter()
                .chain(transaction.transaction_idx.0.clone().into_iter())
                .chain(transaction.transaction_type.0.clone().into_iter())
                .chain(transaction.field_idx.0.clone().into_iter())
                .chain(transaction.field_value.bytes.clone())
                .collect_vec();
            // keccak_storage = keccak(block_response . acct_response . storage_response)
            let var_len = Some(range.gate().add(
                ctx,
                Constant(F::from(10)),
                transaction.field_value.var_len.unwrap(),
            ));
            let hash_id =
                keccak.keccak_var_len(ctx, range, response_chain, None, var_len.unwrap(), 10);
            keccak.var_len_queries[hash_id].output_assigned.clone()
        })
        .collect();
    let keccak_root = keccak.merkle_tree_root(ctx, range.gate(), &full_responses);
    bytes_be_to_u128(ctx, range.gate(), &keccak_root).try_into().unwrap()
}

pub fn get_transaction_response_poseidon_roots<F, C, EccChip, const T: usize, const RATE: usize>(
    loader: &Rc<Halo2Loader<C, EccChip>>,
    poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
    transaction_responses: &[TransactionResponse<F>],
) -> Vec<AssignedValue<F>>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
    EccChip: EccInstructions<F, C>,
{
    let full_responses: Vec<_> = transaction_responses
        .iter()
        .map(|transaction| {
            let transaction_response = transaction.poseidon(loader, poseidon);
            // full_response = hash(block_response . acct_response . storage_response)
            let hash = poseidon_packed(poseidon, PoseidonWords(vec![transaction_response]));
            PoseidonWords::from(hash)
        })
        .collect_vec();
    let [poseidon_root] =
        [full_responses].map(|leaves| poseidon_tree_root(poseidon, leaves, &[]).into_assigned());
    vec![poseidon_root]
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct MultiTransactionCircuit {
    /// The blocktransactionfield queries
    pub queries: Vec<EthBlockTransactionFieldInput>,
    pub network: Network,

    /// Merkle Mountain Range of block hashes for blocks `[0, mmr_list_len)`, in *increasing* order of peak size.
    /// Resized with 0x0 to a fixed length.
    pub mmr: [H256; MMR_MAX_NUM_PEAKS],
    /// `mmr_proofs[i]` is a Merkle proof of `block_hashes[i]` into `mmr`. Resized so `mmr_proofs[i].len() = mmr.len() - 1`
    pub mmr_proofs: Vec<[H256; MMR_MAX_NUM_PEAKS - 1]>,
    pub max_data_byte_len: usize,
    pub max_access_list_len: usize,
    pub enable_types: [bool; 3],
}

impl MultiTransactionCircuit {
    /// Creates circuit inputs from raw data. Does basic sanity checks. Number of queries must be a power of two.
    pub fn new(
        queries: Vec<EthBlockTransactionFieldInput>,
        network: Network,
        mut mmr: Vec<H256>,
        mmr_proofs: Vec<Vec<H256>>,
        max_data_byte_len: usize,
        max_access_list_len: usize,
        enable_types: [bool; 3],
    ) -> Self {
        let len = queries.len();
        assert!(len > 1);
        assert!(len.is_power_of_two(), "Number of queries must be a power of 2");
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
            max_access_list_len,
            enable_types,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        queries: Vec<(usize, usize)>,
        block_numbers: Vec<u32>,
        network: Network,
        mmr: Vec<H256>,
        mmr_proofs: Vec<Vec<H256>>,
        max_data_byte_len: usize,
        max_access_list_len: usize,
        enable_types: [bool; 3],
    ) -> Self {
        use crate::{
            providers::get_block_transaction_input, transaction::TRANSACTION_PROOF_MAX_DEPTH,
        };
        let mut inputs = Vec::new();
        assert_eq!(block_numbers.len(), queries.len());
        for i in 0..block_numbers.len() {
            let transaction_index = queries[i].0;
            let input = get_block_transaction_input(
                provider,
                vec![transaction_index],
                block_numbers[i],
                TRANSACTION_PROOF_MAX_DEPTH,
                max_data_byte_len,
                max_access_list_len,
                enable_types,
                false,
            );
            let tx_input = EthTransactionFieldInput {
                transaction_index,
                proof: input.txs.transaction_pfs[0].2.clone(),
                field_idx: queries[i].1,
            };
            let input = EthBlockTransactionFieldInput {
                block_number: input.block_number,
                block_hash: input.block_hash,
                block_header: input.block_header,
                tx_input,
                constrain_len: input.constrain_len,
                len_proof: input.len_proof,
            };
            inputs.push(input);
        }

        Self::new(
            inputs,
            network,
            mmr,
            mmr_proofs,
            max_data_byte_len,
            max_access_list_len,
            enable_types,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resize_from(
        mut queries: Vec<EthBlockTransactionFieldInput>,
        new_len: usize,
        network: Network,
        mmr: Vec<H256>,
        _mmr_list_len: usize,
        mut mmr_proofs: Vec<Vec<H256>>,
        max_data_byte_len: usize,
        max_access_list_len: usize,
        enable_types: [bool; 3],
    ) -> Self {
        assert!(!queries.is_empty());
        assert!(queries.len() == mmr_proofs.len());
        let default = queries[0].clone();
        let default_proof = mmr_proofs[0].clone();
        queries.resize_with(new_len, || default.clone());
        mmr_proofs.resize(new_len, default_proof);
        Self::new(
            queries,
            network,
            mmr,
            mmr_proofs,
            max_data_byte_len,
            max_access_list_len,
            enable_types,
        )
    }
}

impl EthPreCircuit for MultiTransactionCircuit {
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
        let queries =
            self.queries.into_iter().map(|query| query.assign(ctx, self.network)).collect_vec();
        let witness = chip.parse_transaction_field_from_blocks_phase0(
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
        let transaction_responses =
            witness.iter().map(|w| TransactionResponse::from_witness(w, ctx, &range)).collect_vec();

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
        let keccak_root =
            get_transaction_response_keccak_root(ctx, &range, &mut keccak, &transaction_responses);

        let loader =
            Halo2Loader::<G1Affine, _>::new(DummyEccChip(range.gate()), builder.gate_builder);
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());

        let mut assigned_instances =
            get_transaction_response_poseidon_roots(&loader, &mut poseidon, &transaction_responses);
        assigned_instances.extend(keccak_root.into_iter().chain(mmr_keccaks));
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
                let chip = EthTransactionChip::new(
                    &eth,
                    self.max_data_byte_len,
                    self.max_access_list_len,
                    self.enable_types,
                );
                chip.parse_transaction_field_from_blocks_phase1(builder, witness);
            },
        )
    }
}
