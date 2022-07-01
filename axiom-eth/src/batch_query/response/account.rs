//! Account Response
use super::*;
use crate::{
    batch_query::{
        hash::{
            bytes_select_or_zero, keccak_packed, poseidon_packed, poseidon_tree_root,
            word_select_or_zero,
        },
        response::storage::DEFAULT_STORAGE_QUERY,
        DummyEccChip,
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::FIRST_PHASE,
        RlpChip,
    },
    storage::{
        EthAccountTraceWitness, EthStorageChip, EthStorageInput, ACCOUNT_PROOF_MAX_DEPTH,
        ACCOUNT_STATE_FIELD_IS_VAR_LEN,
    },
    util::{bytes_be_to_u128, load_bool},
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, ETH_LOOKUP_BITS,
};
use ethers_core::types::Address;
#[cfg(feature = "providers")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::G1Affine,
    utils::ScalarField,
    Context,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::halo2::POSEIDON_SPEC;
use std::cell::RefCell;

pub(crate) const STORAGE_ROOT_INDEX: usize = 2;

/// | Account State Field     | Max bytes   |
/// |-------------------------|-------------|
/// | nonce                   | ≤8          |
/// | balance                 | ≤12         |
/// | storageRoot             | 32          |
/// | codeHash                | 32          |
///
/// Struct that stores account state fields as an array of fixed length byte arrays.
/// For fields with variable length byte arrays, the byte arrays are left padded with 0s to the max fixed length.
#[derive(Clone, Debug)]
pub struct AccountState<F: ScalarField>(Vec<FixedByteArray<F>>);

impl<F: Field> AccountState<F> {
    pub fn keccak(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        keccak: &mut KeccakChip<F>,
    ) -> FixedByteArray<F> {
        keccak_packed(
            ctx,
            gate,
            keccak,
            FixedByteArray(self.0.iter().map(|bytes| bytes.0.to_vec()).concat()),
        )
    }
}

/// A single response to an account query.
///
/// | Field                   | Max bytes   |
/// |-------------------------|-------------|
/// | stateRoot               | 32          |
/// | address                 | 20          |
/// | accountState            |             |
///
/// ```
/// account_response = hash(stateRoot . address . hash_tree_root(account_state))
/// ```
/// This struct stores all the data necessary to compute the above hash.
#[derive(Clone, Debug)]
pub struct AccountResponse<F: ScalarField> {
    pub state_root: FixedByteArray<F>,
    pub address: FixedByteArray<F>,
    pub account_state: AccountState<F>,
}

impl<F: Field> AccountResponse<F> {
    pub fn from_witness(
        witness: &EthAccountTraceWitness<F>,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> Self {
        let state_root = FixedByteArray(witness.mpt_witness.root_hash_bytes.clone());
        let address = FixedByteArray(witness.address.clone());
        let account_state = AccountState(
            witness
                .array_witness
                .field_witness
                .iter()
                .enumerate()
                .map(|(i, field)| {
                    if ACCOUNT_STATE_FIELD_IS_VAR_LEN[i] {
                        let field: ByteArray<F> = field.into();
                        field.to_fixed(ctx, gate)
                    } else {
                        field.into()
                    }
                })
                .collect_vec(),
        );
        Self { address, state_root, account_state }
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
        let account_state =
            self.account_state.0.iter().map(|x| x.to_poseidon_words(loader)).collect_vec();
        // Uses fact that account_state length is power of 2
        let account_state_hash = poseidon_tree_root(poseidon, account_state, &[]);
        let [state_root, address] =
            [&self.state_root, &self.address].map(|x| x.to_poseidon_words(loader));
        poseidon_packed(poseidon, state_root.concat(&address).concat(&account_state_hash.into()))
    }
}

/// See [`MultiAccountCircuit`] for more details.
///
/// Assumptions:
/// * `block_responses`, `account_responses`, `not_empty` are all of the same length, which is a **power of two**.
///
/// Returns `(keccak_tree_root(full_account_responses.keccak), account_responses.keccak)`
pub fn get_account_response_keccak_root<'a, F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    keccak: &mut KeccakChip<F>,
    block_numbers: impl IntoIterator<Item = &'a FixedByteArray<F>>,
    account_responses: impl IntoIterator<Item = &'a AccountResponse<F>>,
    not_empty: impl IntoIterator<Item = AssignedValue<F>>,
) -> FixedByteArray<F> {
    let full_responses: Vec<_> = block_numbers
        .into_iter()
        .zip_eq(account_responses)
        .zip_eq(not_empty)
        .map(|((bytes, account), not_empty)| {
            let keccak_account_state = account.account_state.keccak(ctx, gate, keccak);
            let hash = keccak_packed(
                ctx,
                gate,
                keccak,
                bytes.concat(&account.address).concat(&keccak_account_state),
            );
            bytes_select_or_zero(ctx, gate, hash, not_empty).0
        })
        .collect();
    let keccak_root = keccak.merkle_tree_root(ctx, gate, &full_responses);
    FixedByteArray(bytes_be_to_u128(ctx, gate, &keccak_root))
}

/// See [`MultiAccountCircuit`] for more details.
///
/// Assumptions:
/// * `block_responses`, `account_responses`, `not_empty` are all of the same length, which is a **power of two**.
pub fn get_account_response_poseidon_roots<F, C, EccChip, const T: usize, const RATE: usize>(
    loader: &Rc<Halo2Loader<C, EccChip>>,
    poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
    block_responses: Vec<(F, FixedByteArray<F>)>,
    account_responses: &[AccountResponse<F>],
    not_empty: Vec<AssignedValue<F>>,
) -> Vec<AssignedValue<F>>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
    EccChip: EccInstructions<F, C>,
{
    let (block_responses_keccak_hi_lo, full_responses): (Vec<_>, Vec<_>) = block_responses
        .into_iter()
        .zip_eq(account_responses.iter())
        .zip_eq(not_empty)
        .map(|(((word, bytes), account), not_empty)| {
            let account_hash = account.poseidon(loader, poseidon);
            let word = loader.assign_scalar(word);
            let block_response_keccak_hi_lo = bytes.to_poseidon_words(loader);

            let hash = poseidon_packed(poseidon, PoseidonWords(vec![word, account_hash]));
            (
                block_response_keccak_hi_lo,
                PoseidonWords::from(word_select_or_zero(loader, hash, not_empty)),
            )
        })
        .unzip();

    let [poseidon_root, block_response_root] = [full_responses, block_responses_keccak_hi_lo]
        .map(|leaves| poseidon_tree_root(poseidon, leaves, &[]).into_assigned());
    vec![poseidon_root, block_response_root]
}

// switching to just Fr for simplicity:

/// The input datum for the circuit to generate multiple account responses. It is used to generate a circuit.
///
/// Assumptions:
/// * `block_responses`, `queries`, `not_empty` are all of the same length, which is a **power of two**.
/// * `block_responses` has length greater than 1: the length 1 case still works but cannot be aggregated because
/// the single leaf of `block_responses[0].1` would get hashed as two words, whereas in a larger tree it gets
/// concatenated before hashing.
///
/// The public instances of this circuit are 5 field elements:
/// * Keccak merkle tree root of `keccak(block_number[i] . address[i] . keccak_account_state[i])` over all queries: two field elements in hi-lo u128 format
/// * Poseidon merkle tree root of `full_response[i].poseidon := poseidon(block_responses[i].0 . account_responses[i].0)` over all queries: single field element
/// * Poseidon merkle tree root of `block_number[i]` over all queries: single field element
///
/// Above `account_responses` refers to the hash of `AccountResponse`s generated by the circuit for all queries.
/// Since `block_number`s are given as private inputs, we need to expose a *Poseidon* merkle root of all `block_number`s to be checked again the BlockResponses.
// For compatibility with aggregation we keep all the poseidon roots together in the instance
#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct MultiAccountCircuit {
    /// The block responses are provided as UNCHECKED private inputs; they will be checked in a separate circuit
    pub block_responses: Vec<(Fr, u32)>,
    /// The account queries
    pub queries: Vec<EthStorageInput>, // re-use EthStorageInput but storage pf will be empty
    /// Private input to allow full_response[i].hash to be `Fr::zero()` or `H256(0x0)` for empty response
    pub not_empty: Vec<bool>,
}

pub const ACCOUNT_INSTANCE_SIZE: usize = 4;
pub(crate) const KECCAK_ACCOUNT_FULL_RESPONSE_INDEX: usize = 0;
pub(crate) const ACCOUNT_FULL_RESPONSE_POSEIDON_INDEX: usize = 2;
pub(crate) const ACCOUNT_BLOCK_RESPONSE_KECCAK_INDEX: usize = 3;
pub(crate) const ACCOUNT_POSEIDON_ROOT_INDICES: &[usize] =
    &[ACCOUNT_FULL_RESPONSE_POSEIDON_INDEX, ACCOUNT_BLOCK_RESPONSE_KECCAK_INDEX];
pub(crate) const ACCOUNT_KECCAK_ROOT_INDICES: &[usize] = &[KECCAK_ACCOUNT_FULL_RESPONSE_INDEX];

impl MultiAccountCircuit {
    /// Creates circuit inputs from raw data and does basic input validation. Number of queries must be power of two.
    pub fn new(
        block_responses: Vec<(Fr, u32)>,
        queries: Vec<EthStorageInput>,
        not_empty: Vec<bool>,
    ) -> Self {
        assert!(block_responses.len() > 1);
        assert_eq!(block_responses.len(), queries.len());
        assert_eq!(queries.len(), not_empty.len());
        assert!(queries.len().is_power_of_two(), "Number of queries must be a power of 2");
        Self { block_responses, queries, not_empty }
    }

    /// Creates circuit inputs from a JSON-RPC provider.
    #[cfg(feature = "providers")]
    pub fn from_provider(
        provider: &Provider<Http>,
        block_responses: Vec<(Fr, u32)>,
        queries: Vec<(u64, Address)>,
        not_empty: Vec<bool>,
    ) -> Self {
        use crate::providers::get_account_queries;
        let queries = get_account_queries(provider, queries, ACCOUNT_PROOF_MAX_DEPTH);
        Self::new(block_responses, queries, not_empty)
    }

    /// Resizes inputs to `new_len` queries, using [`DEFAULT_ACCOUNT_QUERY`] for new queries.
    pub fn resize_from(
        mut block_responses: Vec<(Fr, u32)>,
        mut queries: Vec<EthStorageInput>,
        mut not_empty: Vec<bool>,
        new_len: usize,
    ) -> Self {
        block_responses.resize(new_len, (Fr::zero(), 0));
        queries.resize_with(new_len, || DEFAULT_ACCOUNT_QUERY.clone());
        not_empty.resize(new_len, false);
        Self::new(block_responses, queries, not_empty)
    }
}

impl EthPreCircuit for MultiAccountCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();
        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let queries = self
            .queries
            .into_iter()
            .map(|query| {
                let query = query.assign_account(ctx, &range);
                (query.address.0, query.acct_pf)
            })
            .collect_vec();
        let witness =
            chip.parse_account_proofs_phase0(&mut builder.gate_builder, &mut keccak, queries);
        // constrain all accounts exist
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let (account_responses, not_empty): (Vec<_>, Vec<_>) = witness
            .iter()
            .zip_eq(self.not_empty)
            .map(|(w, not_empty)| {
                let not_empty = load_bool(ctx, range.gate(), not_empty);
                // we only check if the MPT key is not empty if `not_empty = true`; otherwise we don't care
                let key_check = range.gate().mul(ctx, w.mpt_witness.slot_is_empty, not_empty);
                range.gate().assert_is_const(ctx, &key_check, &Fr::zero());
                (AccountResponse::from_witness(w, ctx, range.gate()), not_empty)
            })
            .unzip();
        let block_responses = self
            .block_responses
            .into_iter()
            .map(|(word, num)| {
                let keccak_bytes = FixedByteArray::new(ctx, &range, &num.to_be_bytes());
                (word, keccak_bytes)
            })
            .collect_vec();
        // hash responses
        let keccak_root = get_account_response_keccak_root(
            ctx,
            range.gate(),
            &mut keccak,
            block_responses.iter().map(|(_, bytes)| bytes),
            &account_responses,
            not_empty.clone(),
        );
        let loader =
            Halo2Loader::<G1Affine, _>::new(DummyEccChip(range.gate()), builder.gate_builder);
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());

        let mut assigned_instances = keccak_root.0;
        assigned_instances.extend(get_account_response_poseidon_roots(
            &loader,
            &mut poseidon,
            block_responses,
            &account_responses,
            not_empty,
        ));
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
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                chip.parse_account_proofs_phase1(builder, witness);
            },
        )
    }
}

lazy_static! {
    pub static ref DEFAULT_ACCOUNT_QUERY: EthStorageInput = {
        let mut query = DEFAULT_STORAGE_QUERY.clone();
        query.storage_pfs.clear();
        query
    };
}
