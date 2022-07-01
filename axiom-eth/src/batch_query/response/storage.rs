//! Storage Response
use std::{cell::RefCell, str::FromStr};

use super::*;
use crate::{
    batch_query::{
        hash::{
            bytes_select_or_zero, keccak_packed, poseidon_packed, poseidon_tree_root,
            word_select_or_zero,
        },
        DummyEccChip, EccInstructions,
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    mpt::MPTFixedKeyInput,
    providers::{get_acct_list, get_acct_rlp},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::FIRST_PHASE,
        RlpChip,
    },
    storage::{
        EthStorageChip, EthStorageInput, EthStorageTraceWitness, ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        STORAGE_PROOF_VALUE_MAX_BYTE_LEN, {ACCOUNT_PROOF_MAX_DEPTH, STORAGE_PROOF_MAX_DEPTH},
    },
    util::{bytes_be_to_u128, load_bool},
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, ETH_LOOKUP_BITS,
};
use ethers_core::{
    types::{Address, EIP1186ProofResponse, H256},
    utils::keccak256,
};
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
use rlp::Encodable;
use serde::{Deserialize, Serialize};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::halo2::POSEIDON_SPEC;

/// A single response to a storage slot query.
/// | Field                   | Max bytes |
/// |-------------------------|--------------|
/// | storageRoot             | 32           |
/// | slot                    | 32           |
/// | value                   | ≤32          |
///
/// We define `storage_response = hash(storageRoot . slot . value)`
///
/// This struct stores the data needed to compute the above hash.
#[derive(Clone, Debug)]
pub struct StorageResponse<F: ScalarField> {
    pub storage_root: FixedByteArray<F>,
    pub slot: FixedByteArray<F>,
    pub value: FixedByteArray<F>,
}

impl<F: Field> StorageResponse<F> {
    pub fn from_witness(
        witness: &EthStorageTraceWitness<F>,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> Self {
        let storage_root = FixedByteArray(witness.mpt_witness.root_hash_bytes.clone());
        let slot = FixedByteArray(witness.slot.clone());
        let value: ByteArray<F> = (&witness.value_witness.witness).into();
        let value = value.to_fixed(ctx, gate);
        Self { storage_root, slot, value }
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
        let [storage_root, slot, value] =
            [&self.storage_root, &self.slot, &self.value].map(|x| x.to_poseidon_words(loader));
        poseidon_packed(poseidon, storage_root.concat(&slot).concat(&value))
    }
}

/// See [`MultiStorageCircuit`] for more details.
///
/// Assumptions:
/// * `block_responses`, `account_responses`, `storage_responses`, `not_empty` are all of the same length, which is a **power of two**.
///
/// Returns `keccak_tree_root(full_storage_responses.keccak)`
pub fn get_storage_response_keccak_root<'a, F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    keccak: &mut KeccakChip<F>,
    block_numbers: impl IntoIterator<Item = &'a FixedByteArray<F>>,
    addresses: impl IntoIterator<Item = &'a FixedByteArray<F>>,
    storage_responses: impl IntoIterator<Item = &'a StorageResponse<F>>,
    not_empty: impl IntoIterator<Item = AssignedValue<F>>,
) -> FixedByteArray<F> {
    let full_responses: Vec<_> = block_numbers
        .into_iter()
        .zip_eq(addresses)
        .zip_eq(storage_responses)
        .zip_eq(not_empty)
        .map(|(((block_num, address), storage), not_empty)| {
            let slot_value = storage.slot.concat(&storage.value);
            // keccak_storage = keccak(block_response . acct_response . storage_response)
            let hash =
                keccak_packed(ctx, gate, keccak, block_num.concat(address).concat(&slot_value));
            bytes_select_or_zero(ctx, gate, hash, not_empty).0
        })
        .collect();
    let keccak_root = keccak.merkle_tree_root(ctx, gate, &full_responses);
    FixedByteArray(bytes_be_to_u128(ctx, gate, &keccak_root))
}

/// See [`MultiStorageCircuit`] for more details.
///
/// Assumptions:
/// * `block_responses`, `account_responses`, `storage_responses`, `not_empty` are all of the same length, which is a **power of two**.
pub fn get_storage_response_poseidon_roots<F, C, EccChip, const T: usize, const RATE: usize>(
    loader: &Rc<Halo2Loader<C, EccChip>>,
    poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
    block_responses: Vec<(F, FixedByteArray<F>)>,
    account_responses: Vec<(F, FixedByteArray<F>)>,
    storage_responses: &[StorageResponse<F>],
    not_empty: Vec<AssignedValue<F>>,
) -> Vec<AssignedValue<F>>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
    EccChip: EccInstructions<F, C>,
{
    let ((block_numbers, addresses), full_responses): ((Vec<_>, Vec<_>), Vec<_>) = block_responses
        .into_iter()
        .zip_eq(account_responses.into_iter())
        .zip_eq(storage_responses.iter())
        .zip_eq(not_empty.into_iter())
        .map(|(((block_response, acct_response), storage), not_empty)| {
            let storage_response = storage.poseidon(loader, poseidon);
            let block_number = block_response.1.to_poseidon_words(loader);
            let address = acct_response.1.to_poseidon_words(loader);
            // full_response = hash(block_response . acct_response . storage_response)
            let hash = poseidon_packed(
                poseidon,
                PoseidonWords(vec![
                    loader.assign_scalar(block_response.0),
                    loader.assign_scalar(acct_response.0),
                    storage_response,
                ]),
            );
            (
                (block_number, address),
                PoseidonWords::from(word_select_or_zero(loader, hash, not_empty)),
            )
        })
        .unzip();
    let [poseidon_root, block_number_root, address_root] =
        [full_responses, block_numbers, addresses]
            .map(|leaves| poseidon_tree_root(poseidon, leaves, &[]).into_assigned());
    vec![poseidon_root, block_number_root, address_root]
}

// switching to just Fr for simplicity:

/// The input datum for the circuit to generate multiple storage responses. It is used to generate a circuit.
///
/// Assumptions:
/// * `block_responses`, `account_responses`, `queries`, `not_empty` are all of the same length, which is a **power of two**.
/// * `block_responses` has length greater than 1: the length 1 case still works but cannot be aggregated because
/// the single leaf of `block_responses[0].1` (and of `account_responses[0].1`) would get hashed as two words,
/// whereas in a larger tree it gets concatenated before hashing.
///
/// The public instances of this circuit are 5 field elements:
/// * Keccak merkle root of `keccak(block_number[i] . address[i], slot[i], value[i])` over all queries: two field elements in hi-lo u128 format
/// * Poseidon merkle root of `poseidon(block_responses[i].0 . account_responses[i].0, storage_responses[i].0)` over all queries: single field element
/// * Poseidon merkle root of `block_number[i]` over all queries: single field element
/// * Poseidon merkle root of `address[i]` over all queries: single field element
///
/// Above `storage_responses` refers to the hash of `StorageResponse`s generated by the circuit for all queries.
/// Since `block_number, address` are given as private inputs, we expose Poseidon merkle roots of them as public inputs to be checked against BlockResponse and AccountResponse.
#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct MultiStorageCircuit {
    /// The block responses are provided as UNCHECKED private inputs; they will be checked in a separate circuit
    pub block_responses: Vec<(Fr, u32)>,
    /// The account responses are provided as UNCHECKED private inputs; they will be checked in a separate circuit
    pub account_responses: Vec<(Fr, Address)>,
    /// The storage queries
    pub queries: Vec<EthStorageInput>,
    /// Private input to allow full_response_hash[i] to be `Fr::zero()` or `H256(0x0)` for empty response
    pub not_empty: Vec<bool>,
}

pub const STORAGE_INSTANCE_SIZE: usize = 5;

pub(crate) const KECCAK_STORAGE_FULL_RESPONSE_INDEX: usize = 0;
pub(crate) const STORAGE_KECCAK_ROOT_INDICES: &[usize] = &[KECCAK_STORAGE_FULL_RESPONSE_INDEX];

pub(crate) const STORAGE_FULL_RESPONSE_POSEIDON_INDEX: usize = 2;
pub(crate) const STORAGE_BLOCK_RESPONSE_KECCAK_INDEX: usize = 3;
pub(crate) const STORAGE_ACCOUNT_RESPONSE_KECCAK_INDEX: usize = 4;
pub(crate) const STORAGE_POSEIDON_ROOT_INDICES: &[usize] = &[
    STORAGE_FULL_RESPONSE_POSEIDON_INDEX,
    STORAGE_BLOCK_RESPONSE_KECCAK_INDEX,
    STORAGE_ACCOUNT_RESPONSE_KECCAK_INDEX,
];

impl MultiStorageCircuit {
    /// Creates circuit inputs from raw data. Does basic sanity checks. Number of queries must be a power of two.
    pub fn new(
        block_responses: Vec<(Fr, u32)>,
        account_responses: Vec<(Fr, Address)>,
        queries: Vec<EthStorageInput>,
        not_empty: Vec<bool>,
    ) -> Self {
        assert!(queries.len() > 1);
        assert_eq!(block_responses.len(), account_responses.len());
        assert_eq!(block_responses.len(), not_empty.len());
        assert_eq!(queries.len(), not_empty.len());
        assert!(queries.len().is_power_of_two(), "Number of queries must be a power of 2");
        Self { block_responses, account_responses, queries, not_empty }
    }

    /// Creates circuit inputs from a JSON-RPC provider.
    #[cfg(feature = "providers")]
    pub fn from_provider(
        provider: &Provider<Http>,
        block_responses: Vec<(Fr, u32)>,
        account_responses: Vec<(Fr, Address)>,
        queries: Vec<(u64, Address, H256)>,
        not_empty: Vec<bool>,
    ) -> Self {
        use crate::providers::get_storage_queries;
        let queries = get_storage_queries(
            provider,
            queries,
            ACCOUNT_PROOF_MAX_DEPTH,
            STORAGE_PROOF_MAX_DEPTH,
        );
        Self::new(block_responses, account_responses, queries, not_empty)
    }

    pub fn resize_from(
        mut block_responses: Vec<(Fr, u32)>,
        mut account_responses: Vec<(Fr, Address)>,
        mut queries: Vec<EthStorageInput>,
        mut not_empty: Vec<bool>,
        new_len: usize,
    ) -> Self {
        block_responses.resize(new_len, (Fr::zero(), 0));
        account_responses.resize(new_len, (Fr::zero(), Address::zero()));
        queries.resize_with(new_len, || DEFAULT_STORAGE_QUERY.clone());
        not_empty.resize(new_len, false);
        Self::new(block_responses, account_responses, queries, not_empty)
    }
}

impl EthPreCircuit for MultiStorageCircuit {
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
                let query = query.assign_storage(ctx, &range);
                (query.slot.0, query.storage_pf)
            })
            .collect_vec();
        let witness =
            chip.parse_storage_proofs_phase0(&mut builder.gate_builder, &mut keccak, queries);
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let (mut storage_responses, not_empty): (Vec<_>, Vec<_>) = witness
            .iter()
            .zip_eq(self.not_empty)
            .map(|(w, not_empty)| {
                let not_empty = load_bool(ctx, range.gate(), not_empty);
                (StorageResponse::from_witness(w, ctx, range.gate()), not_empty)
            })
            .unzip();
        // set slot value to uint256(0) when the slot does not exist in the storage trie
        for (w, storage) in witness.iter().zip(storage_responses.iter_mut()) {
            // constrain the MPT proof must have non-zero depth to exclude the unsupported case of an empty storage trie
            let depth_is_zero = range.gate.is_zero(ctx, w.mpt_witness.depth);
            let depth_is_nonzero = range.gate.not(ctx, depth_is_zero);
            range.gate.assert_is_const(ctx, &depth_is_nonzero, &Fr::one());

            let slot_is_empty = w.mpt_witness.slot_is_empty;
            for byte in &mut storage.value.0 {
                *byte = range.gate().mul_not(ctx, slot_is_empty, *byte);
            }
        }
        let block_responses = self
            .block_responses
            .into_iter()
            .map(|(word, num)| {
                let keccak_bytes = FixedByteArray::new(ctx, &range, &num.to_be_bytes());
                (word, keccak_bytes)
            })
            .collect_vec();
        let account_responses = self
            .account_responses
            .into_iter()
            .map(|(word, addr)| {
                let keccak_bytes = FixedByteArray::new(ctx, &range, addr.as_bytes());
                (word, keccak_bytes)
            })
            .collect_vec();
        // hash responses
        let keccak_root = get_storage_response_keccak_root(
            ctx,
            range.gate(),
            &mut keccak,
            block_responses.iter().map(|(_, bytes)| bytes),
            account_responses.iter().map(|(_, bytes)| bytes),
            &storage_responses,
            not_empty.clone(),
        );

        let loader =
            Halo2Loader::<G1Affine, _>::new(DummyEccChip(range.gate()), builder.gate_builder);
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());

        let mut assigned_instances = keccak_root.0;
        assigned_instances.extend(get_storage_response_poseidon_roots(
            &loader,
            &mut poseidon,
            block_responses,
            account_responses,
            &storage_responses,
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
                chip.parse_storage_proofs_phase1(builder, witness);
            },
        )
    }
}

lazy_static! {
    pub static ref DEFAULT_STORAGE_PROOF: EIP1186ProofResponse = serde_json::from_str(
        r#"{"address":"0x01d5b501c1fc0121e1411970fb79c322737025c2","balance":"0x0","codeHash":"0xa633dd6234bb961a983a1a1e6d22088dfbbd623dede31449808b7b1eda575b7e","nonce":"0x1","storageHash":"0x209f60372065d53cb2b7d98ffbb1c6c3dcb60c2a30317619da189ccb2c6bad55","accountProof":["0xf90211a01dd0fec2b3f9d15468345ac46f6f57fc94d605c3fea7ca46938b3ecc125d3a4ca0850577263ea02739b6f62b8be0295a75550f80003a11842e5fe5d5afe30ac227a097b6edf8102741cc9b6d71ff2f642ddf33dd92c9ae8aba278517e0b91d2fbaa6a0e09ee77f537b2be646ecd82b264eac2c1845dd386a2935ac3313784158f31dd1a05efaa9476bdcbc6d6b4ddd0f05469824a9050d0492f1964f172beb29048a34bda0787865ffaac02ab287f93750b4dda4210bec374f7ffe3d5ea1d868154b2cc4bca01b046ca2bba9829937a96a9a33a49640a21d73ceaa31c96773cef9ac1cd5971ca037a0acaec88503df71185243fab25f327d07518dc7955da9450fcaa544137fc9a0e7b8d8f71ac648d0627c1c3a384763ce76b11550bc754f39c73ef686b0f0eddea03a7580472f61533e60be8e3d07c99446ad82dbf281546ca319d9324957bccf64a0d23283f05bc9bfa37c6b848832ccb94eef6e5a122d7c01a8fac8682b5f5a6724a0985070f0f845671b55f27534b013f183259ad19fe85e5473dd391a691eedfd99a028d103e427c16fedaa9cf5c038a85c86b901906fcb9bd856f45f4cc3ebee2562a06420015278390e56ec77f1f7dc6974f662da50060403be62b3e1e1913555a12aa0847f86badfd749741d5fca3d45459423fdf246368dfb73ee5e1359b9d3a81768a0f3f59fe568d6e11a0bc5f530ba75845529cf615b7365270a37c739180d37c9b080","0xf90211a0591bec78bcafecec4293f55fcc09da0eb48a77bf5f7790507c1fdce6416d4490a09e087976bc3828fba335f473c7a98df55a734375db72eda2201cdda3392b8af1a075e0854232f5c27abb59a60df7d875a1a87372461b28e4de5d16672b8a190af0a009522bf32fc4d343e40a3e64fd2915ee86694de766480e1135b47b5f2e3742bfa0b318c26d659f0ca40072bf8a37b7d1effa956844f839ae59918ec4695a257aefa0d7ccbc5b52984e066d5129aa0ccc3b4a09fbd43dbd59ecd2175c5ba8dacfa76aa0a7e1e7d10f3dcd1ae968a8cedd5b3cb859cb1eccd659e8d41da0174f68ffe291a08215e04c748b8e7260accc0506fe42c51ceb40d7fad92cb77abe2984cb7398f9a095eff22ca4336d5a65a772b46f8f0ac85b7dc6661108c667d0e7a7addd0bfed0a07ba3addc959ca81049c5dc65667d9d6a73484446fe2f3fe09b480c88d37f72dba02c6fa34d13c6e61ce4163b5590ceed16d4385a8a4dd51a391cedf98b3d94c153a0f525881d63bf204a5f7d8e60696581245dc3a3819963e9c7f587cfe6c3068f1ca0b47f5c965b1ce8ab9418f0570ad7b3b4b6296f9b3cba0b181d528d63e288dce2a0a5cf76a3d817e0fc74e47b15e1fc0eca75c4515120dfba7652cf3f637e5603a7a018c157a9be63ea00f432f94bacac4433cc32af504c616dc23fbd44fcd508d8e7a0c799da8c943c40802bc5553fa2efd5ffe1cc63fc2d3bccdca80c8e42e1c9d5a680","0xf90211a0c1d8a57bb338396435d7ac695fa8d74afdb65691ae29901d5e6bde73fb6b2ea3a00f44d497551cceaab46983cc1d79d3e8e2e4389f985bdaafbede19bbea73d8e4a0d6b55d1744d625bd588749810060e73eb411fe440a256f20580f46a39bdd1e8da0b506b59abbc8efd27e3d7b6aba7ce645c945a6cf3ecd8997d4a0dda0fad3c40da0b1abdd1ae9e9e4b19a583ea4ec0036c20c564fb421713d77c66de5106a21294aa07ef4df175184c42cc2ce7c9a88bb8769a3fd54a0d695fdbab7de0fe69bb4431fa06c537d7439d232a0cd16b17f509cba3c9f148e4e1d3ee2847e1fca9714378f96a06ef083d4b9ee50b9577d00cbc3e725cf154f7e531127c8c16fc8b449b25f73a7a0eb41fea54f05ea279ac0f44a31541fed62dad135faaa280570f549a924c27b66a09a85cc6a4bd49e2777247f00b4753f66612045013c7055e8ffe0ff2c54ebeca4a0ae0372d3b2998eed3f808f7cdd32c2fabb249ffa0ae1971bb3649fc58a160ceca0b185f343a574a15ca2f24d1ec776c0976fdff168bc26e9eef6dbc9ec09afcf0ea0c636a2dc92e4afdcd8430786f61e6d373de50d095e52ca463339c198d5359699a00a3d985dc08852e742257921a3762a14ef7894902ab81b8803383718e6bbb328a0842bccd655d45b45de291da6220e08286f421af7ab93223b23487b06a9dd8613a0e2a5a0f6e34ab2a72f2c31b064f34680cfd6d249314d62c5dfa6a036022c000480","0xf90211a043517cac2a83a56c58aa8f6c850c449f62e832d3fb8a9c2197334ef13719ba13a0ff9f673042cf317d247a1a4c0daa4998f593cba1ba40e80ed60a48d382b52e55a0c3bf4ce63800fa68a0314dcfa32849f873c82141ef622a6c11dbc8b7ee940a85a0a70d654d0718c839cc39971edb2ec70c3258828a523b6a155dcb20e81c48cf70a0f0635baf8c1a8a0ac4a03b73ab73d615c7a8eebaddc35ca0a50ca0ef0962bbf6a01202be6997900e1c699f8a2b7a2cd672c620f81fe8dcb2a407d1ed1c0fa56392a0a9773fca2325dd223ee16dc4c4cc3833a6949460ff13958cba2332173e44b829a0f1d33803fc9608a4b0ef316335297c5e7d22aadb3b5ace10b67e691ec126d11ea0d1bf809ac42ce2fa1f9df3c2d99843cf8a5d9f3c54650ee82dd9666ea7b47d24a0c3eada190e706f5be791c34bb7f35a83514246f3d8ff05bd1f78d6afa1a7f2f6a0740224e6867c4264d22e2617688b54bb3a6800a287056f2a55bcaf43f010fb75a03811a47a97b63f394e3b6fad9dc48bf03021ec993a7c2b3a7e8daa3a77ff78c9a0d3df72d1f0e4152d7c529b9ddce5598021c3004a1428fcee8304b6295687d439a099ea137fc015f2bf06247754bbd21ddbd891e914aa48e2db817afb7c36115f8da03001015ae6d4d974ec474445c8e09f7acd78fba0b34069f0f4ceff48618bd571a0ba1d7ce92b926a621e10b3dbceb60a42059ff3883fb3644c3fb51c96a3cfaa9480","0xf90211a0b0f95458177d0353a5b90006078160e0b2d87686230fee05f229feaf20b4d394a0da99a1217fc5aa21888eb2f845a0598690f6ac8d9cc1d48c294f8a83e75b8eaca0bf541d94d39c03263a6b42184efec7e896a58df03bd5933aae9d7fc6dd83db7da03f46a7a06b873492728188390004981c20562264ca270443ea06e4f55e3bab41a091a645a1d5936bf4ead6177a1225b8d6b92199aa3bea18a8bac109615218a53ca00065275af4349b8296593480173b24de236ec8944e5ff6b4c63682e4eed00a91a0a3ec50593073d617e7ae4cdb22192197c34577857fb532684127bf3b7774702ea0e339fc34ed27c2070926b6fe029c51630fb99381e21813b998933aa6575a4322a034d29a9082f9951c53991f299720d4a833feab0ee24dbccac629bc4dcb79ccc0a089e19dd8d40e42a3902dacc8727fdc5b13ee631d5ff09bd7d77b1536a9bd429da0088c7a47f46758b7d78233b9c116afeff2b11cd7e3bad52bc9a3a84d3c5fd3caa017a3e64263dcd5a4b5143963d87eec7c717d19b4e47aeb4b91c18039c62d502fa0be8d80129c4255b6cc9696f845ae5d07894f2505f32f62263d937ecf26834a91a0884fecc706698cabaf7fcf141bea6030167a93b745c5d232eeaab9078d579494a0df2b6f2700fd2df95b3349f261b1c8f9573dd41dfb4bbd47d2a3be9a1b0b90c2a036576ca9089c79fb55d210de4db554d9e638191fa38e1a37b60683a7d12b5dc180","0xf90211a0270f956b324726c987eaa3cded56b9bef8aaf385458daab7acdd70bfd203ee28a031fdda7c3b21ef9eab72b3e64b7fd3bec6b79a200697f7f4b5156a478e7833fba08dccb69de56beabb4084d50f35fc9cd45f7127ca254b529b13c625838ee15a33a0fad147b7a08030aa316015d13d0cc8a3dbadd3c107dfa7853b5dfffac9a5a738a01e03b5dddc0c2f6666b1c75b29909e7db6cfc26050a2ebbc08788a34e332a280a090b012cd85d1fe14241a1f58c8b02715f6b2d7835e9e5b61422ae05124034536a0113d75e61d8f40e30c4ef41974d81a99978a257af9f187086cd3e768ab20b2caa0a3ca2c0ba374ac77bb2e852dafc5169bfddacca5955a7dc43e8cb6d1d1ea9fbaa0f32d3b24f5495371dfbe423e74889e1d08028517dba2a8bab415cdb09a70ce07a0e5e71a4b10aca494fefe50259e497ba4d64d65f719c170bc9dca2a8178e9e8a3a03795fbe7c7fb69733db3e70e04ac1a297181214f0fca67c15480b7adf95cf52ba0e647bb44f3f3150774d478476b7977f7c2e1c2484746c46263ff74e7c5a9078aa07d7d448016779bd028116dea371aebe74036ed8356bcc07ce457a5b7bdd737dfa0100b0edbd15981e7f97fb293dee6a2fa18df5b9399caf20535158f5009d3c7f1a0a13439769cf90bcd6cd9d311e20f2a87ec616354314e3e1b4b2ff083ff4fc5dca0468329217298d1ffa8e41eab4678d02c7f589eca3c935f0dd191bdf44646947080","0xf90111a00e3484808a216730502daa7ab011fdcc6eb6df9dfcf65a97a170223b71fb0ac080a085a500be60f07ff9d75dcda7c1a9149a15219218188153b9b0227fa4bc523d75a0314d5dceb46c93156dd04a452d883b33bc55532b9f753530576c962cf80dc31880808080a0228d682f2312e51f484d2a3c3e53e987536e5a08afdc5bdd91345eff0c6c07f48080a0a478b8506e6cffc9dddb38a334a15a112d2ed155c2eb02438a4a329821ddf0dea0d37bd3a8c6197e501c6259a6bb50da18900c253f06eabec3b4c17633214c450da076eca457a853dfbfca74edb837bbd53865c0ba85734cece65f06242a6d6fe25c80a03aefcdb44bcd162364bafeddae1b7f8e2c7575e1c1b43032056650e17aab470480","0xf8669d373d3b2842e26222b7332b138c965d6e98a2f70add6324f24cc764fa8eb846f8440180a0209f60372065d53cb2b7d98ffbb1c6c3dcb60c2a30317619da189ccb2c6bad55a0a633dd6234bb961a983a1a1e6d22088dfbbd623dede31449808b7b1eda575b7e"],"storageProof":[{"key":"0x0000000000000000000000000000000000000000000000000000000000000000","proof":["0xf8518080a000ebce886332cd57419a907349ecfbd07043791d641877410ca470e69dcdd9f48080808080808080a06e3176d9ae4126e5bee6550649d603653ecde555bb105b6a81178f8908fb473e8080808080","0xf7a0390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594f0e3b9aada6d89ddeb34aab7e9cd1744cf90d82f"],"value":"0xf0e3b9aada6d89ddeb34aab7e9cd1744cf90d82f"}]}"#
    ).unwrap();

    pub static ref DEFAULT_STORAGE_QUERY: EthStorageInput = {
        let pf = &DEFAULT_STORAGE_PROOF;
        let addr = Address::from_str("0x01d5b501c1fc0121e1411970fb79c322737025c2").unwrap();
        let state_root = H256::from_str("0x32b26146b9b2a3ea68eb74585a124f912b8cbfe788696c7a86a79c91086c89f0").unwrap();

        let acct_key = H256(keccak256(addr));
        let acct_state = get_acct_list(pf);
        let acct_pf = MPTFixedKeyInput {
            path: acct_key,
            value: get_acct_rlp(pf),
            root_hash: state_root,
            proof: pf.account_proof.iter().map(|x| x.to_vec()).collect(),
            value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
            max_depth: ACCOUNT_PROOF_MAX_DEPTH,
            slot_is_empty: false,
        };
        let storage_pfs = pf
            .storage_proof
            .iter()
            .map(|storage_pf| {
                let path = H256(keccak256(storage_pf.key));
                let value = storage_pf.value.rlp_bytes().to_vec();
                (
                    storage_pf.key,
                    storage_pf.value,
                    MPTFixedKeyInput {
                        path,
                        value,
                        root_hash: pf.storage_hash,
                        proof: storage_pf.proof.iter().map(|x| x.to_vec()).collect(),
                        value_max_byte_len: STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
                        max_depth: STORAGE_PROOF_MAX_DEPTH,
                        slot_is_empty: false,
                    },
                )
            })
            .collect();
        EthStorageInput { addr, acct_state, acct_pf, storage_pfs }
    };
}
