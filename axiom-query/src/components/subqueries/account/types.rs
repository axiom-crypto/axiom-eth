//! Types are separated into:
//! - Circuit metadata that along with the circuit type determines the circuit configuration completely.
//! - Human readable _logical_ input and output to the circuit. These include private inputs and outputs that are only commited to in the public output.
//! - The in-circuit formatted versions of logical inputs and outputs. These include formatting in terms of field elements and accounting for all lengths needing to be fixed at compile time.
//!   - We then provide conversion functions from human-readable to circuit formats.
//! - This circuit has no public instances (IO) other than the circuit's own component commitment and the promise commitments from any component calls.
use std::marker::PhantomData;

use axiom_codec::{
    types::{field_elements::FieldAccountSubquery, native::AccountSubquery},
    HiLo,
};
use axiom_eth::{
    halo2_base::AssignedValue,
    impl_fix_len_call_witness,
    providers::storage::json_to_mpt_input,
    storage::circuit::EthStorageInput,
    utils::{
        build_utils::dummy::DummyFrom,
        component::{circuit::CoreBuilderInput, ComponentType, ComponentTypeId, LogicalResult},
    },
};
use ethers_core::types::{EIP1186ProofResponse, H256};
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::common::OutputSubqueryShard, utils::codec::AssignedAccountSubquery,
    Field,
};

use super::circuit::CoreParamsAccountSubquery;

/// Identifier for the component type of this component circuit
pub struct ComponentTypeAccountSubquery<F: Field>(PhantomData<F>);

/// Human readable.
/// The output value of any account subquery is always `bytes32` right now.
pub type OutputAccountShard = OutputSubqueryShard<AccountSubquery, H256>;

/// Circuit input for a shard of Account subqueries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputAccountShard<F: Field> {
    /// Enriched subquery requests
    pub requests: Vec<CircuitInputAccountSubquery>,
    pub _phantom: PhantomData<F>,
}

/// Circuit input for a single Account subquery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputAccountSubquery {
    /// The block number to access the account state at.
    pub block_number: u64,
    /// Account proof formatted as MPT input. `proof.storage_pfs` will be empty.
    /// It will contain the correct state root of the block.
    pub proof: EthStorageInput,
    pub field_idx: u32,
}

impl<F: Field> DummyFrom<CoreParamsAccountSubquery> for CircuitInputAccountShard<F> {
    fn dummy_from(core_params: CoreParamsAccountSubquery) -> Self {
        let CoreParamsAccountSubquery { capacity, max_trie_depth } = core_params;
        let request = {
            let mut pf: EIP1186ProofResponse =
                serde_json::from_str(GENESIS_ADDRESS_0_ACCOUNT_PROOF).unwrap();
            pf.storage_proof.clear();
            let proof = json_to_mpt_input(pf, max_trie_depth, 0);
            CircuitInputAccountSubquery { block_number: 0, field_idx: 0, proof }
        };
        Self { requests: vec![request; capacity], _phantom: PhantomData }
    }
}

/// The output value of any account subquery is always `bytes32` right now.
/// Vector has been resized to the capacity.
pub type CircuitOutputAccountShard<T> = OutputSubqueryShard<FieldAccountSubquery<T>, HiLo<T>>;

impl_fix_len_call_witness!(
    FieldAccountSubqueryCall,
    FieldAccountSubquery,
    ComponentTypeAccountSubquery
);

// ===== The account component has no public instances other than the component commitment and promise commitments from external component calls =====

impl<F: Field> ComponentType<F> for ComponentTypeAccountSubquery<F> {
    type InputValue = FieldAccountSubquery<F>;
    type InputWitness = AssignedAccountSubquery<F>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldAccountSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeAccountSubquery".to_string()
    }

    fn logical_result_to_virtual_rows_impl(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        vec![(ins.input, ins.output)]
    }
    fn logical_input_to_virtual_rows_impl(li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        vec![*li]
    }
}

impl<F: Field> From<OutputAccountShard> for CircuitOutputAccountShard<F> {
    fn from(output: OutputAccountShard) -> Self {
        output.convert_into()
    }
}

pub const GENESIS_ADDRESS_0_ACCOUNT_PROOF: &str = r#"{"address":"0x0000000000000000000000000000000000000000","balance":"0x0","codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","storageHash":"0x0000000000000000000000000000000000000000000000000000000000000000","accountProof":["0xf90211a090dcaf88c40c7bbc95a912cbdde67c175767b31173df9ee4b0d733bfdd511c43a0babe369f6b12092f49181ae04ca173fb68d1a5456f18d20fa32cba73954052bda0473ecf8a7e36a829e75039a3b055e51b8332cbf03324ab4af2066bbd6fbf0021a0bbda34753d7aa6c38e603f360244e8f59611921d9e1f128372fec0d586d4f9e0a04e44caecff45c9891f74f6a2156735886eedf6f1a733628ebc802ec79d844648a0a5f3f2f7542148c973977c8a1e154c4300fec92f755f7846f1b734d3ab1d90e7a0e823850f50bf72baae9d1733a36a444ab65d0a6faaba404f0583ce0ca4dad92da0f7a00cbe7d4b30b11faea3ae61b7f1f2b315b61d9f6bd68bfe587ad0eeceb721a07117ef9fc932f1a88e908eaead8565c19b5645dc9e5b1b6e841c5edbdfd71681a069eb2de283f32c11f859d7bcf93da23990d3e662935ed4d6b39ce3673ec84472a0203d26456312bbc4da5cd293b75b840fc5045e493d6f904d180823ec22bfed8ea09287b5c21f2254af4e64fca76acc5cd87399c7f1ede818db4326c98ce2dc2208a06fc2d754e304c48ce6a517753c62b1a9c1d5925b89707486d7fc08919e0a94eca07b1c54f15e299bd58bdfef9741538c7828b5d7d11a489f9c20d052b3471df475a051f9dd3739a927c89e357580a4c97b40234aa01ed3d5e0390dc982a7975880a0a089d613f26159af43616fd9455bb461f4869bfede26f2130835ed067a8b967bfb80","0xf90211a06f499aafd2fcc95db6ac85b9ec36ce16b3747180d51b7ba72babdbceaef0cac8a034ffbe94cc9f4ac7e43bbd0ab875ce079e5d131f72f33974c09525bad37da4b4a026ac19ac1e99055b84ef53fad0ff4bf76a54af485b399dac5d91e55320941c16a0a33d103a92ff6f95c081309f83f474a009048614d5d40e14067dbae0cf9ed084a046a0e834a4f3482cb37f70f1f188d7c749c33fb8b94854b16dcebe840fc9390aa0a5a914013e15472dc3ae08f774e9d5ac3127419a2c81bec98963f40dde42ebaaa0b5740bdfa8ecf2b4d0b560f72474846788a3e19f9e0894c6bd2eb46255d222e9a04aa4e4ebe1930364ae283e8f1fa4de7ef1867a3f7fb89c23e068b807464eac14a0f84e5e71db73c15fc0bfa5566fae5e687e8eed398ef68e0d8229a7bc2eb333fda0551d35fa9c76d23bbbc1feb30a16e6ee1087c96aa2c31a8be297c4904c37373ba0f25b1be3ea53f222e17985dde60b04716bc342232874af3ad0af1652165138f2a0e50848e903b54f966851f4cbac1deb5b1d1beb42b4223379bb911f68001747f8a021d90bccf615ff6349cc5fdf8604ee52789c0e977fe12c2401b1cc229a9e7e47a0ade009f37dd2907895900d853eefbcf26af8f1665c8802804584241d825a6b49a09fe500ded938f686589ab2f42caad51341441980ea20e9fcb69e62b774c9990fa087888bb118be98fa5dfd57a76d0b59af08d7977fe87bad7c0d68ef82f2c9a92880","0xf901b1a0ec652a529bfb6f625879b961b8f7986b8294cfb1082d24b2c27f9a5b3fbccece80a088a3bacf48a0d00e3b36c3274ca2ab8d9d8f54c90e03724b3f6f5137c5a350c1a0a3c84954aad8408ed44eed138573a4db917e19d49e6cb716c14c7dedcb7a0051a069d3ae295c988b5e52f9d86b3aa85e9167a2d59a5ad47b6d1f8faaae9cd3aee4a0252dbbed1d3b713b43b6b8745d1d60605bbc4474746bfffe16375acbf42c0ec080a0a886f03399a8e32312b65d59b2a5d97ba7bb078aa5dab7aeb08d1fbd721a0944a0e9b89be70399650793c37b4aca1779e5adf4d8a07cea63dab9a9f5ef6b7dc66fa0b352a156bda0e42ce192bc430f8513e827b0aaa70002a21fef3a4df416be93e9a00665ba82ae23119a4a244be15e42e23589490995236c43bac11b5628613c337ba0b45176ce952dda9f523f244d921805f005c11b2027f53d12dda0e069278cf908a0eefa94d2ecf8946494c634277eac048823f35f7820d354c6e9352176c9b44e4da046443df5febce492f17eed4f98f2ad755fec20cd9eede857dc951757ef85b51aa0fc14ff2dbb3675d852fb37d7796eb1f303282d3466aef865a17da813d22bfc028080","0xf8718080a06f69700f636d81db1793bcee2562dcf0a4a06f2525fb2f55f5c00aab81b4b86880a00f13a02c0878c787e7f9fdcfbb3b3169b42c2a0595c7afecf86dbb46fbcb567b80808080a05c80e25e034b9cc0f079b1226a97c22434851b86c6b55be77eae89b096462afd80808080808080"],"storageProof":[{"key":"0x0","proof":[],"value":"0x0"}]}"#;

#[cfg(test)]
mod test {
    use axiom_eth::providers::setup_provider;
    use ethers_core::types::{Chain, H256};
    use ethers_providers::Middleware;

    use super::GENESIS_ADDRESS_0_ACCOUNT_PROOF;

    #[tokio::test]
    async fn test_dummy_account_proof() {
        let provider = setup_provider(Chain::Mainnet);
        let address = "0x0000000000000000000000000000000000000000";
        let proof = provider.get_proof(address, vec![H256::zero()], Some(0.into())).await.unwrap();
        assert_eq!(GENESIS_ADDRESS_0_ACCOUNT_PROOF, serde_json::to_string(&proof).unwrap());
    }
}
