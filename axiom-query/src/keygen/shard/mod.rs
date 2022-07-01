use std::{any::TypeId, path::Path};

use axiom_components::{
    ecdsa::ECDSAComponent, framework::promise_loader::empty::EmptyPromiseLoader,
    scaffold::BasicComponentScaffoldImpl,
};
use axiom_eth::{
    halo2_base::{
        gates::circuit::CircuitBuilderStage,
        utils::halo2::{KeygenCircuitIntent, ProvingKeyGenerator},
    },
    halo2_proofs::{
        plonk::{Circuit, ProvingKey},
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    rlc::virtual_region::RlcThreadBreakPoints,
    snark_verifier::pcs::kzg::KzgDecidingKey,
    snark_verifier_sdk::CircuitExt,
    utils::{
        build_utils::{
            aggregation::CircuitMetadata,
            dummy::DummyFrom,
            keygen::{get_dummy_rlc_circuit_params, read_srs_from_dir, write_pk_and_pinning},
            pinning::aggregation::AggTreeId,
        },
        component::{
            circuit::{
                ComponentCircuitImpl, CoreBuilder, CoreBuilderInput, CoreBuilderParams,
                PromiseBuilder,
            },
            promise_loader::utils::DummyPromiseBuilder,
            ComponentCircuit,
        },
    },
    zkevm_hashes::keccak::component::circuit::shard::KeccakComponentShardCircuit,
};
use enum_dispatch::enum_dispatch;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    components::{
        results::circuit::{
            ComponentCircuitResultsRoot, CoreBuilderResultsRoot, PromiseLoaderResultsRoot,
        },
        subqueries::{
            account::circuit::{
                ComponentCircuitAccountSubquery, CoreBuilderAccountSubquery,
                PromiseLoaderAccountSubquery,
            },
            block_header::circuit::{
                ComponentCircuitHeaderSubquery, CoreBuilderHeaderSubquery,
                PromiseLoaderHeaderSubquery,
            },
            receipt::circuit::{
                ComponentCircuitReceiptSubquery, CoreBuilderReceiptSubquery,
                PromiseLoaderReceiptSubquery,
            },
            solidity_mappings::circuit::{
                ComponentCircuitSolidityNestedMappingSubquery,
                CoreBuilderSolidityNestedMappingSubquery,
                PromiseLoaderSolidityNestedMappingSubquery,
            },
            storage::circuit::{
                ComponentCircuitStorageSubquery, CoreBuilderStorageSubquery,
                PromiseLoaderStorageSubquery,
            },
            transaction::circuit::{
                ComponentCircuitTxSubquery, CoreBuilderTxSubquery, PromiseLoaderTxSubquery,
            },
        },
    },
    verify_compute::circuit::{
        ComponentCircuitVerifyCompute, CoreBuilderVerifyCompute, PromiseLoaderVerifyCompute,
    },
};

use self::keccak::ShardIntentKeccak;

use super::{agg::common::AggTreePinning, ProvingKeySerializer, SupportedPinning};

/// Keccak component shard requires special treatment.
pub mod keccak;

pub type ShardIntentHeader =
    ComponentShardCircuitIntent<CoreBuilderHeaderSubquery<Fr>, PromiseLoaderHeaderSubquery<Fr>>;
pub type ShardIntentAccount =
    ComponentShardCircuitIntent<CoreBuilderAccountSubquery<Fr>, PromiseLoaderAccountSubquery<Fr>>;
pub type ShardIntentStorage =
    ComponentShardCircuitIntent<CoreBuilderStorageSubquery<Fr>, PromiseLoaderStorageSubquery<Fr>>;
pub type ShardIntentTx =
    ComponentShardCircuitIntent<CoreBuilderTxSubquery<Fr>, PromiseLoaderTxSubquery<Fr>>;
pub type ShardIntentReceipt =
    ComponentShardCircuitIntent<CoreBuilderReceiptSubquery<Fr>, PromiseLoaderReceiptSubquery<Fr>>;
pub type ShardIntentSolidityMapping = ComponentShardCircuitIntent<
    CoreBuilderSolidityNestedMappingSubquery<Fr>,
    PromiseLoaderSolidityNestedMappingSubquery<Fr>,
>;
pub type ShardIntentECDSA = ComponentShardCircuitIntent<
    BasicComponentScaffoldImpl<Fr, ECDSAComponent<Fr>>,
    EmptyPromiseLoader<Fr>,
>;
pub type ShardIntentResultsRoot =
    ComponentShardCircuitIntent<CoreBuilderResultsRoot<Fr>, PromiseLoaderResultsRoot<Fr>>;
// You should never shard verify compute, but the struct is the same.
pub type CircuitIntentVerifyCompute =
    ComponentShardCircuitIntent<CoreBuilderVerifyCompute, PromiseLoaderVerifyCompute>;

pub type ECDSAComponentImpl = ComponentCircuitImpl<
    Fr,
    BasicComponentScaffoldImpl<Fr, ECDSAComponent<Fr>>,
    EmptyPromiseLoader<Fr>,
>;

#[derive(Clone, Serialize, Deserialize)]
#[enum_dispatch(AggTreePinning)]
pub enum SupportedShardPinning {
    ShardHeader(ComponentShardPinning<ComponentCircuitHeaderSubquery<Fr>>),
    ShardAccount(ComponentShardPinning<ComponentCircuitAccountSubquery<Fr>>),
    ShardStorage(ComponentShardPinning<ComponentCircuitStorageSubquery<Fr>>),
    ShardTx(ComponentShardPinning<ComponentCircuitTxSubquery<Fr>>),
    ShardReceipt(ComponentShardPinning<ComponentCircuitReceiptSubquery<Fr>>),
    ShardSolidityMapping(ComponentShardPinning<ComponentCircuitSolidityNestedMappingSubquery<Fr>>),
    ShardECDSA(ComponentShardPinning<ECDSAComponentImpl>),
    ShardResultsRoot(ComponentShardPinning<ComponentCircuitResultsRoot<Fr>>),
    ShardKeccak(ComponentShardPinning<KeccakComponentShardCircuit<Fr>>),
    ShardVerifyCompute(ComponentShardPinning<ComponentCircuitVerifyCompute>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentShardCircuitIntent<C: CoreBuilder<Fr>, P: PromiseBuilder<Fr>>
where
    C::Params: CoreBuilderParams,
{
    pub core_params: C::Params,
    pub loader_params: P::Params,
    pub k: u32,
    #[serde(default = "default_lookup_bits")]
    pub lookup_bits: usize,
}

impl<C, P> Clone for ComponentShardCircuitIntent<C, P>
where
    C: CoreBuilder<Fr>,
    P: PromiseBuilder<Fr>,
    C::Params: CoreBuilderParams + Clone,
    P::Params: Clone,
{
    fn clone(&self) -> Self {
        Self {
            core_params: self.core_params.clone(),
            loader_params: self.loader_params.clone(),
            k: self.k,
            lookup_bits: self.lookup_bits,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentShardPinning<C: Circuit<Fr>> {
    pub params: C::Params,
    /// Number of instances in each instance column
    pub num_instance: Vec<usize>,
    /// g1 generator, g2 generator, s_g2 (s is generator of trusted setup).
    /// Together with domain size `2^k`, this commits to the trusted setup used.
    /// This is all that's needed to verify the final ecpairing check on the KZG proof.
    pub dk: KzgDecidingKey<Bn256>,
    pub break_points: RlcThreadBreakPoints,
}

impl<C: Circuit<Fr>> Clone for ComponentShardPinning<C>
where
    C::Params: Clone,
{
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
            num_instance: self.num_instance.clone(),
            break_points: self.break_points.clone(),
            dk: self.dk.clone(),
        }
    }
}

impl<C, P> KeygenCircuitIntent<Fr> for ComponentShardCircuitIntent<C, P>
where
    C: CoreBuilder<Fr> + CircuitMetadata + 'static,
    C::Params: CoreBuilderParams,
    C::CoreInput: DummyFrom<C::Params>,
    P: DummyPromiseBuilder<Fr>,
{
    type ConcreteCircuit = ComponentCircuitImpl<Fr, C, P>;
    type Pinning = ComponentShardPinning<Self::ConcreteCircuit>;

    fn get_k(&self) -> u32 {
        self.k
    }

    /// ## Panics
    /// In any situation where creating the keygen circuit fails.
    fn build_keygen_circuit(self) -> Self::ConcreteCircuit {
        let Self { core_params, loader_params, k, mut lookup_bits } = self;
        if TypeId::of::<C>() == TypeId::of::<CoreBuilderVerifyCompute>() {
            // VerifyCompute is aggregation circuit, so optimal lookup bits is `k - 1`
            lookup_bits = k as usize - 1;
            log::debug!("Verify Compute lookup bits: {lookup_bits}");
        }
        let rlc_params = get_dummy_rlc_circuit_params(k as usize, lookup_bits);
        let mut circuit = ComponentCircuitImpl::<Fr, C, P>::new_from_stage(
            CircuitBuilderStage::Keygen,
            core_params.clone(),
            loader_params,
            rlc_params,
        );
        let default_input = C::CoreInput::dummy_from(core_params);
        circuit.feed_input(Box::new(default_input)).unwrap();
        circuit.promise_builder.borrow_mut().fulfill_dummy_promise_results();
        circuit.calculate_params();

        circuit
    }

    fn get_pinning_after_keygen(
        self,
        kzg_params: &ParamsKZG<Bn256>,
        circuit: &Self::ConcreteCircuit,
    ) -> Self::Pinning {
        let circuit_params = circuit.params();
        let break_points = circuit.rlc_builder.borrow().break_points();
        // get public instances
        circuit.clear_witnesses();
        circuit.virtual_assign_phase0().unwrap();
        let num_instance =
            circuit.rlc_builder.borrow().base.assigned_instances.iter().map(|x| x.len()).collect();
        circuit.clear_witnesses(); // prevent drop warning
        let svk = kzg_params.get_g()[0];
        let dk = (svk, kzg_params.g2(), kzg_params.s_g2());
        ComponentShardPinning { params: circuit_params, num_instance, break_points, dk: dk.into() }
    }
}

fn default_lookup_bits() -> usize {
    8
}

impl<C, P> ProvingKeySerializer for ComponentShardCircuitIntent<C, P>
where
    C: CoreBuilder<Fr> + CircuitMetadata + 'static,
    C::Params: CoreBuilderParams + Clone,
    C::CoreInput: DummyFrom<C::Params>,
    P: DummyPromiseBuilder<Fr>,
    P::Params: Clone,
    ComponentShardPinning<ComponentCircuitImpl<Fr, C, P>>:
        Serialize + DeserializeOwned + Into<SupportedShardPinning>,
{
    fn create_and_serialize_proving_key(
        self,
        params_dir: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, SupportedPinning)> {
        let k = self.get_k();
        let kzg_params = read_srs_from_dir(params_dir, k)?;
        let (pk, pinning_json) = self.create_pk_and_pinning(&kzg_params);
        let pinning: <Self as KeygenCircuitIntent<Fr>>::Pinning =
            serde_json::from_value(pinning_json)?;
        let pinning: SupportedShardPinning = pinning.into();
        let pinning = SupportedPinning::Shard(pinning);
        let circuit_id = write_pk_and_pinning(data_dir, &pk, &serde_json::to_value(&pinning)?)?;
        // ** !! Warning !! **
        // Currently all shard component circuits are **leaves** in the aggregation tree.
        // This implementation would need to change if that changes.
        //
        // VerifyCompute is an aggregation circuit but does not have children as an aggregation tree because the snark to be aggregated is part of the input.
        // Thus all shard circuits are leaves in the aggregation tree.
        let leaf_id = AggTreeId { circuit_id, children: vec![], aggregate_vk_hash: None };
        Ok((leaf_id, pk, pinning))
    }
}
// special case (for now)
// if we need to do this more than twice, we should make a macro
impl ProvingKeySerializer for ShardIntentKeccak {
    fn create_and_serialize_proving_key(
        self,
        params_dir: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, SupportedPinning)> {
        let k = self.get_k();
        let kzg_params = read_srs_from_dir(params_dir, k)?;
        let (pk, pinning_json) = self.create_pk_and_pinning(&kzg_params);
        let pinning: <Self as KeygenCircuitIntent<Fr>>::Pinning =
            serde_json::from_value(pinning_json)?;
        let pinning: SupportedShardPinning = pinning.into();
        let pinning = SupportedPinning::Shard(pinning);
        let circuit_id = write_pk_and_pinning(data_dir, &pk, &serde_json::to_value(&pinning)?)?;
        let leaf_id = AggTreeId { circuit_id, children: vec![], aggregate_vk_hash: None };
        Ok((leaf_id, pk, pinning))
    }
}

impl<C: CircuitExt<Fr>> AggTreePinning for ComponentShardPinning<C> {
    fn num_instance(&self) -> Vec<usize> {
        self.num_instance.clone()
    }
    fn accumulator_indices(&self) -> Option<Vec<(usize, usize)>> {
        C::accumulator_indices()
    }
    // ** !! Assertion !! **
    // No ComponentShardPinning has non-None agg_vk_hash_data.
    // While VerifyCompute is a universal aggregation circuit, the compute snark's
    // vkey is committed to separately in the querySchema.
    fn agg_vk_hash_data(&self) -> Option<((usize, usize), Fr)> {
        None
    }
}
