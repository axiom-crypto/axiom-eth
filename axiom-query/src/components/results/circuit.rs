use axiom_codec::constants::{MAX_SUBQUERY_OUTPUTS, NUM_SUBQUERY_TYPES};
use axiom_eth::{
    component_type_list,
    halo2_base::{
        gates::{GateInstructions, RangeInstructions},
        halo2_proofs::plonk::ConstraintSystem,
        AssignedValue,
        QuantumCell::Constant,
    },
    keccak::{types::ComponentTypeKeccak, KeccakChip},
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::{
        build_utils::aggregation::CircuitMetadata,
        component::{
            circuit::{
                ComponentBuilder, ComponentCircuitImpl, CoreBuilder, CoreBuilderOutput,
                CoreBuilderOutputParams, CoreBuilderParams,
            },
            promise_collector::PromiseCaller,
            promise_loader::{
                combo::PromiseBuilderCombo, multi::MultiPromiseLoader, single::PromiseLoader,
            },
            types::FixLenLogical,
            utils::create_hasher,
        },
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::{
        account::types::ComponentTypeAccountSubquery,
        block_header::types::ComponentTypeHeaderSubquery,
        receipt::types::ComponentTypeReceiptSubquery,
        solidity_mappings::types::ComponentTypeSolidityNestedMappingSubquery,
        storage::types::ComponentTypeStorageSubquery, transaction::types::ComponentTypeTxSubquery,
    },
    Field,
};

use super::{
    results_root::get_results_root,
    subquery_hash::get_subquery_hash,
    types::{
        CircuitInputResultsRootShard, ComponentTypeResultsRoot, LogicalPublicInstanceResultsRoot,
        RlcAdapterResultsRoot, SubqueryResultCall, VirtualComponentType,
    },
};

/// Core builder for results root component.
pub struct CoreBuilderResultsRoot<F: Field> {
    pub input: Option<CircuitInputResultsRootShard<F>>,
    pub params: CoreParamsResultRoot,
}

/// Specify the output format of ResultRoot component.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsResultRoot {
    /// - `enabled_types[subquery_type as u16]` is true if the subquery type is enabled.
    /// - `enabled_types[0]` corresponds to the Null type. It doesn't matter whether it's enabled or disabled; behavior remains the same.
    pub enabled_types: [bool; NUM_SUBQUERY_TYPES],
    /// Maximum total number of subquery results supported
    pub capacity: usize,
}
impl CoreBuilderParams for CoreParamsResultRoot {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![])
    }
}

/// Subquery dependencies of ResultsRoot component.
pub type SubqueryDependencies<F> = component_type_list!(
    F,
    ComponentTypeHeaderSubquery<F>,
    ComponentTypeAccountSubquery<F>,
    ComponentTypeStorageSubquery<F>,
    ComponentTypeTxSubquery<F>,
    ComponentTypeReceiptSubquery<F>,
    ComponentTypeSolidityNestedMappingSubquery<F>
);

pub type PromiseLoaderResultsRoot<F> = PromiseBuilderCombo<
    F,
    PromiseLoader<F, ComponentTypeKeccak<F>>, // keccak
    MultiPromiseLoader<
        F,
        VirtualComponentType<F>,
        SubqueryDependencies<F>,
        RlcAdapterResultsRoot<F>,
    >, // Grouped subquery results
>;
pub type ComponentCircuitResultsRoot<F> =
    ComponentCircuitImpl<F, CoreBuilderResultsRoot<F>, PromiseLoaderResultsRoot<F>>;

impl<F: Field> CircuitMetadata for CoreBuilderResultsRoot<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        // currently implemented at the ComponentCircuitImpl level
        unreachable!()
    }
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderResultsRoot<F> {
    type Params = CoreParamsResultRoot;
    fn new(params: Self::Params) -> Self {
        Self { input: None, params }
    }
    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }
    fn clear_witnesses(&mut self) {}
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
    fn configure_with_params(_: &mut ConstraintSystem<F>, _: Self::Params) {}
}

impl<F: Field> CoreBuilder<F> for CoreBuilderResultsRoot<F> {
    type CompType = ComponentTypeResultsRoot<F>;
    type PublicInstanceValue = LogicalPublicInstanceResultsRoot<F>;
    type PublicInstanceWitness = LogicalPublicInstanceResultsRoot<AssignedValue<F>>;
    type CoreInput = CircuitInputResultsRootShard<F>;

    fn feed_input(&mut self, mut input: Self::CoreInput) -> anyhow::Result<()> {
        if input.subqueries.len() > self.params.capacity {
            anyhow::bail!(
                "Subquery results table is greater than capcaity - {} > {}",
                input.subqueries.len(),
                self.params.capacity
            );
        }
        let cap = self.params.capacity;
        input.subqueries.rows.resize(cap, input.subqueries.rows[0]);
        self.input = Some(input);
        Ok(())
    }
    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_caller: PromiseCaller<F>,
    ) -> CoreBuilderOutput<F, Self::CompType> {
        let keccak =
            KeccakChip::new_with_promise_collector(builder.range_chip(), promise_caller.clone());
        let range = keccak.range();
        let gate = &range.gate;

        // Assumption: we already have input when calling this function.
        // TODO: automatically derive a dummy input from params.
        let input = self.input.as_ref().unwrap();

        let ctx = builder.base.main(0);
        // assign subquery results
        let subqueries = input.subqueries.assign(ctx).rows;
        // Make virtual promise calls.
        for subquery in &subqueries {
            promise_caller
                .call::<SubqueryResultCall<F>, VirtualComponentType<F>>(
                    ctx,
                    SubqueryResultCall(*subquery),
                )
                .unwrap();
        }

        // compute subquery hashes (keccak)
        let subquery_hashes = subqueries
            .iter()
            .map(|row| get_subquery_hash(ctx, &keccak, &row.key, &self.params.enabled_types))
            .collect_vec();

        let num_subqueries = ctx.load_witness(input.num_subqueries);
        range.check_less_than_safe(ctx, num_subqueries, subqueries.len() as u64 + 1);

        let mut poseidon = create_hasher();
        poseidon.initialize_consts(ctx, gate);
        // compute resultsRootPoseidon
        let results_root_poseidon =
            get_results_root(ctx, range, &poseidon, &subqueries, num_subqueries);

        let commit_subquery_hashes = {
            // take variable length list of `num_subqueries` subquery hashes and flat hash them all together
            // the reason we use variable length is so the hash does not depend on `subquery_hashes.len()` and only on `num_subqueries`. this allows more flexibility in the VerifyCompute circuit
            let to_commit = subquery_hashes.into_iter().flat_map(|hash| hash.hi_lo()).collect_vec();
            let len = gate.mul(ctx, num_subqueries, Constant(F::from(MAX_SUBQUERY_OUTPUTS as u64)));
            poseidon.hash_var_len_array(ctx, range, &to_commit, len)
        };

        // This component is never called directly.
        // The VerifyCompute circuit will read the other public instances and decommit them directly.
        let pis =
            LogicalPublicInstanceResultsRoot { results_root_poseidon, commit_subquery_hashes };

        CoreBuilderOutput::<F, Self::CompType> {
            public_instances: pis.into_raw(),
            virtual_table: vec![],
            logical_results: vec![],
        }
    }
}
