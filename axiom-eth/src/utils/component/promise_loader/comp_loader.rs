#![allow(clippy::type_complexity)]
use std::{iter, marker::PhantomData};

use crate::utils::component::utils::compute_poseidon;
use crate::Field;
use crate::{
    rlc::{chip::RlcChip, circuit::builder::RlcCircuitBuilder, RLC_PHASE},
    utils::component::{
        types::FixLenLogical, utils::compute_poseidon_merkle_tree, FlattenVirtualRow,
        FlattenVirtualTable, LogicalResult, PromiseShardMetadata, SelectedDataShardsInMerkle,
    },
};
use getset::{CopyGetters, Getters};
use halo2_base::{
    gates::{circuit::builder::BaseCircuitBuilder, GateInstructions, RangeChip, RangeInstructions},
    AssignedValue,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use super::{
    super::{
        promise_collector::PromiseResultWitness,
        types::Flatten,
        utils::{compute_commitment_with_flatten, create_hasher},
        ComponentPromiseResultsInMerkle, ComponentType, ComponentTypeId,
    },
    flatten_witness_to_rlc,
};

/// To seal SingleComponentLoader so no external implementation is allowed.
mod private {
    pub trait Sealed {}
}

#[derive(Clone, Debug, Hash, Getters, CopyGetters, Serialize, Deserialize, Eq, PartialEq)]
/// Specify what merkle tree of commits can be loaded.
pub struct SingleComponentLoaderParams {
    /// The maximum height of the merkle tree this loader can load.
    #[getset(get_copy = "pub")]
    max_height: usize,
    /// Specify the number of shards to be loaded and the capacity of each shard.
    #[getset(get = "pub")]
    shard_caps: Vec<usize>,
}

impl SingleComponentLoaderParams {
    /// Create SingleComponentLoaderParams
    pub fn new(max_height: usize, shard_caps: Vec<usize>) -> Self {
        // Tip: binary tree with only 1 node has height 0.
        assert!(shard_caps.len() <= 1 << max_height);
        Self { max_height, shard_caps }
    }
    /// Create SingleComponentLoaderParams for only 1 shard
    pub fn new_for_one_shard(cap: usize) -> Self {
        Self { max_height: 0, shard_caps: vec![cap] }
    }
}

impl Default for SingleComponentLoaderParams {
    fn default() -> Self {
        Self::new(0, vec![0])
    }
}

/// Object safe trait for loading promises of a component type.
pub trait SingleComponentLoader<F: Field>: private::Sealed {
    /// Get the component type id this loader is for.
    fn get_component_type_id(&self) -> ComponentTypeId;
    /// Get ComponentTypeName for logging/debugging.
    fn get_component_type_name(&self) -> &'static str;
    fn get_params(&self) -> &SingleComponentLoaderParams;
    /// Check if promise results are ready.
    fn promise_results_ready(&self) -> bool;
    /// Load promise results from promise results getter.
    fn load_promise_results(&mut self, promise_results: ComponentPromiseResultsInMerkle<F>);
    /// Load dummy promise results according to the loader params.
    fn load_dummy_promise_results(&mut self);
    /// Return (merkle_tree_root, concat_assigned_virtual_tables). Data is preloaded.
    /// TODO: do we really need  to return assigned virtual table?
    fn assign_and_compute_commitment(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
    ) -> (AssignedValue<F>, FlattenVirtualTable<AssignedValue<F>>);
    /// Return (to_lookup, lookup_table)
    fn generate_lookup_rlc(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_calls: &[&PromiseResultWitness<F>],
        promise_results: &[FlattenVirtualRow<AssignedValue<F>>],
    ) -> (Vec<AssignedValue<F>>, Vec<AssignedValue<F>>);
}

/// Promise results but each shard is in the virtual table format.
type PromiseVirtualTableResults<F> = SelectedDataShardsInMerkle<F, FlattenVirtualTable<F>>;

/// Implementation of SingleComponentLoader for a component type.
pub struct SingleComponentLoaderImpl<F: Field, T: ComponentType<F>> {
    val_promise_results: Option<PromiseVirtualTableResults<F>>,
    params: SingleComponentLoaderParams,
    _phantom: PhantomData<T>,
}

impl<F: Field, T: ComponentType<F>> SingleComponentLoaderImpl<F, T> {
    /// Create SingleComponentLoaderImpl for T.
    pub fn new(params: SingleComponentLoaderParams) -> Self {
        Self { val_promise_results: None, params, _phantom: PhantomData }
    }
    /// Create dummy promise results based on params for CircuitBuilder params calculation.
    fn create_dummy_promise_result_merkle(&self) -> PromiseVirtualTableResults<F> {
        let num_shards = self.params.shard_caps.len();
        let num_leaves = num_shards.next_power_of_two();
        let mut leaves = Vec::with_capacity(num_leaves);
        for i in 0..num_leaves {
            let commit = F::ZERO;
            leaves.push(PromiseShardMetadata::<F> {
                commit,
                capacity: if i < num_shards { self.params.shard_caps[i] } else { 0 },
            });
        }
        let shards = self
            .params
            .shard_caps
            .iter()
            .copied()
            .enumerate()
            .map(|(idx, shard_cap)| {
                let dummy_input = Flatten::<F> {
                    fields: vec![F::ZERO; T::InputValue::get_num_fields()],
                    field_size: T::InputValue::get_field_size(),
                };
                let dummy_output = Flatten::<F> {
                    fields: vec![F::ZERO; T::OutputValue::get_num_fields()],
                    field_size: T::OutputValue::get_field_size(),
                };
                let shard = vec![(dummy_input, dummy_output); shard_cap];
                (idx, shard)
            })
            .collect_vec();
        PromiseVirtualTableResults::<F>::new(leaves, shards)
    }
}

impl<F: Field, T: ComponentType<F>> private::Sealed for SingleComponentLoaderImpl<F, T> {}

impl<F: Field, T: ComponentType<F>> SingleComponentLoader<F> for SingleComponentLoaderImpl<F, T> {
    fn get_component_type_id(&self) -> ComponentTypeId {
        T::get_type_id()
    }
    fn get_component_type_name(&self) -> &'static str {
        T::get_type_name()
    }
    fn get_params(&self) -> &SingleComponentLoaderParams {
        &self.params
    }
    fn promise_results_ready(&self) -> bool {
        self.val_promise_results.is_some()
    }
    fn load_promise_results(&mut self, promise_results: ComponentPromiseResultsInMerkle<F>) {
        // Tip: binary tree with only 1 node has height 0.
        assert!(promise_results.leaves().len() <= 1 << self.params.max_height);
        assert_eq!(promise_results.shards().len(), self.params.shard_caps().len());

        let merkle_vt = promise_results.map_data(|typeless_prs| {
            typeless_prs
                .into_iter()
                .flat_map(|typeless_prs| {
                    FlattenVirtualTable::<F>::from(
                        LogicalResult::<F, T>::try_from(typeless_prs).unwrap(),
                    )
                })
                .collect_vec()
        });

        for (shard_idx, shard) in merkle_vt.shards() {
            let shard_capacity = merkle_vt.leaves()[*shard_idx].capacity;
            assert_eq!(shard_capacity, shard.len());
        }
        self.val_promise_results = Some(merkle_vt);
    }

    fn assign_and_compute_commitment(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
    ) -> (AssignedValue<F>, FlattenVirtualTable<AssignedValue<F>>) {
        let val_promise_results =
            if let Some(val_promise_results) = self.val_promise_results.as_ref() {
                val_promise_results.clone()
            } else {
                self.create_dummy_promise_result_merkle()
            };
        let leaves_to_load = val_promise_results.leaves();

        let assigned_per_shard = val_promise_results
            .shards()
            .iter()
            .map(|(_, vt)| {
                let ctx = builder.base.main(0);
                let witness_vt =
                    vt.iter().map(|(v_i, v_o)| (v_i.assign(ctx), v_o.assign(ctx))).collect_vec();
                let commit = T::Commiter::compute_commitment(&mut builder.base, &witness_vt);
                (commit, witness_vt)
            })
            .collect_vec();

        let range_chip = &builder.range_chip();
        let gate_chip = &range_chip.gate;
        let ctx = builder.base.main(0);
        // Indexes of selected shards. The length is deterministic because we had
        // checked selected_shard.len() == params.shard_caps.len() in load_promise_results.
        let selected_shards = ctx.assign_witnesses(
            val_promise_results.shards().iter().map(|(shard_idx, _)| F::from(*shard_idx as u64)),
        );

        // The circuit has a fixed `self.params.max_height`. This is the maximum height merkle tree supported.
        // However the private inputs of the circuit will dictate the actual heigh of the merkle tree of shards that this circuit is using.
        // Example:
        // We have max height is 3.
        // However, this circuit will only get `leaves_to_load` for 4 shard commitments: [a, b, c, d]
        // It will compute the merkle root of [a, b, c, d] where `4` is a private witness.
        // Then it may have `selected_shards = [0, 2]`, meaning it only de-commits the shards for a, c. It does this by using `select_from_idx` on `[a, b, c, d]` to get `a, c`.
        // Because we always decommit the leaves, meaning we dictate that the leaves much be flat hashes of virtual tables of fixed size (given by `shard_caps`), the
        // private witness for the true height (in this example `4`), is committed to by the merkle root we generate.
        // In other words, our definition of shard commitment provides domain separation for the merkle leaves.

        // The loader's behavior should not depend on inputs. So the loader always computes a merkle tree with a pre-defined height.
        // Then we put the merkle tree to load in the left-bottom of the pre-defined merkle tree. The rest of the leaves are filled with zeros.
        // The root of the merkle tree to load will be on the leftmost path of the pre-defined merkle tree. So we can select the root by
        // the height of the merkle tree to load.

        let num_leaves = 1 << self.params.max_height;
        let leaves_commits = ctx.assign_witnesses(
            leaves_to_load.iter().map(|l| l.commit).chain(iter::repeat(F::ZERO)).take(num_leaves),
        );
        let mut assigned_vts = Vec::with_capacity(assigned_per_shard.len());
        for (selected_shard, (shard_commit, assigned_vt)) in
            selected_shards.into_iter().zip_eq(assigned_per_shard)
        {
            range_chip.check_less_than_safe(ctx, selected_shard, num_leaves as u64);
            let leaf_commit =
                gate_chip.select_from_idx(ctx, leaves_commits.clone(), selected_shard);
            ctx.constrain_equal(&leaf_commit, &shard_commit);

            assigned_vts.push(assigned_vt);
        }
        let flatten_assigned_vts = assigned_vts.into_iter().flatten().collect_vec();

        // Optimization: if there is only one shard, we don't need to compute the merkle tree so no need to create hasher.
        if leaves_commits.len() == 1 {
            return (leaves_commits[0], flatten_assigned_vts);
        };

        let mut hasher = create_hasher::<F>();
        hasher.initialize_consts(ctx, gate_chip);
        let nodes = compute_poseidon_merkle_tree(ctx, gate_chip, &hasher, leaves_commits);

        // Leftmost nodes of the pre-defined merkle tree from bottom to top.
        let leftmost_nodes =
            (0..=self.params.max_height).rev().map(|i| nodes[(1 << i) - 1]).collect_vec();
        // The height of the merkle tree to load.
        let result_height: AssignedValue<F> =
            ctx.load_witness(F::from(leaves_to_load.len().ilog2() as u64));
        range_chip.check_less_than_safe(ctx, result_height, (self.params.max_height + 1) as u64);

        let output_commit = gate_chip.select_from_idx(ctx, leftmost_nodes, result_height);

        (output_commit, flatten_assigned_vts)
    }

    fn generate_lookup_rlc(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_calls: &[&PromiseResultWitness<F>],
        promise_results: &[FlattenVirtualRow<AssignedValue<F>>],
    ) -> (Vec<AssignedValue<F>>, Vec<AssignedValue<F>>) {
        let range_chip = &builder.range_chip();
        let rlc_chip = builder.rlc_chip(&range_chip.gate);
        generate_lookup_rlcs_impl::<F, T>(
            builder,
            range_chip,
            &rlc_chip,
            promise_calls,
            promise_results,
        )
    }

    fn load_dummy_promise_results(&mut self) {
        let vt = self.create_dummy_promise_result_merkle();
        self.val_promise_results = Some(vt);
    }
}

/// Returns `(to_lookup_rlc, lookup_table_rlc)`
/// where `to_lookup_rlc` corresponds to `promise_calls` and
/// `lookup_table_rlc` corresponds to `promise_results`.
///
/// This should only be called in phase1.
pub fn generate_lookup_rlcs_impl<F: Field, T: ComponentType<F>>(
    builder: &mut RlcCircuitBuilder<F>,
    range_chip: &RangeChip<F>,
    rlc_chip: &RlcChip<F>,
    promise_calls: &[&PromiseResultWitness<F>],
    promise_results: &[(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)],
) -> (Vec<AssignedValue<F>>, Vec<AssignedValue<F>>) {
    let gate_ctx = builder.base.main(RLC_PHASE);

    let input_multiplier =
        rlc_chip.rlc_pow_fixed(gate_ctx, range_chip.gate(), T::OutputValue::get_num_fields());

    let to_lookup_rlc =
        builder.parallelize_phase1(promise_calls.to_vec(), |(gate_ctx, rlc_ctx), (f_i, f_o)| {
            let i_rlc = f_i.to_rlc((gate_ctx, rlc_ctx), range_chip, rlc_chip);
            let o_rlc = flatten_witness_to_rlc(rlc_ctx, rlc_chip, f_o);
            range_chip.gate.mul_add(gate_ctx, i_rlc, input_multiplier, o_rlc)
        });

    let (gate_ctx, rlc_ctx) = builder.rlc_ctx_pair();

    let lookup_table_rlc = T::rlc_virtual_rows(
        (gate_ctx, rlc_ctx),
        range_chip,
        rlc_chip,
        &promise_results
            .iter()
            .map(|(f_i, f_o)| {
                (
                    T::InputWitness::try_from(f_i.clone()).unwrap(),
                    T::OutputWitness::try_from(f_o.clone()).unwrap(),
                )
            })
            .collect_vec(),
    );
    (to_lookup_rlc, lookup_table_rlc)
}

/// Trait for computing commit of ONE virtual table.
pub trait ComponentCommiter<F: Field> {
    /// Compute the commitment of a virtual table.
    fn compute_commitment(
        builder: &mut BaseCircuitBuilder<F>,
        witness_promise_results: &[(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)],
    ) -> AssignedValue<F>;
    /// The implementor **must** enforce that the output of this function
    /// is the same as the output value of `compute_commitment`.
    /// We allow a separate implementation purely for performance, as the native commitment
    /// computation is much faster than doing it in the circuit.
    fn compute_native_commitment(witness_promise_results: &[(Flatten<F>, Flatten<F>)]) -> F;
}

/// BasicComponentCommiter simply compute poseidon of all virtual rows.
pub struct BasicComponentCommiter<F: Field>(PhantomData<F>);

impl<F: Field> ComponentCommiter<F> for BasicComponentCommiter<F> {
    fn compute_commitment(
        builder: &mut BaseCircuitBuilder<F>,
        witness_promise_results: &[(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)],
    ) -> AssignedValue<F> {
        let range_chip = &builder.range_chip();
        let ctx = builder.main(0);

        let mut hasher = create_hasher::<F>();
        hasher.initialize_consts(ctx, &range_chip.gate);
        compute_commitment_with_flatten(ctx, &range_chip.gate, &hasher, witness_promise_results)
    }
    fn compute_native_commitment(witness_promise_results: &[(Flatten<F>, Flatten<F>)]) -> F {
        let to_commit = witness_promise_results
            .iter()
            .flat_map(|(i, o)| i.fields.iter().chain(o.fields.iter()).copied())
            .collect_vec();
        compute_poseidon(&to_commit)
    }
}
