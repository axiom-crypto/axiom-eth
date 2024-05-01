use std::collections::HashMap;

use anyhow::{bail, Result};
use axiom_eth::{
    halo2_base::gates::{circuit::CircuitBuilderStage, GateChip},
    halo2_proofs::poly::kzg::commitment::ParamsKZG,
    halo2curves::bn256::Bn256,
    snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, SHPLONK},
    utils::{
        build_utils::pinning::aggregation::AggregationCircuitPinning,
        component::{
            promise_loader::multi::ComponentTypeList, types::ComponentPublicInstances,
            utils::create_hasher, ComponentType,
        },
        snark_verifier::{
            create_universal_aggregation_circuit, AggregationCircuitParams, NUM_FE_ACCUMULATOR,
        },
    },
};
use itertools::{zip_eq, Itertools};

use crate::components::{
    results::{circuit::SubqueryDependencies, types::LogicalPublicInstanceResultsRoot},
    subqueries::{
        account::types::ComponentTypeAccountSubquery,
        block_header::types::{ComponentTypeHeaderSubquery, LogicalPublicInstanceHeader},
        receipt::types::ComponentTypeReceiptSubquery,
        solidity_mappings::types::ComponentTypeSolidityNestedMappingSubquery,
        storage::types::ComponentTypeStorageSubquery,
        transaction::types::ComponentTypeTxSubquery,
    },
};

use super::types::{InputSubqueryAggregation, LogicalPublicInstanceSubqueryAgg, F};

impl InputSubqueryAggregation {
    /// Builds general circuit
    ///
    /// Warning: this MUST return a circuit implementing `CircuitExt` with accumulator indices provided.
    /// In particular, do not return `BaseCircuitBuilder`.
    pub fn build(
        self,
        stage: CircuitBuilderStage,
        circuit_params: AggregationCircuitParams,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> Result<AggregationCircuit> {
        // dependency checks
        if self.snark_storage.is_some() && self.snark_account.is_none() {
            bail!("Storage snark requires Account snark");
        }
        if self.snark_solidity_mapping.is_some() && self.snark_storage.is_none() {
            bail!("SolidityMapping snark requires Storage snark");
        }
        const NUM_SNARKS: usize = 7;
        let snarks = vec![
            Some(self.snark_header),
            self.snark_account,
            self.snark_storage,
            self.snark_tx,
            self.snark_receipt,
            self.snark_solidity_mapping,
            Some(self.snark_results_root),
        ];
        let snarks_enabled = snarks.iter().map(|s| s.is_some()).collect_vec();
        let subquery_type_ids = [
            ComponentTypeHeaderSubquery::<F>::get_type_id(),
            ComponentTypeAccountSubquery::<F>::get_type_id(),
            ComponentTypeStorageSubquery::<F>::get_type_id(),
            ComponentTypeTxSubquery::<F>::get_type_id(),
            ComponentTypeReceiptSubquery::<F>::get_type_id(),
            ComponentTypeSolidityNestedMappingSubquery::<F>::get_type_id(),
        ];
        if snarks.iter().flatten().any(|s| s.agg_vk_hash_idx.is_some()) {
            bail!("[SubqueryAggregation] No snark should be universal.");
        }
        let snarks = snarks.into_iter().flatten().map(|s| s.inner).collect_vec();
        let agg_vkey_hash_indices = vec![None; snarks.len()];
        let (mut circuit, previous_instances, agg_vkey_hash) =
            create_universal_aggregation_circuit::<SHPLONK>(
                stage,
                circuit_params,
                kzg_params,
                snarks,
                agg_vkey_hash_indices,
            );

        let builder = &mut circuit.builder;
        let ctx = builder.main(0);

        // Parse aggregated component public instances
        let mut previous_instances = previous_instances.into_iter();
        let mut get_next_pis =
            || ComponentPublicInstances::try_from(previous_instances.next().unwrap());
        let mut pis = Vec::with_capacity(NUM_SNARKS);
        for snark_enabled in snarks_enabled {
            if snark_enabled {
                pis.push(Some(get_next_pis()?));
            } else {
                pis.push(None);
            }
        }
        let pis_header = pis[0].clone().unwrap();
        let pis_results = pis.pop().unwrap().unwrap();

        // Load promise commit keccak as a public input
        let promise_keccak = ctx.load_witness(self.promise_commit_keccak);
        // ======== Create Poseidon hasher ===========
        let gate = GateChip::default();
        let mut hasher = create_hasher();
        hasher.initialize_consts(ctx, &gate);
        // Insert subquery output commits
        // Unclear if this is a necessary precaution, but we store based on `subquery_type_ids` so the order does not depend on ordering in other modules
        let mut subquery_commits = HashMap::new();
        // Insert subquery promise commits
        let mut subquery_promises = HashMap::new();
        for (type_id, pi) in zip_eq(subquery_type_ids, &pis) {
            if let Some(pi) = pi {
                subquery_commits.insert(type_id.clone(), pi.output_commit);
                subquery_promises.insert(type_id, pi.promise_result_commit);
            }
        }
        // Hash each subquery output commit with the `promise_commit_keccak`, to be compared with subquery promises later.
        // This matches the promise public output computation in `ComponentCircuitImpl::generate_public_instances`.
        // The dependencies of a non-Header subquery circuit are always [Keccak, <Single Subquery Type>]
        // We only need to calculate the hash for components that are called: Header, Account, Storage. Currently Tx, Receipt, SolidityNestedMapping are not called.
        let mut hashed_commits = HashMap::new();
        for type_id in [
            ComponentTypeHeaderSubquery::<F>::get_type_id(),
            ComponentTypeAccountSubquery::<F>::get_type_id(),
            ComponentTypeStorageSubquery::<F>::get_type_id(),
        ] {
            if let Some(output_commit) = subquery_commits.get(&type_id) {
                hashed_commits.insert(
                    type_id,
                    hasher.hash_fix_len_array(ctx, &gate, &[promise_keccak, *output_commit]),
                );
            }
        }

        // ======== Manually check all promise calls between subqueries: =======
        // Header calls Keccak
        {
            let hashed_commit_keccak = hasher.hash_fix_len_array(ctx, &gate, &[promise_keccak]);
            let header_promise_commit =
                subquery_promises[&ComponentTypeHeaderSubquery::<F>::get_type_id()];
            log::debug!("hash(promise_keccak): {:?}", hashed_commit_keccak.value());
            log::debug!("header_promise_commit: {:?}", header_promise_commit.value());
            ctx.constrain_equal(&hashed_commit_keccak, &header_promise_commit);
        }
        // Below when we say promise_header and commit_header, we actually mean promise_keccak_header and commit_keccak_header because both have been hashed with a promise_keccak.
        // Account calls Keccak & Header
        if let Some(promise_header) =
            subquery_promises.get(&ComponentTypeAccountSubquery::<F>::get_type_id())
        {
            let commit_header = hashed_commits[&ComponentTypeHeaderSubquery::<F>::get_type_id()];
            log::debug!("account:commit_header: {:?}", commit_header.value());
            log::debug!("account:promise_header: {:?}", promise_header.value());
            ctx.constrain_equal(&commit_header, promise_header);
        }
        // Storage calls Keccak & Account
        if let Some(promise_account) =
            subquery_promises.get(&ComponentTypeStorageSubquery::<F>::get_type_id())
        {
            let commit_account = hashed_commits[&ComponentTypeAccountSubquery::<F>::get_type_id()];
            log::debug!("storage:commit_account: {:?}", commit_account.value());
            log::debug!("storage:promise_account: {:?}", promise_account.value());
            ctx.constrain_equal(&commit_account, promise_account);
        }
        // Tx calls Keccak & Header
        if let Some(promise_header) =
            subquery_promises.get(&ComponentTypeTxSubquery::<F>::get_type_id())
        {
            let commit_header = hashed_commits[&ComponentTypeHeaderSubquery::<F>::get_type_id()];
            log::debug!("tx:commit_header: {:?}", commit_header.value());
            log::debug!("tx:promise_header: {:?}", promise_header.value());
            ctx.constrain_equal(&commit_header, promise_header);
        }
        // Receipt calls Keccak & Header
        if let Some(promise_header) =
            subquery_promises.get(&ComponentTypeReceiptSubquery::<F>::get_type_id())
        {
            let commit_header = hashed_commits[&ComponentTypeHeaderSubquery::<F>::get_type_id()];
            log::debug!("receipt:commit_header: {:?}", commit_header.value());
            log::debug!("receipt:promise_header: {:?}", promise_header.value());
            ctx.constrain_equal(&commit_header, promise_header);
        }
        // SolidityNestedMapping calls Keccak & Storage
        if let Some(promise_storage) =
            subquery_promises.get(&ComponentTypeSolidityNestedMappingSubquery::<F>::get_type_id())
        {
            let commit_storage = hashed_commits[&ComponentTypeStorageSubquery::<F>::get_type_id()];
            log::debug!("solidity_nested_mapping:commit_storage: {:?}", commit_storage.value());
            log::debug!("solidity_nested_mapping:promise_storage: {:?}", promise_storage.value());
            ctx.constrain_equal(&commit_storage, promise_storage);
        }

        // Get keccakPacked(blockhashMmr)
        let LogicalPublicInstanceHeader { mmr_keccak } = pis_header.other.try_into()?;

        // ======== results root =========
        // MUST match order in `InputResultsRootShard::build`
        let type_ids = SubqueryDependencies::<F>::get_component_type_ids();
        // We now collect the promises from snarks in the order they were committed to in ResultsRoot
        let mut results_deps_commits = Vec::new();
        results_deps_commits.push(promise_keccak);
        for t_id in &type_ids {
            if let Some(commit) = subquery_commits.get(t_id) {
                results_deps_commits.push(*commit);
            }
        }

        let results_promise_commit = hasher.hash_fix_len_array(ctx, &gate, &results_deps_commits);

        log::debug!("results_promise_commit: {:?}", results_promise_commit.value());
        log::debug!("promise_result_commit: {:?}", pis_results.promise_result_commit.value());
        ctx.constrain_equal(&results_promise_commit, &pis_results.promise_result_commit);

        // We have implicitly checked all Components use the same `promise_keccak` above.

        let LogicalPublicInstanceResultsRoot { results_root_poseidon, commit_subquery_hashes } =
            pis_results.other.try_into().unwrap();

        let logical_pis = LogicalPublicInstanceSubqueryAgg {
            promise_keccak,
            agg_vkey_hash,
            results_root_poseidon,
            commit_subquery_hashes,
            mmr_keccak,
        };
        if builder.assigned_instances.len() != 1 {
            bail!("should only have 1 instance column");
        }
        assert_eq!(builder.assigned_instances[0].len(), NUM_FE_ACCUMULATOR);
        builder.assigned_instances[0].extend(logical_pis.flatten());

        Ok(circuit)
    }

    pub fn prover_circuit(
        self,
        pinning: AggregationCircuitPinning,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> Result<AggregationCircuit> {
        Ok(self
            .build(CircuitBuilderStage::Prover, pinning.params, kzg_params)?
            .use_break_points(pinning.break_points))
    }
}
