use std::{cell::RefCell, env::var, iter};

use halo2_base::{
    gates::{builder::CircuitBuilderStage, RangeChip, RangeInstructions},
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::kzg::commitment::ParamsKZG,
    },
};
use itertools::Itertools;
use snark_verifier::{loader::halo2::Halo2Loader, util::hash::Poseidon};
use snark_verifier_sdk::{
    halo2::{aggregation::AggregationCircuit, POSEIDON_SPEC},
    Snark, LIMBS, SHPLONK,
};

use crate::{
    batch_query::{
        aggregation::{merklelize_instances, HashStrategy},
        response::{
            account::{
                ACCOUNT_BLOCK_RESPONSE_KECCAK_INDEX, ACCOUNT_FULL_RESPONSE_POSEIDON_INDEX,
                ACCOUNT_INSTANCE_SIZE, ACCOUNT_KECCAK_ROOT_INDICES, ACCOUNT_POSEIDON_ROOT_INDICES,
                KECCAK_ACCOUNT_FULL_RESPONSE_INDEX,
            },
            block_header::{
                BLOCK_INSTANCE_SIZE, BLOCK_KECCAK_ROOT_INDICES, BLOCK_POSEIDON_ROOT_INDICES,
                BLOCK_RESPONSE_POSEIDON_INDEX, KECCAK_BLOCK_RESPONSE_INDEX,
            },
            row_consistency::{
                ROW_ACCT_BLOCK_KECCAK_INDEX, ROW_ACCT_POSEIDON_INDEX, ROW_BLOCK_POSEIDON_INDEX,
                ROW_STORAGE_ACCT_KECCAK_INDEX, ROW_STORAGE_BLOCK_KECCAK_INDEX,
                ROW_STORAGE_POSEIDON_INDEX,
            },
            storage::{
                KECCAK_STORAGE_FULL_RESPONSE_INDEX, STORAGE_ACCOUNT_RESPONSE_KECCAK_INDEX,
                STORAGE_BLOCK_RESPONSE_KECCAK_INDEX, STORAGE_FULL_RESPONSE_POSEIDON_INDEX,
                STORAGE_INSTANCE_SIZE, STORAGE_KECCAK_ROOT_INDICES, STORAGE_POSEIDON_ROOT_INDICES,
            },
        },
        DummyEccChip,
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::FIRST_PHASE,
        RlpChip,
    },
    util::EthConfigParams,
    EthCircuitBuilder,
};

/// Circuit that assembles the full response table, verifying
/// block hashes in the table are included in a Merkle Mountain Range (MMR).
/// The MMR will be a commitment to a contiguous list of block hashes, for block numbers `[0, mmr_list_len)`.
///
/// Public instances: accumulators, followed by 13 field elements:
/// * `poseidon_tree_root(block_responses.poseidon)`            // as a field element
/// * `keccak_tree_root(block_responses.keccak)`                // 2 field elements, in hi-lo form
/// * `poseidon_tree_root(full_account_responses.poseidon)`     // as a field element
/// * `keccak_tree_root(full_account_responses.keccak)`         // 2 field elements, in hi-lo form
/// * `poseidon_tree_root(full_storage_response.poseidon)`      // as a field element
/// * `keccak_tree_root(full_storage_response.keccak)`          // 2 field elements, in hi-lo form
/// * `keccak256(abi.encodePacked(mmr[BLOCK_BATCH_DEPTH..]))`   // 2 field elements, H256 in hi-lo form.
/// * `keccak256(abi.encodePacked(mmr[..BLOCK_BATCH_DEPTH]))` as 2 field elements, H256 in hi-lo form.
/// To be clear, `abi.encodedPacked(mmr[d..]) = mmr[d] . mmr[d + 1] . ... . mmr[mmr_num_peaks - 1]` where `.` is concatenation of byte arrays.
#[derive(Clone, Debug)]
pub struct FinalResponseAssemblyCircuit {
    /// Snark with merklelized block responses, verified against MMR
    pub column_block_snark: Snark,
    /// Snark with merklelized account responses
    pub column_account_snark: Snark,
    /// Snark with merklelized storage responses
    pub column_storage_snark: Snark,
    /// Snark for checking consistency of each row of the table (block, account, storage)
    pub row_consistency_snark: Snark,
    /// True if `column_block_snark` was an aggregation circuit
    pub column_block_has_accumulator: bool,
    /// True if `column_account_snark` was an aggregation circuit
    pub column_account_has_accumulator: bool,
    /// True if `column_storage_snark` was an aggregation circuit
    pub column_storage_has_accumulator: bool,
    /// True if `row_consistency_snark` was an aggregation circuit
    pub row_consistency_has_accumulator: bool,
}

impl FinalResponseAssemblyCircuit {
    pub fn new(
        column_block: (Snark, bool),
        column_account: (Snark, bool),
        column_storage: (Snark, bool),
        row_consistency: (Snark, bool),
    ) -> Self {
        Self {
            column_block_snark: column_block.0,
            column_account_snark: column_account.0,
            column_storage_snark: column_storage.0,
            row_consistency_snark: row_consistency.0,
            column_block_has_accumulator: column_block.1,
            column_account_has_accumulator: column_account.1,
            column_storage_has_accumulator: column_storage.1,
            row_consistency_has_accumulator: row_consistency.1,
        }
    }
}

impl FinalResponseAssemblyCircuit {
    fn create(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<RlcThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        log::info!("New FinalResponseAggregationCircuit",);
        // aggregate the snarks
        let aggregation = AggregationCircuit::new::<SHPLONK>(
            stage,
            Some(Vec::new()), // break points aren't actually used, since we will just take the builder from this circuit
            lookup_bits,
            params,
            [
                self.column_block_snark,
                self.column_account_snark,
                self.column_storage_snark,
                self.row_consistency_snark,
            ],
        );
        let (block_instance, account_instance, storage_instance, row_consistency_instance) =
            aggregation
                .previous_instances
                .iter()
                .zip_eq([
                    self.column_block_has_accumulator,
                    self.column_account_has_accumulator,
                    self.column_storage_has_accumulator,
                    self.row_consistency_has_accumulator,
                ])
                .map(|(instance, has_accumulator)| {
                    let start = (has_accumulator as usize) * 4 * LIMBS;
                    &instance[start..]
                })
                .collect_tuple()
                .unwrap();

        // TODO: should reuse RangeChip from aggregation circuit, but can't refactor right now
        let range = RangeChip::default(lookup_bits);
        let gate_builder = aggregation.inner.circuit.0.builder.take();
        let _chip = DummyEccChip(range.gate());
        let loader = Halo2Loader::<G1Affine, _>::new(_chip, gate_builder);

        let mut keccak = KeccakChip::default();
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());

        let (block_instance, verify_mmr_instance) =
            block_instance.split_at(block_instance.len() - 4);
        let block_instance = merklelize_instances(
            HashStrategy::Tree,
            block_instance,
            BLOCK_INSTANCE_SIZE - 4, // exclude mmrs
            BLOCK_POSEIDON_ROOT_INDICES,
            BLOCK_KECCAK_ROOT_INDICES,
            &loader,
            &mut poseidon,
            &range,
            &mut keccak,
        );
        let account_instance = merklelize_instances(
            HashStrategy::Onion,
            account_instance,
            ACCOUNT_INSTANCE_SIZE,
            ACCOUNT_POSEIDON_ROOT_INDICES,
            ACCOUNT_KECCAK_ROOT_INDICES,
            &loader,
            &mut poseidon,
            &range,
            &mut keccak,
        );
        let storage_instance = merklelize_instances(
            HashStrategy::Onion,
            storage_instance,
            STORAGE_INSTANCE_SIZE,
            STORAGE_POSEIDON_ROOT_INDICES,
            STORAGE_KECCAK_ROOT_INDICES,
            &loader,
            &mut poseidon,
            &range,
            &mut keccak,
        );

        let mut gate_builder = loader.take_ctx();
        let ctx = gate_builder.main(FIRST_PHASE);
        // each root in row consistency circuit must match the corresponding root in the other column circuits
        ctx.constrain_equal(
            &row_consistency_instance[ROW_BLOCK_POSEIDON_INDEX],
            &block_instance[BLOCK_RESPONSE_POSEIDON_INDEX],
        );
        ctx.constrain_equal(
            &row_consistency_instance[ROW_ACCT_POSEIDON_INDEX],
            &account_instance[ACCOUNT_FULL_RESPONSE_POSEIDON_INDEX],
        );
        ctx.constrain_equal(
            &row_consistency_instance[ROW_ACCT_BLOCK_KECCAK_INDEX],
            &account_instance[ACCOUNT_BLOCK_RESPONSE_KECCAK_INDEX],
        );
        ctx.constrain_equal(
            &row_consistency_instance[ROW_STORAGE_POSEIDON_INDEX],
            &storage_instance[STORAGE_FULL_RESPONSE_POSEIDON_INDEX],
        );
        ctx.constrain_equal(
            &row_consistency_instance[ROW_STORAGE_BLOCK_KECCAK_INDEX],
            &storage_instance[STORAGE_BLOCK_RESPONSE_KECCAK_INDEX],
        );
        ctx.constrain_equal(
            &row_consistency_instance[ROW_STORAGE_ACCT_KECCAK_INDEX],
            &storage_instance[STORAGE_ACCOUNT_RESPONSE_KECCAK_INDEX],
        );

        // All computations are contained in the `aggregations`'s builder, so we take that to create a new RlcThreadBuilder
        let builder = RlcThreadBuilder { threads_rlc: Vec::new(), gate_builder };
        let mut assigned_instances = aggregation.inner.assigned_instances;

        // add new public instances
        assigned_instances.extend(
            iter::once(block_instance[BLOCK_RESPONSE_POSEIDON_INDEX])
                .chain(block_instance[KECCAK_BLOCK_RESPONSE_INDEX..].iter().take(2).copied())
                .chain(iter::once(account_instance[ACCOUNT_FULL_RESPONSE_POSEIDON_INDEX]))
                .chain(
                    account_instance[KECCAK_ACCOUNT_FULL_RESPONSE_INDEX..].iter().take(2).copied(),
                )
                .chain(iter::once(storage_instance[STORAGE_FULL_RESPONSE_POSEIDON_INDEX]))
                .chain(
                    storage_instance[KECCAK_STORAGE_FULL_RESPONSE_INDEX..].iter().take(2).copied(),
                )
                .chain(verify_mmr_instance.iter().copied()),
        );

        EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            |_: &mut RlcThreadBuilder<Fr>,
             _: RlpChip<Fr>,
             _: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {},
        )
    }

    pub fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<RlcThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let circuit = self.create(stage, break_points, lookup_bits, params);
        #[cfg(not(feature = "production"))]
        if stage != CircuitBuilderStage::Prover {
            let config_params: EthConfigParams = serde_json::from_str(
                var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
            )
            .unwrap();
            circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
        }
        circuit
    }
}
