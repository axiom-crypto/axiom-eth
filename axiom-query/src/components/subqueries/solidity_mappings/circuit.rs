use axiom_codec::{
    constants::MAX_SOLIDITY_MAPPING_KEYS,
    types::field_elements::FieldSolidityNestedMappingSubquery, HiLo,
};
use axiom_eth::{
    halo2_base::{
        gates::flex_gate::threads::parallelize_core, safe_types::SafeBytes32, AssignedValue,
        Context,
    },
    halo2_proofs::plonk::ConstraintSystem,
    keccak::{types::ComponentTypeKeccak, KeccakChip},
    mpt::MPTChip,
    rlc::circuit::builder::RlcCircuitBuilder,
    rlc::circuit::builder::RlcContextPair,
    rlp::RlpChip,
    solidity::{
        types::{NestedMappingWitness, SolidityType},
        SolidityChip,
    },
    utils::{
        build_utils::aggregation::CircuitMetadata,
        circuit_utils::bytes::safe_bytes32_to_hi_lo,
        component::{
            circuit::{
                ComponentBuilder, ComponentCircuitImpl, CoreBuilder, CoreBuilderOutput,
                CoreBuilderOutputParams, CoreBuilderParams,
            },
            promise_collector::PromiseCaller,
            promise_loader::{combo::PromiseBuilderCombo, single::PromiseLoader},
            types::LogicalEmpty,
            utils::{create_hasher, get_logical_value},
            LogicalResult,
        },
        uint_to_bytes_be,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::storage::types::{
        ComponentTypeStorageSubquery, FieldStorageSubqueryCall,
    },
    utils::codec::{AssignedSolidityNestedMappingSubquery, AssignedStorageSubquery},
    Field,
};

use super::types::{
    CircuitInputSolidityNestedMappingShard, ComponentTypeSolidityNestedMappingSubquery,
};

pub struct CoreBuilderSolidityNestedMappingSubquery<F: Field> {
    input: Option<CircuitInputSolidityNestedMappingShard<F>>,
    params: CoreParamsSolidityNestedMappingSubquery,
    payload: Option<(KeccakChip<F>, Vec<PayloadSolidityNestedMappingSubquery<F>>)>,
}

/// Specify the output format of SolidityNestedMappingSubquery component.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsSolidityNestedMappingSubquery {
    pub capacity: usize,
}
impl CoreBuilderParams for CoreParamsSolidityNestedMappingSubquery {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

type CKeccak<F> = ComponentTypeKeccak<F>;
type CStorage<F> = ComponentTypeStorageSubquery<F>;
/// Used for loading solidity nested mapping promise results.
pub type PromiseLoaderSolidityNestedMappingSubquery<F> =
    PromiseBuilderCombo<F, PromiseLoader<F, CKeccak<F>>, PromiseLoader<F, CStorage<F>>>;
pub type ComponentCircuitSolidityNestedMappingSubquery<F> = ComponentCircuitImpl<
    F,
    CoreBuilderSolidityNestedMappingSubquery<F>,
    PromiseLoaderSolidityNestedMappingSubquery<F>,
>;

impl<F: Field> CircuitMetadata for CoreBuilderSolidityNestedMappingSubquery<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        unreachable!()
    }
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderSolidityNestedMappingSubquery<F> {
    type Params = CoreParamsSolidityNestedMappingSubquery;

    fn new(params: Self::Params) -> Self {
        Self { input: None, params, payload: None }
    }
    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }
    fn clear_witnesses(&mut self) {
        self.payload = None;
    }
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
    fn configure_with_params(_: &mut ConstraintSystem<F>, _: Self::Params) {}
}
impl<F: Field> CoreBuilder<F> for CoreBuilderSolidityNestedMappingSubquery<F> {
    type CompType = ComponentTypeSolidityNestedMappingSubquery<F>;
    type PublicInstanceValue = LogicalEmpty<F>;
    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;
    type CoreInput = CircuitInputSolidityNestedMappingShard<F>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        self.input = Some(input);
        Ok(())
    }
    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_caller: PromiseCaller<F>,
    ) -> CoreBuilderOutput<F, Self::CompType> {
        // preamble: to be removed
        let keccak =
            KeccakChip::new_with_promise_collector(builder.range_chip(), promise_caller.clone());
        let range_chip = keccak.range();
        let rlp = RlpChip::new(range_chip, None);
        let mut poseidon = create_hasher();
        poseidon.initialize_consts(builder.base.main(0), keccak.gate());

        // Assumption: we already have input when calling this function.
        // TODO: automatically derive a dummy input from params.
        let input = self.input.as_ref().unwrap();

        let mpt = MPTChip::new(rlp, &keccak);
        let chip = SolidityChip::new(&mpt, MAX_SOLIDITY_MAPPING_KEYS, 32);
        let pool = &mut builder.base.pool(0);
        let payload = parallelize_core(pool, input.requests.clone(), |ctx, subquery| {
            handle_single_solidity_nested_mapping_subquery_phase0(ctx, &chip, &subquery)
        });

        let ctx = pool.main();
        let mut vt = Vec::with_capacity(payload.len());
        let mut lr = Vec::with_capacity(payload.len());
        // promise calls to header component:
        for p in payload.iter() {
            let block_number = p.subquery.block_number;
            let addr = p.subquery.addr;
            let slot = p.value_slot;
            let storage_subquery = AssignedStorageSubquery { block_number, addr, slot };
            // promise call to get the value at the value_slot
            let value = promise_caller
                .call::<FieldStorageSubqueryCall<F>, ComponentTypeStorageSubquery<F>>(
                    ctx,
                    FieldStorageSubqueryCall(storage_subquery),
                )
                .unwrap();
            vt.push((p.subquery.into(), value.into()));
            lr.push(LogicalResult::<F, Self::CompType>::new(
                get_logical_value(&p.subquery),
                get_logical_value(&value),
            ));
        }
        self.payload = Some((keccak, payload));
        CoreBuilderOutput { public_instances: vec![], virtual_table: vt, logical_results: lr }
    }

    fn virtual_assign_phase1(&mut self, builder: &mut RlcCircuitBuilder<F>) {
        let (keccak, payload) = self.payload.take().unwrap();
        // preamble
        let range_chip = keccak.range();
        let rlc_chip = builder.rlc_chip(&range_chip.gate);
        let rlp = RlpChip::new(range_chip, Some(&rlc_chip));
        let mpt = MPTChip::new(rlp, &keccak);
        let chip = SolidityChip::new(&mpt, MAX_SOLIDITY_MAPPING_KEYS, 32);

        // actual logic
        builder.parallelize_phase1(payload, |(ctx_gate, ctx_rlc), payload| {
            handle_single_solidity_nested_mapping_subquery_phase1(
                (ctx_gate, ctx_rlc),
                &chip,
                payload,
            )
        });
    }
}

pub struct PayloadSolidityNestedMappingSubquery<F: Field> {
    pub mapping_witness: NestedMappingWitness<F>,
    pub subquery: AssignedSolidityNestedMappingSubquery<F>,
    /// Storage slot with the actual value of the mapping
    pub value_slot: HiLo<AssignedValue<F>>,
}

/// Assigns `subquery` to virtual cells and then handles the subquery.
/// Calculates the correct raw EVM storage slot corresponding to the nested mapping.
/// We do not return the `value` here. Instead we use the `value` gotten by making a promise
/// call to the Storage Subqueries Component circuit at the returned `slot`.
pub fn handle_single_solidity_nested_mapping_subquery_phase0<F: Field>(
    ctx: &mut Context<F>,
    chip: &SolidityChip<F>,
    subquery: &FieldSolidityNestedMappingSubquery<F>,
) -> PayloadSolidityNestedMappingSubquery<F> {
    let gate = chip.gate();
    let range = chip.range();
    // assign `mapping_slot` as HiLo
    let mapping_slot = subquery.mapping_slot.assign(ctx);
    // convert to `SafeBytes32`
    let mapping_slot_bytes = SafeBytes32::try_from(
        mapping_slot.hi_lo().map(|u| uint_to_bytes_be(ctx, range, &u, 16)).concat(),
    )
    .unwrap();
    let keys_hilo = subquery.keys.map(|key| key.assign(ctx));
    let keys = keys_hilo.map(|k| {
        SolidityType::Value(
            SafeBytes32::try_from(k.hi_lo().map(|u| uint_to_bytes_be(ctx, range, &u, 16)).concat())
                .unwrap(),
        )
    });
    let mapping_depth = ctx.load_witness(subquery.mapping_depth);
    let mapping_witness =
        chip.slot_for_nested_mapping_phase0(ctx, mapping_slot_bytes, keys, mapping_depth);
    let value_slot = safe_bytes32_to_hi_lo(ctx, gate, &mapping_witness.slot);

    // Assign the rest of the subquery as witnesses
    let addr = ctx.load_witness(subquery.addr);
    let block_number = ctx.load_witness(subquery.block_number);
    let subquery = AssignedSolidityNestedMappingSubquery {
        block_number,
        addr,
        mapping_slot,
        mapping_depth,
        keys: keys_hilo,
    };

    PayloadSolidityNestedMappingSubquery { mapping_witness, subquery, value_slot }
}

pub fn handle_single_solidity_nested_mapping_subquery_phase1<F: Field>(
    ctx: RlcContextPair<F>,
    chip: &SolidityChip<F>,
    payload: PayloadSolidityNestedMappingSubquery<F>,
) {
    chip.slot_for_nested_mapping_phase1(ctx, payload.mapping_witness);
}
