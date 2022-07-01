use std::any::type_name;

use axiom_eth::{
    halo2_base::{AssignedValue, Context},
    halo2_proofs::plonk::ConstraintSystem,
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::build_utils::{aggregation::CircuitMetadata, dummy::DummyFrom},
    Field,
};
use component_derive::ComponentParams;
use itertools::Itertools;

use crate::framework::{
    circuit::{
        ComponentBuilder, CoreBuilder, CoreBuilderInput, CoreBuilderOutput, CoreBuilderParams,
    },
    promise_collector::PromiseCaller,
    types::{FixLenLogical, LogicalEmpty},
    utils::get_logical_value,
    ComponentType, ComponentTypeId, FlattenVirtualTable, LogicalInputValue, LogicalResult,
};

pub type BasicComponentScaffoldIOPair<F, I> = Vec<(
    <I as BasicComponentScaffold<F>>::Input<AssignedValue<F>>,
    <I as BasicComponentScaffold<F>>::Output<AssignedValue<F>>,
)>;

pub type BasicComponentScaffoldIO<F, I> = (
    <I as BasicComponentScaffold<F>>::Phase0Payload,
    BasicComponentScaffoldIOPair<F, I>,
);

/// Basic component paramater struct for components whose configuration is only based on capacity.
#[derive(Default, Clone, ComponentParams)]
pub struct BasicComponentParams {
    pub capacity: usize,
}

impl BasicComponentParams {
    pub fn new(capacity: usize) -> Self {
        Self { capacity }
    }
}

/// The struct on which `ComponentType` and `CoreBuilder` are implemented,
/// given some `BasicComponentScaffold` implementation.
pub struct BasicComponentScaffoldImpl<F: Field, I: BasicComponentScaffold<F>> {
    pub params: I::Params,
    pub input: Option<Vec<I::Input<F>>>,
    pub payload: Option<I::Phase0Payload>,
}

/// Trait for specifying the types for a **single** input and output of a `BasicComponentScaffold` component.
/// The input of the component is `Vec<InputType<T>>` and the output is `Vec<OutputType<T>>`.
pub trait BasicComponentScaffoldIOTypes<F: Field> {
    type InputType<T: Copy>: FixLenLogical<T>;
    type OutputType<T: Copy>: FixLenLogical<T>;
}

/// Trait for defining a fixed-len component that uses `RlcCircuitBuilder` and does not
/// make calls to other components.
///
/// See `./README.md` for more information on how to use this trait, and `src/example/mod.rs`
/// for an example of how to implement this trait
pub trait BasicComponentScaffold<F: Field>: BasicComponentScaffoldIOTypes<F> {
    type Input<T: Copy>: FixLenLogical<T> = Self::InputType<T>;
    type Output<T: Copy>: FixLenLogical<T> = Self::OutputType<T>;
    type Params: Clone + Default + CoreBuilderParams = BasicComponentParams;
    type Phase0Payload = ();
    type LogicalPublicInstance<T: Copy>: FixLenLogical<T> = LogicalEmpty<T>;

    fn virtual_assign_phase0(
        params: Self::Params,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<Self::Input<F>>,
    ) -> BasicComponentScaffoldIO<F, Self>;

    #[allow(unused_variables)]
    fn virtual_assign_phase1(builder: &mut RlcCircuitBuilder<F>, payload: Self::Phase0Payload) {}

    //optional helper function to assign input
    fn assign_input(ctx: &mut Context<F>, input: Self::Input<F>) -> Self::Input<AssignedValue<F>> {
        let flattened_input = input.into_raw();
        let assigned_input = ctx.assign_witnesses(flattened_input);
        Self::Input::<AssignedValue<F>>::try_from_raw(assigned_input).unwrap()
    }
}

impl<F: Field, I: BasicComponentScaffold<F> + 'static> ComponentType<F>
    for BasicComponentScaffoldImpl<F, I>
where
    I::Input<F>: LogicalInputValue<F> + DummyFrom<I::Params>,
{
    type InputValue = I::Input<F>;
    type InputWitness = I::Input<AssignedValue<F>>;
    type OutputValue = I::Output<F>;
    type OutputWitness = I::Output<AssignedValue<F>>;
    type LogicalInput = Self::InputValue;

    fn get_type_id() -> ComponentTypeId {
        //type_name includes generic parameters, so we remove them
        type_name::<I>().split('<').next().unwrap().to_string()
    }

    fn logical_result_to_virtual_rows_impl(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        vec![(ins.input.clone(), ins.output.clone())]
    }
    fn logical_input_to_virtual_rows_impl(li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        vec![li.clone()]
    }
}

impl<F: Field, I: BasicComponentScaffold<F>> ComponentBuilder<F>
    for BasicComponentScaffoldImpl<F, I>
{
    type Config = ();
    type Params = I::Params;

    fn new(params: Self::Params) -> Self {
        Self {
            input: None,
            params,
            payload: None,
        }
    }

    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }

    fn configure_with_params(_: &mut ConstraintSystem<F>, _: Self::Params) -> Self::Config {}

    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }

    fn clear_witnesses(&mut self) {
        self.payload = None;
    }
}

impl<F: Field, I: BasicComponentScaffold<F> + 'static> CoreBuilder<F>
    for BasicComponentScaffoldImpl<F, I>
where
    I::Input<F>: LogicalInputValue<F> + DummyFrom<I::Params>,
    Vec<I::Input<F>>: DummyFrom<I::Params>,
{
    type CompType = Self;
    type PublicInstanceValue = I::LogicalPublicInstance<F>;
    type PublicInstanceWitness = I::LogicalPublicInstance<AssignedValue<F>>;
    type CoreInput = Vec<I::Input<F>>;

    fn feed_input(&mut self, mut input: Self::CoreInput) -> anyhow::Result<()> {
        let capacity = self.params.get_output_params().cap_per_shard()[0];
        if input.len() > capacity {
            anyhow::bail!(
                "Subquery results table is greater than capcaity - {} > {}",
                input.len(),
                capacity
            );
        }
        input.resize(capacity, input.get(0).unwrap().clone());
        self.input = Some(input);
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        _: PromiseCaller<F>,
    ) -> CoreBuilderOutput<F, Self::CompType> {
        //otherwise will fail if phase1 doesn't exist
        builder.base.main(1);
        let (payload, output_vec) =
            I::virtual_assign_phase0(self.params.clone(), builder, self.input.clone().unwrap());
        self.payload = Some(payload);
        let vt: FlattenVirtualTable<AssignedValue<F>> = output_vec
            .iter()
            .map(|output| (output.0.clone().into(), output.1.clone().into()))
            .collect_vec();
        let lr = output_vec
            .iter()
            .map(|output| {
                LogicalResult::<F, Self::CompType>::new(
                    get_logical_value(&output.0.clone()),
                    get_logical_value(&output.1.clone()),
                )
            })
            .collect_vec();

        CoreBuilderOutput {
            public_instances: vec![],
            virtual_table: vt,
            logical_results: lr,
        }
    }

    fn virtual_assign_phase1(&mut self, builder: &mut RlcCircuitBuilder<F>) {
        let payload = self.payload.take().unwrap();
        I::virtual_assign_phase1(builder, payload);
    }
}

impl<F: Field, I: BasicComponentScaffold<F>> CircuitMetadata for BasicComponentScaffoldImpl<F, I> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        unreachable!()
    }
}
