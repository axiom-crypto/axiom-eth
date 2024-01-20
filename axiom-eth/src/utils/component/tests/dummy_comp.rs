use crate::{
    impl_flatten_conversion, impl_logical_input,
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::{CoreBuilderInput, CoreBuilderOutput, CoreBuilderOutputParams},
            utils::{get_logical_value, into_key},
        },
    },
};
use halo2_base::{
    gates::GateInstructions,
    halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem},
    AssignedValue,
};

use super::{
    circuit::{ComponentBuilder, CoreBuilder},
    promise_collector::PromiseCaller,
    promise_loader::flatten_witness_to_rlc,
    types::{FixLenLogical, LogicalEmpty},
    utils::load_logical_value,
    *,
};

// =============== Add Component ===============

const ADD_INPUT_FIELD_SIZE: [usize; 2] = [64, 64];
const ADD_OUTPUT_FIELD_SIZE: [usize; 1] = [128];

/// a + b
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalInputAdd<T: Clone> {
    pub a: T,
    pub b: T,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct LogicalOutputAdd<T> {
    pub c: T,
}

impl<T: Clone> TryFrom<Vec<T>> for LogicalInputAdd<T> {
    type Error = anyhow::Error;
    fn try_from(mut value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(anyhow::anyhow!("invalid length"));
        }
        let b = value.pop().unwrap();
        let a = value.pop().unwrap();

        Ok(LogicalInputAdd::<T> { a, b })
    }
}

impl<T: Clone> LogicalInputAdd<T> {
    pub fn flatten(self) -> Vec<T> {
        vec![self.a, self.b]
    }
}

impl_flatten_conversion!(LogicalInputAdd, ADD_INPUT_FIELD_SIZE);
impl_logical_input!(LogicalInputAdd, 1);

impl<F: Field> PromiseCallWitness<F> for LogicalInputAdd<AssignedValue<F>> {
    fn get_component_type_id(&self) -> ComponentTypeId {
        ComponentTypeAdd::<F>::get_type_id()
    }
    fn get_capacity(&self) -> usize {
        1
    }
    fn to_rlc(
        &self,
        (_, rlc_ctx): (&mut Context<F>, &mut Context<F>),
        _range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
    ) -> AssignedValue<F> {
        flatten_witness_to_rlc(rlc_ctx, rlc_chip, &self.clone().into())
    }
    fn to_typeless_logical_input(&self) -> TypelessLogicalInput {
        let f_a: Flatten<AssignedValue<F>> = self.clone().into();
        let f_v: Flatten<F> = f_a.into();
        let l_v: LogicalInputAdd<F> = f_v.try_into().unwrap();
        into_key(l_v)
    }
    fn get_mock_output(&self) -> Flatten<F> {
        let output_val: <ComponentTypeAdd<F> as ComponentType<F>>::OutputValue = Default::default();
        output_val.into()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// This should be done by marco.
impl<T: Copy> TryFrom<Flatten<T>> for LogicalOutputAdd<T> {
    type Error = anyhow::Error;

    fn try_from(value: Flatten<T>) -> std::result::Result<Self, Self::Error> {
        if value.field_size != ADD_OUTPUT_FIELD_SIZE {
            return Err(anyhow::anyhow!("invalid field size for add output"));
        }
        Ok(LogicalOutputAdd::<T> { c: value.fields[0] })
    }
}
// This should be done by marco.
impl<T: Copy> From<LogicalOutputAdd<T>> for Flatten<T> {
    fn from(val: LogicalOutputAdd<T>) -> Self {
        Flatten::<T> { fields: vec![val.c], field_size: &ADD_OUTPUT_FIELD_SIZE }
    }
}
// This should be done by marco.
impl<T: Copy> FixLenLogical<T> for LogicalOutputAdd<T> {
    fn get_field_size() -> &'static [usize] {
        &ADD_OUTPUT_FIELD_SIZE
    }
}

#[derive(Debug, Clone)]
pub struct ComponentTypeAdd<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ComponentType<F> for ComponentTypeAdd<F> {
    type InputValue = LogicalInputAdd<F>;
    type InputWitness = LogicalInputAdd<AssignedValue<F>>;
    type OutputValue = LogicalOutputAdd<F>;
    type OutputWitness = LogicalOutputAdd<AssignedValue<F>>;
    type LogicalInput = LogicalInputAdd<F>;

    fn get_type_id() -> ComponentTypeId {
        "ComponentTypeAdd".to_string()
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

const ADD_MUL_INPUT_FIELD_SIZE: [usize; 3] = [64, 64, 64];

/// a * b + c
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LogicalInputAddMul<T: Clone> {
    pub a: T,
    pub b: T,
    pub c: T,
}

pub type LogicalOutputAddMul<T> = LogicalOutputAdd<T>;

impl<T: Clone> TryFrom<Vec<T>> for LogicalInputAddMul<T> {
    type Error = anyhow::Error;
    fn try_from(mut value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() != 3 {
            return Err(anyhow::anyhow!("invalid length"));
        }
        let c = value.pop().unwrap();
        let b = value.pop().unwrap();
        let a = value.pop().unwrap();

        Ok(LogicalInputAddMul::<T> { a, b, c })
    }
}

impl<T: Clone> LogicalInputAddMul<T> {
    pub fn flatten(self) -> Vec<T> {
        vec![self.a, self.b, self.c]
    }
}

impl_flatten_conversion!(LogicalInputAddMul, ADD_MUL_INPUT_FIELD_SIZE);
impl_logical_input!(LogicalInputAddMul, 1);

// =============== AddMul Component ===============
#[derive(Debug, Clone)]
pub struct ComponentTypeAddMul<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ComponentType<F> for ComponentTypeAddMul<F> {
    type InputValue = LogicalInputAddMul<F>;
    type InputWitness = LogicalInputAddMul<AssignedValue<F>>;
    type OutputValue = LogicalOutputAddMul<F>;
    type OutputWitness = LogicalOutputAddMul<AssignedValue<F>>;
    type LogicalInput = LogicalInputAddMul<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-eth:ComponentTypeAddMul".to_string()
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

#[derive(Clone, Serialize, Deserialize)]
pub struct CoreInputAddMul<F: RawField> {
    pub inputs: Vec<LogicalInputAddMul<F>>,
}

impl<F: RawField> DummyFrom<CoreBuilderOutputParams> for CoreInputAddMul<F> {
    fn dummy_from(params: CoreBuilderOutputParams) -> Self {
        Self {
            inputs: params
                .cap_per_shard()
                .iter()
                .flat_map(|c| {
                    vec![LogicalInputAddMul::<F> { a: F::ZERO, b: F::ZERO, c: F::ZERO }; *c]
                })
                .collect(),
        }
    }
}

pub struct BuilderAddMul<F: Field> {
    input: Option<CoreInputAddMul<F>>,
    params: CoreBuilderOutputParams,
}

impl<F: Field> ComponentBuilder<F> for BuilderAddMul<F> {
    type Config = ();
    type Params = CoreBuilderOutputParams;

    fn new(params: CoreBuilderOutputParams) -> Self {
        Self { input: None, params }
    }
    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }
    fn clear_witnesses(&mut self) {}
    fn configure_with_params(
        _meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
    }
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
}

impl<F: Field> CoreBuilder<F> for BuilderAddMul<F> {
    type CompType = ComponentTypeAddMul<F>;
    type PublicInstanceValue = LogicalEmpty<F>;
    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;
    type CoreInput = CoreInputAddMul<F>;
    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        self.input = Some(input);
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_caller: PromiseCaller<F>,
    ) -> CoreBuilderOutput<F, Self::CompType> {
        let range_chip = builder.range_chip();
        let ctx = builder.base.main(0);
        let inputs: &Vec<LogicalInputAddMul<F>> = &self.input.as_ref().unwrap().inputs;
        let (vt, lr): (FlattenVirtualTable<AssignedValue<F>>, Vec<LogicalResult<F, _>>) = inputs
            .iter()
            .map(|input| {
                let witness_input = load_logical_value::<
                    F,
                    LogicalInputAddMul<F>,
                    LogicalInputAddMul<AssignedValue<F>>,
                >(ctx, input);
                let witness_mul = range_chip.gate.mul(ctx, witness_input.a, witness_input.b);
                let to_add = LogicalInputAdd { a: witness_mul, b: witness_input.c };
                let add_result = promise_caller
                    .call::<LogicalInputAdd<AssignedValue<F>>, ComponentTypeAdd<F>>(ctx, to_add)
                    .unwrap();
                let add_result_val = get_logical_value(&add_result);
                (
                    (witness_input.into(), add_result.into()),
                    LogicalResult::<F, Self::CompType>::new(input.clone(), add_result_val),
                )
            })
            .unzip();
        CoreBuilderOutput::<F, Self::CompType> {
            public_instances: vec![],
            virtual_table: vt,
            logical_results: lr,
        }
    }
    fn raw_synthesize_phase0(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {}
    fn virtual_assign_phase1(&mut self, _builder: &mut RlcCircuitBuilder<F>) {}
    fn raw_synthesize_phase1(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {}
}
