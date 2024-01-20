use std::{hash::Hash, marker::PhantomData};

use crate::Field;
use halo2_base::{AssignedValue, Context};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use super::param::{POSEIDON_RATE, POSEIDON_T};
use super::{ComponentType, ComponentTypeId, LogicalInputValue, LogicalResult};

pub type PoseidonHasher<F> =
    halo2_base::poseidon::hasher::PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>;

/// Flatten represents a flatten fixed-len logical input/output/public instances.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Flatten<T> {
    pub fields: Vec<T>,
    pub field_size: &'static [usize],
}

impl<F: Field> From<Flatten<AssignedValue<F>>> for Flatten<F> {
    fn from(f: Flatten<AssignedValue<F>>) -> Self {
        Flatten::<F> {
            fields: f.fields.into_iter().map(|v| *v.value()).collect_vec(),
            field_size: f.field_size,
        }
    }
}

impl<F: Field> Flatten<F> {
    /// Assign Flatten<F>.
    pub fn assign(&self, ctx: &mut Context<F>) -> Flatten<AssignedValue<F>> {
        Flatten::<AssignedValue<F>> {
            fields: ctx.assign_witnesses(self.fields.clone()),
            field_size: self.field_size,
        }
    }
}

impl<T: Copy> From<Flatten<T>> for Vec<T> {
    fn from(val: Flatten<T>) -> Self {
        val.fields
    }
}

/// A logical input/output should be able to convert to a flatten logical input/ouptut.
pub trait FixLenLogical<T: Copy>:
    TryFrom<Flatten<T>, Error = anyhow::Error> + Into<Flatten<T>> + Clone
{
    /// Get field size of this logical.
    fn get_field_size() -> &'static [usize];
    /// Get number of fields of this logical.
    fn get_num_fields() -> usize {
        Self::get_field_size().len()
    }
    /// From raw vec to logical.
    fn try_from_raw(fields: Vec<T>) -> anyhow::Result<Self> {
        // TODO: we should auto generate this as Into<Vec<T>>
        let flatten = Flatten::<T> { fields, field_size: Self::get_field_size() };
        Self::try_from(flatten)
    }
    /// Into raw vec.
    fn into_raw(self) -> Vec<T> {
        // TODO: we should auto generate this as Into<Vec<T>>
        self.into().fields
    }
}

#[derive(Clone, Debug)]
pub struct ComponentPublicInstances<T: Copy> {
    pub output_commit: T,
    pub promise_result_commit: T,
    pub other: Vec<T>,
}

type V<T> = Vec<T>;
impl<T: Copy> From<ComponentPublicInstances<T>> for V<T> {
    fn from(val: ComponentPublicInstances<T>) -> Self {
        [vec![val.output_commit, val.promise_result_commit], val.other].concat()
    }
}

impl<T: Copy> TryFrom<V<T>> for ComponentPublicInstances<T> {
    type Error = anyhow::Error;
    fn try_from(val: V<T>) -> anyhow::Result<Self> {
        if val.len() < 2 {
            return Err(anyhow::anyhow!("invalid length"));
        }
        Ok(Self { output_commit: val[0], promise_result_commit: val[1], other: val[2..].to_vec() })
    }
}

impl<F: Field> From<ComponentPublicInstances<AssignedValue<F>>> for ComponentPublicInstances<F> {
    fn from(f: ComponentPublicInstances<AssignedValue<F>>) -> Self {
        Self {
            output_commit: *f.output_commit.value(),
            promise_result_commit: *f.promise_result_commit.value(),
            other: f.other.into_iter().map(|v| *v.value()).collect_vec(),
        }
    }
}

const FIELD_SIZE_EMPTY: [usize; 0] = [];
/// Type for empty public instance
#[derive(Default, Clone, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LogicalEmpty<T>(PhantomData<T>);

impl<T: Copy> TryFrom<Flatten<T>> for LogicalEmpty<T> {
    type Error = anyhow::Error;

    fn try_from(value: Flatten<T>) -> std::result::Result<Self, Self::Error> {
        if value.field_size != FIELD_SIZE_EMPTY {
            return Err(anyhow::anyhow!("invalid field size"));
        }
        if value.field_size.len() != value.fields.len() {
            return Err(anyhow::anyhow!("field length doesn't match"));
        }
        Ok(LogicalEmpty::<T>(PhantomData::<T>))
    }
}
// This should be done by marco.
impl<T: Copy> From<LogicalEmpty<T>> for Flatten<T> {
    fn from(_val: LogicalEmpty<T>) -> Self {
        Flatten::<T> { fields: vec![], field_size: &FIELD_SIZE_EMPTY }
    }
}
// This should be done by marco.
impl<T: Copy> FixLenLogical<T> for LogicalEmpty<T> {
    fn get_field_size() -> &'static [usize] {
        &FIELD_SIZE_EMPTY
    }
}

impl<F: Field> From<LogicalEmpty<F>> for Vec<LogicalEmpty<F>> {
    fn from(val: LogicalEmpty<F>) -> Self {
        vec![val]
    }
}

impl<F: Field> LogicalInputValue<F> for LogicalEmpty<F> {
    fn get_capacity(&self) -> usize {
        1
    }
}

/// Empty component type.
#[derive(Debug, Clone)]
pub struct EmptyComponentType<F: Field>(PhantomData<F>);
impl<F: Field> ComponentType<F> for EmptyComponentType<F> {
    type InputValue = LogicalEmpty<F>;
    type InputWitness = LogicalEmpty<AssignedValue<F>>;
    type OutputValue = LogicalEmpty<F>;
    type OutputWitness = LogicalEmpty<AssignedValue<F>>;
    type LogicalInput = LogicalEmpty<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-eth:EmptyComponentType".to_string()
    }

    fn logical_result_to_virtual_rows_impl(
        _ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        unreachable!()
    }

    fn logical_input_to_virtual_rows_impl(_li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        unreachable!()
    }
}

// ================== Macro for conversion to/from Flatten ==================
#[macro_export]
macro_rules! impl_flatten_conversion {
    ($struct_name:ident, $bits_per_fe:ident) => {
        impl<T: Copy> TryFrom<$crate::utils::component::types::Flatten<T>> for $struct_name<T> {
            type Error = anyhow::Error;

            fn try_from(
                value: $crate::utils::component::types::Flatten<T>,
            ) -> anyhow::Result<Self> {
                if &value.field_size != &$bits_per_fe {
                    anyhow::bail!("invalid field size");
                }
                if value.field_size.len() != value.fields.len() {
                    anyhow::bail!("field length doesn't match");
                }
                let res = value.fields.try_into()?;
                Ok(res)
            }
        }

        impl<T: Copy> From<$struct_name<T>> for $crate::utils::component::types::Flatten<T> {
            fn from(value: $struct_name<T>) -> Self {
                $crate::utils::component::types::Flatten::<T> {
                    fields: value.flatten().to_vec(),
                    field_size: &$bits_per_fe,
                }
            }
        }

        impl<T: Copy> $crate::utils::component::types::FixLenLogical<T> for $struct_name<T> {
            fn get_field_size() -> &'static [usize] {
                &$bits_per_fe
            }
        }
    };
}

#[macro_export]
macro_rules! impl_logical_input {
    ($struct_name:ident, $capacity:expr) => {
        impl<F: Field<Repr = [u8; 32]>> $crate::utils::component::LogicalInputValue<F>
            for $struct_name<F>
        {
            fn get_capacity(&self) -> usize {
                $capacity
            }
        }
    };
}

#[macro_export]
macro_rules! impl_fix_len_call_witness {
    ($call_name:ident, $fix_len_logical_name:ident, $component_type_name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $call_name<F: Field>(pub $fix_len_logical_name<AssignedValue<F>>);
        impl<F: Field> $crate::utils::component::PromiseCallWitness<F> for $call_name<F> {
            fn get_component_type_id(&self) -> $crate::utils::component::ComponentTypeId {
                $component_type_name::<F>::get_type_id()
            }
            fn get_capacity(&self) -> usize {
                1
            }
            fn to_rlc(
                &self,
                (_, rlc_ctx): (&mut $crate::halo2_base::Context<F>, &mut $crate::halo2_base::Context<F>),
                _range_chip: &$crate::halo2_base::gates::RangeChip<F>,
                rlc_chip: &$crate::rlc::chip::RlcChip<F>,
            ) -> AssignedValue<F> {
                $crate::utils::component::promise_loader::flatten_witness_to_rlc(
                    rlc_ctx,
                    &rlc_chip,
                    &self.0.clone().into(),
                )
            }
            fn to_typeless_logical_input(
                &self,
            ) -> $crate::utils::component::TypelessLogicalInput {
                let f_a: $crate::utils::component::types::Flatten<AssignedValue<F>> =
                    self.0.clone().into();
                let f_v: $crate::utils::component::types::Flatten<F> = f_a.into();
                let l_v: <$component_type_name<F> as ComponentType<F>>::LogicalInput =
                    f_v.try_into().unwrap();
                $crate::utils::component::utils::into_key(l_v)
            }
            fn get_mock_output(&self) -> $crate::utils::component::types::Flatten<F> {
                let output_val: <$component_type_name<F> as $crate::utils::component::ComponentType<F>>::OutputValue =
                    Default::default();
                output_val.into()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
    };
}
