use axiom_eth::{
    halo2_base::gates::{flex_gate::threads::parallelize_core, GateChip, GateInstructions},
    rlc::circuit::builder::RlcCircuitBuilder,
    Field,
};
use component_derive::{Component, ComponentIO, ComponentParams, Dummy};
use serde::{Deserialize, Serialize};

use crate::{
    scaffold::{BasicComponentScaffold, BasicComponentScaffoldIO},
    utils::flatten::FixLenVec,
};
#[cfg(test)]
mod test;

#[derive(Component)]
pub struct GenericComponent<F: Field, const N: usize, const M: usize>(std::marker::PhantomData<F>);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO, Dummy)]
pub struct GenericComponentInput<T: Copy, const N: usize, const M: usize> {
    pub a: FixLenVec<T, N>,
    pub b: FixLenVec<T, M>,
}

#[derive(Default, Clone, ComponentParams)]
pub struct GenericComponentParams {
    pub capacity: usize,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct GenericComponentOutput<T: Copy, const N: usize, const M: usize> {
    pub sum: T,
}

impl<F: Field, const N: usize, const M: usize> BasicComponentScaffold<F>
    for GenericComponent<F, N, M>
{
    type Params = GenericComponentParams;
    fn virtual_assign_phase0(
        _: GenericComponentParams,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<GenericComponentInput<F, N, M>>,
    ) -> BasicComponentScaffoldIO<F, Self> {
        let pool = builder.base.pool(0);
        let gate = GateChip::<F>::default();
        let res = parallelize_core(pool, input, |ctx, subquery| {
            let input = Self::assign_input(ctx, subquery);
            let a = input.clone().a.into_inner();
            let b = input.clone().b.into_inner();
            let sum_a = gate.sum(ctx, a);
            let sum_b = gate.sum(ctx, b);
            let sum = gate.add(ctx, sum_a, sum_b);
            (input, GenericComponentOutput { sum })
        });
        ((), res)
    }
}
