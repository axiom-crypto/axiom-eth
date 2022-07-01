use axiom_eth::{
    halo2_base::gates::{flex_gate::threads::parallelize_core, GateChip, GateInstructions},
    rlc::circuit::builder::RlcCircuitBuilder,
    Field,
};
use component_derive::{component, ComponentIO, ComponentParams, Dummy};
use serde::{Deserialize, Serialize};

use crate::scaffold::{BasicComponentScaffold, BasicComponentScaffoldIO};
#[cfg(test)]
mod test;

#[derive(Default, Clone, ComponentParams)]
pub struct ExampleComponentParams {
    pub capacity: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO, Dummy)]
pub struct ExampleComponentInput<T: Copy> {
    pub a: T,
    pub b: T,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct ExampleComponentOutput<T: Copy> {
    pub sum: T,
}

component!(Example);

impl<F: Field> BasicComponentScaffold<F> for ExampleComponent<F> {
    type Params = ExampleComponentParams;

    fn virtual_assign_phase0(
        _: ExampleComponentParams,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<ExampleComponentInput<F>>,
    ) -> BasicComponentScaffoldIO<F, Self> {
        let pool = builder.base.pool(0);
        let gate = GateChip::<F>::default();
        let res = parallelize_core(pool, input, |ctx, subquery| {
            let input = Self::assign_input(ctx, subquery);
            let sum = gate.add(ctx, input.a, input.b);
            (input, ExampleComponentOutput { sum })
        });
        ((), res)
    }
}
