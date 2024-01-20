use std::{any::Any, collections::HashMap, iter};

use anyhow::{anyhow, bail, Result};
use ethers_core::{types::H256, utils::keccak256};
use zkevm_hashes::keccak::{
    component::{
        circuit::shard::KeccakComponentShardCircuit,
        output::{calculate_circuit_outputs_commit, multi_inputs_to_circuit_outputs},
    },
    vanilla::keccak_packed_multi::get_num_keccak_f,
};

use crate::{
    halo2_proofs::plonk::Circuit,
    utils::{
        component::{
            types::ComponentPublicInstances, ComponentCircuit, ComponentPromiseResult,
            ComponentPromiseResultsInMerkle, GroupedPromiseCalls, GroupedPromiseResults,
            LogicalResult, PromiseShardMetadata,
        },
        encode_h256_to_hilo,
    },
    Field,
};

use super::types::{ComponentTypeKeccak, CoreInputKeccak, KeccakLogicalInput, KeccakVirtualOutput};

impl<F: Field> ComponentCircuit<F> for KeccakComponentShardCircuit<F> {
    fn clear_witnesses(&self) {
        self.base_circuit_builder().borrow_mut().clear();
        self.hasher().borrow_mut().clear();
    }
    /// No promise calls
    fn compute_promise_calls(&self) -> Result<GroupedPromiseCalls> {
        Ok(HashMap::new())
    }
    /// The `input` should be of type [CoreInputKeccak].
    /// As a special case, we allow the input to have used capacity less than the configured capacity because the Keccak component circuit knows to automatically pad the input.
    fn feed_input(&self, input: Box<dyn Any>) -> Result<()> {
        let typed_input =
            input.downcast::<CoreInputKeccak>().map_err(|_| anyhow!("invalid input type"))?;
        let params_cap = self.params().capacity();
        let input_cap =
            typed_input.iter().map(|input| get_num_keccak_f(input.len())).sum::<usize>();
        if input_cap > params_cap {
            bail!("Input capacity {input_cap} > configured capacity {params_cap}");
        }
        let mut inputs = *typed_input;
        // resize so the capacity of `inputs` is exactly `params_cap`
        inputs.extend(iter::repeat(vec![]).take(params_cap - input_cap));
        *self.inputs().borrow_mut() = inputs;
        Ok(())
    }
    fn compute_outputs(&self) -> Result<ComponentPromiseResultsInMerkle<F>> {
        let capacity = self.params().capacity();
        // This is the same as the `instances()` implementation
        let vt = multi_inputs_to_circuit_outputs::<F>(&self.inputs().borrow(), capacity);
        let output_commit_val = calculate_circuit_outputs_commit(&vt);
        let pr: Vec<ComponentPromiseResult<F>> = self
            .inputs()
            .borrow()
            .iter()
            .map(|bytes| {
                let output = H256(keccak256(bytes));
                LogicalResult::<F, ComponentTypeKeccak<F>>::new(
                    KeccakLogicalInput::new(bytes.clone()),
                    KeccakVirtualOutput::new(encode_h256_to_hilo(&output)),
                )
                .into()
            })
            .collect();

        Ok(ComponentPromiseResultsInMerkle::<F>::new(
            vec![PromiseShardMetadata { commit: output_commit_val, capacity }],
            vec![(0, pr)],
        ))
    }
    fn get_public_instances(&self) -> ComponentPublicInstances<F> {
        unreachable!("keccak does not follow ComponentPublicInstances")
    }
    /// Promise results are ignored since this component makes no promise calls.
    fn fulfill_promise_results(&self, _: &GroupedPromiseResults<F>) -> anyhow::Result<()> {
        Ok(())
    }
}
