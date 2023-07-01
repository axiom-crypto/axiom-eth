///! A simple scheduler that just wraps a `PreCircuit` with a `PublicAggregationCircuit` circuit, to produce a SNARK that is cheap to verify in EVM
///
use super::{EthScheduler, Scheduler, Task};
use crate::{
    util::{
        circuit::{AnyCircuit, PreCircuit, PublicAggregationCircuit},
        AggregationConfigPinning, Halo2ConfigPinning,
    },
    Network,
};
use ethers_providers::{Http, Provider};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::Snark;
use std::{hash::Hash, path::Path, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Wrapper<T> {
    Initial(T),
    ForEvm(T),
}
// commonly used
pub use Wrapper::ForEvm;

impl<T: Task> Task for Wrapper<T> {
    type CircuitType = Wrapper<T::CircuitType>;

    fn circuit_type(&self) -> Self::CircuitType {
        match self {
            Self::Initial(t) => Wrapper::Initial(t.circuit_type()),
            Self::ForEvm(t) => Wrapper::ForEvm(t.circuit_type()),
        }
    }
    fn type_name(circuit_type: Self::CircuitType) -> String {
        match circuit_type {
            Wrapper::Initial(circuit_type) => T::type_name(circuit_type),
            Wrapper::ForEvm(circuit_type) => format!("{}_evm", T::type_name(circuit_type)),
        }
    }
    fn name(&self) -> String {
        match self {
            Wrapper::Initial(t) => t.name(),
            Wrapper::ForEvm(t) => format!("{}_evm", t.name()),
        }
    }
    fn dependencies(&self) -> Vec<Self> {
        match self {
            Wrapper::Initial(_) => vec![],
            Wrapper::ForEvm(t) => vec![Wrapper::Initial(t.clone())],
        }
    }
}

pub trait SimpleTask: Task {
    type PreCircuit: PreCircuit + Clone;

    fn get_circuit(&self, provider: Arc<Provider<Http>>, network: Network) -> Self::PreCircuit;
}

#[derive(Clone, Debug)]
pub enum WrapperRouter<C: PreCircuit> {
    Initial(C),
    ForEvm(PublicAggregationCircuit),
}

pub type EvmWrapper<T> = EthScheduler<Wrapper<T>>;

impl<T: SimpleTask> Scheduler for EvmWrapper<T> {
    type Task = Wrapper<T>;
    type CircuitRouter = WrapperRouter<T::PreCircuit>;

    fn get_degree(&self, circuit_type: Wrapper<T::CircuitType>) -> u32 {
        if let Some(k) = self.degree.read().unwrap().get(&circuit_type) {
            return *k;
        }
        let path = self.pinning_path(circuit_type);
        let k = match circuit_type {
            Wrapper::Initial(_) => <T::PreCircuit as PreCircuit>::Pinning::from_path(path).degree(),
            Wrapper::ForEvm(_) => AggregationConfigPinning::from_path(path).degree(),
        };
        self.degree.write().unwrap().insert(circuit_type, k);
        k
    }

    fn get_circuit(&self, task: Self::Task, prev_snarks: Vec<Snark>) -> Self::CircuitRouter {
        match task {
            Wrapper::Initial(t) => {
                let circuit = t.get_circuit(Arc::clone(&self.provider), self.network);
                WrapperRouter::Initial(circuit)
            }
            Wrapper::ForEvm(_) => {
                assert_eq!(prev_snarks.len(), 1);
                WrapperRouter::ForEvm(PublicAggregationCircuit::new(prev_snarks, false))
            }
        }
    }
}

impl<C: PreCircuit> AnyCircuit for WrapperRouter<C> {
    fn read_or_create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        read_only: bool,
    ) -> ProvingKey<G1Affine> {
        // does almost the same thing for each circuit type; don't know how to get around this with rust
        match self {
            Self::Initial(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
            Self::ForEvm(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
        }
    }

    fn gen_snark_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: Option<impl AsRef<Path>>,
    ) -> Snark {
        match self {
            Self::Initial(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
            Self::ForEvm(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
        }
    }

    fn gen_evm_verifier_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        yul_path: impl AsRef<Path>,
    ) -> Vec<u8> {
        match self {
            Self::Initial(pre_circuit) => {
                pre_circuit.gen_evm_verifier_shplonk(params, pk, yul_path)
            }
            Self::ForEvm(pre_circuit) => pre_circuit.gen_evm_verifier_shplonk(params, pk, yul_path),
        }
    }

    fn gen_calldata(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
    ) -> String {
        match self {
            Self::Initial(pre_circuit) => {
                pre_circuit.gen_calldata(params, pk, pinning_path, path, deployment_code)
            }
            Self::ForEvm(pre_circuit) => {
                pre_circuit.gen_calldata(params, pk, pinning_path, path, deployment_code)
            }
        }
    }
}
