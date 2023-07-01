use std::env::var;

use halo2_base::{
    gates::builder::CircuitBuilderStage,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
};

use crate::{
    batch_query::{
        aggregation::{
            FinalResponseAssemblyCircuit, MultiBlockAggregationCircuit, PoseidonAggregationCircuit,
        },
        response::row_consistency::RowConsistencyCircuit,
    },
    util::{
        circuit::{PinnableCircuit, PreCircuit},
        AggregationConfigPinning, EthConfigPinning, Halo2ConfigPinning,
    },
    AggregationPreCircuit,
};

// MultiBlockCircuit, MultiAccountCircuit, MultiStorageCircuit are all EthPreCircuits, which auto-implement PreCircuit
// Rust does not allow two different traits to both auto-implement PreCircuit (because it cannot then determine conflicting implementations), so the rest we do manually:

impl PreCircuit for RowConsistencyCircuit {
    type Pinning = AggregationConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let break_points = pinning.map(|p| p.break_points());
        RowConsistencyCircuit::create_circuit(self, stage, break_points, params.k())
    }
}

impl PreCircuit for PoseidonAggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        // look for lookup_bits either from pinning, if available, or from env var
        let lookup_bits = pinning
            .as_ref()
            .map(|p| p.params.lookup_bits)
            .or_else(|| var("LOOKUP_BITS").map(|v| v.parse().unwrap()).ok())
            .expect("LOOKUP_BITS is not set");
        let break_points = pinning.map(|p| p.break_points());
        AggregationPreCircuit::create_circuit(self, stage, break_points, lookup_bits, params)
    }
}

impl PreCircuit for MultiBlockAggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        // look for lookup_bits either from pinning, if available, or from env var
        let lookup_bits = pinning
            .as_ref()
            .map(|p| p.params.lookup_bits)
            .or_else(|| var("LOOKUP_BITS").map(|v| v.parse().unwrap()).ok())
            .expect("LOOKUP_BITS is not set");
        let break_points = pinning.map(|p| p.break_points());
        AggregationPreCircuit::create_circuit(self, stage, break_points, lookup_bits, params)
    }
}

impl PreCircuit for FinalResponseAssemblyCircuit {
    type Pinning = EthConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        // look for lookup_bits either from pinning, if available, or from env var
        let lookup_bits = pinning
            .as_ref()
            .map(|p| p.params.lookup_bits.unwrap())
            .or_else(|| var("LOOKUP_BITS").map(|v| v.parse().unwrap()).ok())
            .expect("LOOKUP_BITS is not set");
        let break_points = pinning.map(|p| p.break_points());
        FinalResponseAssemblyCircuit::create_circuit(self, stage, break_points, lookup_bits, params)
    }
}
