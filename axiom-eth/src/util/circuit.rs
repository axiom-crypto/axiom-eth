use super::{AggregationConfigPinning, EthConfigPinning, Halo2ConfigPinning};
use crate::{
    keccak::FnSynthesize,
    rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder},
    EthCircuitBuilder, EthPreCircuit, Field,
};
use halo2_base::{
    gates::builder::{
        CircuitBuilderStage, MultiPhaseThreadBreakPoints, RangeWithInstanceCircuitBuilder,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{Circuit, ProvingKey, VerifyingKey},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::ScalarField,
};
#[cfg(feature = "evm")]
use snark_verifier_sdk::evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    read_pk, CircuitExt, Snark, LIMBS, SHPLONK,
};
use std::{env::var, fs::File, path::Path};

pub trait PinnableCircuit<F: ff::Field>: CircuitExt<F> {
    type Pinning: Halo2ConfigPinning;

    fn break_points(&self) -> <Self::Pinning as Halo2ConfigPinning>::BreakPoints;

    fn write_pinning(&self, path: impl AsRef<Path>) {
        let break_points = self.break_points();
        let pinning: Self::Pinning = Halo2ConfigPinning::from_var(break_points);
        serde_json::to_writer_pretty(File::create(path).unwrap(), &pinning).unwrap();
    }
}

impl<F: Field, FnPhase1: FnSynthesize<F>> PinnableCircuit<F> for EthCircuitBuilder<F, FnPhase1> {
    type Pinning = EthConfigPinning;

    fn break_points(&self) -> RlcThreadBreakPoints {
        self.circuit.break_points.borrow().clone()
    }
}

impl PinnableCircuit<Fr> for AggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        AggregationCircuit::break_points(self)
    }
}

impl<F: ScalarField> PinnableCircuit<F> for RangeWithInstanceCircuitBuilder<F> {
    type Pinning = AggregationConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        RangeWithInstanceCircuitBuilder::break_points(self)
    }
}

/// Common functionality we want to get out of any kind of circuit.
/// In particular used for types that hold multiple `PreCircuit`s.
pub trait AnyCircuit: Sized {
    fn read_or_create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        read_only: bool,
    ) -> ProvingKey<G1Affine>;

    fn gen_snark_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: Option<impl AsRef<Path>>,
    ) -> Snark;

    #[cfg(feature = "evm")]
    fn gen_evm_verifier_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        yul_path: impl AsRef<Path>,
    ) -> Vec<u8>;

    #[cfg(feature = "evm")]
    fn gen_calldata(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
    ) -> String;
}

pub trait PreCircuit: Sized {
    type Pinning: Halo2ConfigPinning;

    /// Creates a [`PinnableCircuit`], auto-configuring the circuit if not in production or prover mode.
    ///
    /// `params` should be the universal trusted setup for the present aggregation circuit.
    /// We assume the trusted setup for the previous SNARKs is compatible with `params` in the sense that
    /// the generator point and toxic waste `tau` are the same.
    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr>;

    /// Reads the proving key for the pre-circuit.
    /// If `read_only` is true, then it is assumed that the proving key exists and can be read from `path` (otherwise the program will panic).
    fn read_pk(self, params: &ParamsKZG<Bn256>, path: impl AsRef<Path>) -> ProvingKey<G1Affine> {
        let circuit = self.create_circuit(CircuitBuilderStage::Keygen, None, params);
        custom_read_pk(path, &circuit)
    }

    /// Creates the proving key for the pre-circuit if file at `pk_path` is not found.
    /// If a new proving key is created, the new pinning data is written to `pinning_path`.
    fn create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
    ) -> ProvingKey<G1Affine> {
        let circuit = self.create_circuit(CircuitBuilderStage::Keygen, None, params);
        let pk_exists = pk_path.as_ref().exists();
        let pk = gen_pk(params, &circuit, Some(pk_path.as_ref()));
        if !pk_exists {
            // should only write pinning data if we created a new pkey
            circuit.write_pinning(pinning_path);
        }
        pk
    }

    fn get_degree(pinning_path: impl AsRef<Path>) -> u32 {
        let pinning = Self::Pinning::from_path(pinning_path);
        pinning.degree()
    }
}

impl<C: EthPreCircuit> PreCircuit for C {
    type Pinning = EthConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        _: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let builder = RlcThreadBuilder::from_stage(stage);
        let break_points = pinning.map(|p| p.break_points());
        EthPreCircuit::create_circuit(self, builder, break_points)
    }
}

impl<C: PreCircuit> AnyCircuit for C {
    fn read_or_create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        read_only: bool,
    ) -> ProvingKey<G1Affine> {
        if read_only {
            self.read_pk(params, pk_path)
        } else {
            self.create_pk(params, pk_path, pinning_path)
        }
    }

    fn gen_snark_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: Option<impl AsRef<Path>>,
    ) -> Snark {
        let pinning = C::Pinning::from_path(pinning_path);
        let circuit = self.create_circuit(CircuitBuilderStage::Prover, Some(pinning), params);
        gen_snark_shplonk(params, pk, circuit, path)
    }

    #[cfg(feature = "evm")]
    fn gen_evm_verifier_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        yul_path: impl AsRef<Path>,
    ) -> Vec<u8> {
        let circuit = self.create_circuit(CircuitBuilderStage::Keygen, None, params);
        custom_gen_evm_verifier_shplonk(params, pk.get_vk(), &circuit, Some(yul_path))
    }

    #[cfg(feature = "evm")]
    fn gen_calldata(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
    ) -> String {
        let pinning = C::Pinning::from_path(pinning_path);
        let circuit = self.create_circuit(CircuitBuilderStage::Prover, Some(pinning), params);
        write_calldata_generic(params, pk, circuit, path, deployment_code)
    }
}

/// Aggregates snarks and re-exposes previous public inputs.
///
#[derive(Clone, Debug)]
pub struct PublicAggregationCircuit {
    /// The previous snarks to aggregate.
    /// `snarks` consists of a vector of `(snark, has_prev_accumulator)` pairs, where `snark` is [Snark] and `has_prev_accumulator` is boolean. If `has_prev_accumulator` is true, then it assumes `snark` is already an
    /// aggregation circuit and does not re-expose the old accumulator from `snark` as public inputs.
    pub snarks: Vec<(Snark, bool)>,
}

impl PublicAggregationCircuit {
    pub fn new(snarks: Vec<(Snark, bool)>) -> Self {
        Self { snarks }
    }

    // excludes old accumulators from prev instance
    pub fn private(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> AggregationCircuit {
        let (snarks, has_prev_acc): (Vec<_>, Vec<_>) = self.snarks.into_iter().unzip();
        let mut private =
            AggregationCircuit::new::<SHPLONK>(stage, break_points, lookup_bits, params, snarks);
        for (prev_instance, has_acc) in private.previous_instances.iter_mut().zip(has_prev_acc) {
            let start = (has_acc as usize) * 4 * LIMBS;
            *prev_instance = prev_instance.split_off(start);
        }
        private
    }
}

impl PreCircuit for PublicAggregationCircuit {
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
        let mut private = self.private(stage, break_points, lookup_bits, params);
        for prev in &private.previous_instances {
            private.inner.assigned_instances.extend_from_slice(prev);
        }

        #[cfg(not(feature = "production"))]
        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                private.config(
                    params.k(),
                    Some(var("MINIMUM_ROWS").unwrap_or_else(|_| "10".to_string()).parse().unwrap()),
                );
            }
        }
        private
    }
}

#[cfg(feature = "evm")]
pub fn write_calldata_generic<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    path: impl AsRef<Path>,
    deployment_code: Option<Vec<u8>>,
) -> String {
    use ethers_core::utils::hex::encode;
    use snark_verifier::loader::evm::encode_calldata;
    use snark_verifier_sdk::evm::evm_verify;
    use std::fs;

    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());
    // calldata as hex string
    let calldata = encode(encode_calldata(&instances, &proof));
    fs::write(path, &calldata).expect("write calldata should not fail");
    if let Some(deployment_code) = deployment_code {
        evm_verify(deployment_code, instances, proof);
    }
    calldata
}

// need to trick rust into inferring type of the circuit because `C` involves closures
// this is not ideal...
fn custom_read_pk<C, P>(fname: P, _: &C) -> ProvingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    read_pk::<C>(fname.as_ref()).expect("proving key should exist")
}

// also for type inference
#[cfg(feature = "evm")]
pub fn custom_gen_evm_verifier_shplonk<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    circuit: &C,
    path: Option<impl AsRef<Path>>,
) -> Vec<u8> {
    gen_evm_verifier_shplonk::<C>(
        params,
        vk,
        circuit.num_instance(),
        path.as_ref().map(|p| p.as_ref()),
    )
}
