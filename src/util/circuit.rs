use super::{AggregationConfigPinning, EthConfigPinning, Halo2ConfigPinning};
use crate::{keccak::FnSynthesize, rlp::builder::RlcThreadBreakPoints, EthCircuitBuilder, Field};
use halo2_base::{
    gates::builder::{CircuitBuilderStage, MultiPhaseThreadBreakPoints},
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{Circuit, ProvingKey, VerifyingKey},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
};
#[cfg(feature = "evm")]
use snark_verifier_sdk::evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    read_pk, CircuitExt, Snark, SHPLONK,
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
    ) -> Vec<u8>;
}

pub trait PreCircuit: Sized {
    type Pinning: Halo2ConfigPinning;

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

    fn create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pinning_path: impl AsRef<Path>,
    ) -> ProvingKey<G1Affine> {
        let circuit = self.create_circuit(CircuitBuilderStage::Keygen, None, params);
        let pk = gen_pk(params, &circuit, None);
        circuit.write_pinning(pinning_path);

        pk
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
            self.create_pk(params, pinning_path)
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
    ) -> Vec<u8> {
        let pinning = C::Pinning::from_path(pinning_path);
        let circuit = self.create_circuit(CircuitBuilderStage::Prover, Some(pinning), params);
        write_calldata_generic(params, pk, circuit, path, deployment_code)
    }
}

/// Aggregates snarks and re-exposes previous public inputs.
///
/// If `has_prev_accumulators` is true, then it assumes all previous snarks are already aggregation circuits and does not re-expose the old accumulators as public inputs.
#[derive(Clone, Debug)]
pub struct PublicAggregationCircuit {
    pub snarks: Vec<Snark>,
    pub has_prev_accumulators: bool,
}

impl PreCircuit for PublicAggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let lookup_bits = var("LOOKUP_BITS").expect("LOOKUP_BITS is not set").parse().unwrap();
        let break_points = pinning.map(|p| p.break_points());
        let circuit = AggregationCircuit::public::<SHPLONK>(
            stage,
            break_points,
            lookup_bits,
            params,
            self.snarks.clone(),
            self.has_prev_accumulators,
        );
        #[cfg(not(feature = "production"))]
        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                circuit.config(
                    params.k(),
                    Some(var("MINIMUM_ROWS").unwrap_or_else(|_| "10".to_string()).parse().unwrap()),
                );
            }
        }
        circuit
    }
}

#[cfg(feature = "evm")]
pub fn write_calldata_generic<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    path: impl AsRef<Path>,
    deployment_code: Option<Vec<u8>>,
) -> Vec<u8> {
    use snark_verifier::loader::evm::encode_calldata;
    use snark_verifier_sdk::evm::evm_verify;
    use std::fs;

    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());
    let calldata = encode_calldata(&instances, &proof);
    fs::write(path, ethers_core::utils::hex::encode(&calldata))
        .expect("write calldata should not fail");
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
