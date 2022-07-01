use std::marker::PhantomData;

use axiom_eth::{
    halo2_base::{
        gates::circuit::{BaseCircuitParams, BaseConfig},
        utils::ScalarField,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{keygen_vk_custom, Circuit, ConstraintSystem, Error, VerifyingKey},
        poly::kzg::commitment::ParamsKZG,
    },
    rlc::circuit::{RlcCircuitParams, RlcConfig},
};

use super::metadata::AxiomV2CircuitMetadata;

/// We only care about evaluations (custom gates) but not the domain, so we use a very small dummy
pub(super) const DUMMY_K: u32 = 7;

/// Dummy circuit just to get the correct constraint system corresponding
/// to the circuit metadata.
#[derive(Clone)]
struct DummyAxiomCircuit<F> {
    metadata: AxiomV2CircuitMetadata,
    _marker: PhantomData<F>,
}

/// An enum to choose between a circuit with only basic columns and gates or a circuit that in addition has RLC columns and gates.
/// The distinction is that even when `RlcConfig` has `num_rlc_columns` set to 0, it will always have the challenge `gamma`.
/// Therefore we use this enum to more clearly distinguish between the two cases.
#[derive(Clone, Debug)]
pub enum MaybeRlcConfig<F: ScalarField> {
    Rlc(RlcConfig<F>),
    Base(BaseConfig<F>),
}

// For internal use only
impl<F: ScalarField> Circuit<F> for DummyAxiomCircuit<F> {
    type Config = MaybeRlcConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = AxiomV2CircuitMetadata;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn params(&self) -> Self::Params {
        self.metadata.clone()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        metadata: Self::Params,
    ) -> Self::Config {
        let num_phase = metadata.num_challenge.len();
        assert!(num_phase == 1 || num_phase == 2, "only support 2 phases for now");
        let base_circuit_params = BaseCircuitParams {
            k: DUMMY_K as usize,
            num_advice_per_phase: metadata
                .num_advice_per_phase
                .iter()
                .map(|x| *x as usize)
                .collect(),
            num_fixed: metadata.num_fixed as usize,
            num_lookup_advice_per_phase: metadata
                .num_lookup_advice_per_phase
                .iter()
                .map(|x| *x as usize)
                .collect(),
            lookup_bits: Some(DUMMY_K as usize - 1), // doesn't matter because we replace fixed commitments later
            num_instance_columns: metadata.num_instance.len(),
        };
        if num_phase == 1 {
            assert!(metadata.num_rlc_columns == 0, "rlc columns only allowed in phase1");
            // Note that BaseConfig ignores lookup bits if there are no lookup advice columns
            MaybeRlcConfig::Base(BaseConfig::configure(meta, base_circuit_params))
        } else {
            let rlc_circuit_params = RlcCircuitParams {
                base: base_circuit_params,
                num_rlc_columns: metadata.num_rlc_columns as usize,
            };
            MaybeRlcConfig::Rlc(RlcConfig::configure(meta, rlc_circuit_params))
        }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("must use configure_with_params")
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(|| "dummy", |_region| Ok(()))
    }
}

/// For internal use only, num_instance will be replaced later
pub(crate) fn dummy_vk_from_metadata(
    params: &ParamsKZG<Bn256>,
    metadata: AxiomV2CircuitMetadata,
) -> anyhow::Result<VerifyingKey<G1Affine>> {
    let dummy_circuit = DummyAxiomCircuit::<Fr> { metadata, _marker: PhantomData };
    let vk = keygen_vk_custom(params, &dummy_circuit, false)?;
    Ok(vk)
}
