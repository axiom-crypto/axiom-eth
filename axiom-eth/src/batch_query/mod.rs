use halo2_base::{
    gates::{builder::GateThreadBuilder, GateChip},
    halo2_proofs::halo2curves::CurveAffine,
    utils::{BigPrimeField, ScalarField},
    AssignedValue,
};

#[cfg(feature = "aggregation")]
pub mod aggregation;
pub mod hash;
pub mod response;
#[cfg(feature = "aggregation")]
pub mod scheduler;

#[cfg(feature = "providers")]
#[cfg(test)]
mod tests;

pub trait EccInstructions<F: ScalarField, C: CurveAffine> =
    snark_verifier::loader::halo2::EccInstructions<
        C,
        Context = GateThreadBuilder<F>,
        ScalarChip = GateChip<F>,
        AssignedScalar = AssignedValue<F>,
    >;

/// We unfortunately need Halo2Loader to use Poseidon in circuit, which requires `EccChip: EccInstructions`.
/// Since we don't actually use the EccInstructions, we make a dummy chip wrapping just `GateChip`.
#[derive(Clone, Debug)]
pub(crate) struct DummyEccChip<'a, C: CurveAffine>(&'a GateChip<C::ScalarExt>)
where
    C::ScalarExt: ScalarField;

impl<'a, C: CurveAffine> snark_verifier::loader::halo2::EccInstructions<C> for DummyEccChip<'a, C>
where
    C::ScalarExt: BigPrimeField,
{
    type Context = GateThreadBuilder<C::ScalarExt>;
    type ScalarChip = GateChip<C::ScalarExt>;
    type AssignedScalar = AssignedValue<C::ScalarExt>;
    type AssignedCell = AssignedValue<C::ScalarExt>;
    type AssignedEcPoint = ();

    fn scalar_chip(&self) -> &Self::ScalarChip {
        self.0
    }

    fn assign_constant(&self, _: &mut Self::Context, _: C) -> Self::AssignedEcPoint {
        unreachable!();
    }

    fn assign_point(&self, _: &mut Self::Context, _: C) -> Self::AssignedEcPoint {
        unreachable!();
    }

    fn sum_with_const(
        &self,
        _: &mut Self::Context,
        _: &[impl lazy_static::__Deref<Target = Self::AssignedEcPoint>],
        _: C,
    ) -> Self::AssignedEcPoint {
        unreachable!();
    }

    fn fixed_base_msm(
        &mut self,
        _: &mut Self::Context,
        _: &[(impl lazy_static::__Deref<Target = Self::AssignedScalar>, C)],
    ) -> Self::AssignedEcPoint {
        unreachable!();
    }

    fn variable_base_msm(
        &mut self,
        _: &mut Self::Context,
        _: &[(
            impl lazy_static::__Deref<Target = Self::AssignedScalar>,
            impl lazy_static::__Deref<Target = Self::AssignedEcPoint>,
        )],
    ) -> Self::AssignedEcPoint {
        unreachable!();
    }

    fn assert_equal(
        &self,
        _: &mut Self::Context,
        _: &Self::AssignedEcPoint,
        _: &Self::AssignedEcPoint,
    ) {
        unreachable!();
    }
}
