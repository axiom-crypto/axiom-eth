use axiom_eth::{
    halo2_base::{
        gates::{flex_gate::threads::parallelize_core, RangeChip},
        AssignedValue, Context,
    },
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::build_utils::dummy::DummyFrom,
    Field,
};
use component_derive::{Component, ComponentIO, ComponentParams};
use groth_verifier::{types::*, *};
use halo2_ecc::{
    bn254::{pairing::PairingChip, Fp2Chip, FpChip},
    ecc::EccChip,
};
use serde::{Deserialize, Serialize};

use self::utils::*;
use crate::{
    scaffold::{BasicComponentScaffold, BasicComponentScaffoldIO},
    utils::flatten::{FixLenVec, VecKey},
};

#[cfg(test)]
pub mod test;
pub mod utils;

#[derive(Default, Clone, ComponentParams)]
pub struct Groth16VerifierComponentParams {
    pub capacity: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct Groth16VerifierComponentVerificationKey<T: Copy, const MAX_PUBLIC_INPUTS: usize> {
    pub alpha_g1: HiLoPoint<T>,
    pub beta_g2: HiLoPair<T>,
    pub gamma_g2: HiLoPair<T>,
    pub delta_g2: HiLoPair<T>,
    pub gamma_abc_g1: VecKey<HiLoPoint<T>, MAX_PUBLIC_INPUTS>, // will create vector of size MAX_PUBLIC_INPUTS + 1
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct Groth16VerifierComponentProof<T: Copy> {
    pub a: HiLoPoint<T>,
    pub b: HiLoPair<T>,
    pub c: HiLoPoint<T>,
}

impl<F: Field> Groth16VerifierComponentProof<AssignedValue<F>> {
    pub fn convert_to_affine(
        &self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        g1_chip: &EccChip<F, FpChip<F>>,
    ) -> ProofAssigned<F> {
        let a = hilo_point_to_affine(ctx, range, g1_chip, self.a);
        let b = hilo_pair_to_affine(ctx, range, g1_chip, self.b);
        let c = hilo_point_to_affine(ctx, range, g1_chip, self.c);

        ProofAssigned { a, b, c }
    }
}

impl<F: Field, const MAX_PUBLIC_INPUTS: usize>
    Groth16VerifierComponentVerificationKey<AssignedValue<F>, MAX_PUBLIC_INPUTS>
{
    pub fn convert_to_affine(
        &self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        g1_chip: &EccChip<F, FpChip<F>>,
        num_public_inputs: AssignedValue<F>,
        max_len: usize,
    ) -> VerifyingKeyAssigned<F> {
        let alpha_g1 = hilo_point_to_affine(ctx, range, g1_chip, self.alpha_g1);
        let beta_g2 = hilo_pair_to_affine(ctx, range, g1_chip, self.beta_g2);
        let gamma_g2 = hilo_pair_to_affine(ctx, range, g1_chip, self.gamma_g2);
        let delta_g2 = hilo_pair_to_affine(ctx, range, g1_chip, self.delta_g2);
        let mut gamma_abc_g1 = self
            .gamma_abc_g1
            .iter()
            .map(|pt| hilo_point_to_affine(ctx, range, g1_chip, *pt))
            .collect::<Vec<_>>();
        gamma_abc_g1.resize(max_len, gamma_abc_g1[0].clone());
        VerifyingKeyAssigned {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
            abc_len: num_public_inputs,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct Groth16VerifierComponentInput<T: Copy, const MAX_PUBLIC_INPUTS: usize> {
    pub vk: Groth16VerifierComponentVerificationKey<T, MAX_PUBLIC_INPUTS>,
    pub proof: Groth16VerifierComponentProof<T>,
    pub public_inputs: FixLenVec<T, MAX_PUBLIC_INPUTS>, // MAX_PUBLIC_INPUTS
    pub num_public_inputs: T,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct Groth16VerifierComponentOutput<T: Copy, const MAX_PUBLIC_INPUTS: usize> {
    pub success: T,
}

#[derive(Component)]
pub struct Groth16VerifierComponent<F: Field, const MAX_PUBLIC_INPUTS: usize>(
    std::marker::PhantomData<F>,
);

impl<F: Field, const MAX_PUBLIC_INPUTS: usize> BasicComponentScaffold<F>
    for Groth16VerifierComponent<F, MAX_PUBLIC_INPUTS>
{
    type Params = Groth16VerifierComponentParams;
    fn virtual_assign_phase0(
        params: Groth16VerifierComponentParams,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<Groth16VerifierComponentInput<F, MAX_PUBLIC_INPUTS>>,
    ) -> BasicComponentScaffoldIO<F, Self> {
        let range = builder.base.range_chip();
        let pool = builder.base.pool(0);
        let res = parallelize_core(pool, input, |ctx, subquery| {
            let input = Self::assign_input(ctx, subquery);
            handle_single_groth16verify(ctx, &range, input, params.limb_bits, params.num_limbs)
        });
        ((), res)
    }
}

impl<F: Field, const MAX_PUBLIC_INPUTS: usize> DummyFrom<Groth16VerifierComponentParams>
    for Groth16VerifierComponentInput<F, MAX_PUBLIC_INPUTS>
{
    fn dummy_from(_core_params: Groth16VerifierComponentParams) -> Self {
        Groth16VerifierComponentInput {
            vk: Groth16VerifierComponentVerificationKey::default(),
            proof: Groth16VerifierComponentProof::default(),
            public_inputs: FixLenVec::new(vec![F::ZERO; MAX_PUBLIC_INPUTS]).unwrap(),
            num_public_inputs: F::from(MAX_PUBLIC_INPUTS as u64),
        }
    }
}

//todo: actually implement dummy from for the component params
impl<F: Field, const MAX_PUBLIC_INPUTS: usize> DummyFrom<Groth16VerifierComponentParams>
    for Vec<Groth16VerifierComponentInput<F, MAX_PUBLIC_INPUTS>>
{
    fn dummy_from(_core_params: Groth16VerifierComponentParams) -> Self {
        todo!()
    }
}

pub fn handle_single_groth16verify<F: Field, const MAX_PUBLIC_INPUTS: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: Groth16VerifierComponentInput<AssignedValue<F>, MAX_PUBLIC_INPUTS>,
    limb_bits: usize,
    num_limbs: usize,
) -> (
    Groth16VerifierComponentInput<AssignedValue<F>, MAX_PUBLIC_INPUTS>,
    Groth16VerifierComponentOutput<AssignedValue<F>, MAX_PUBLIC_INPUTS>,
) {
    let fp_chip = FpChip::<F>::new(range, limb_bits, num_limbs);
    let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
    let g1_chip = EccChip::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);
    let pairing_chip = PairingChip::new(&fp_chip);

    let p = input.proof.convert_to_affine(ctx, range, &g1_chip);
    let vk = input.vk.convert_to_affine(
        ctx,
        range,
        &g1_chip,
        input.num_public_inputs,
        MAX_PUBLIC_INPUTS + 1,
    );

    let public_inputs = input.public_inputs.clone();

    let success = verify_proof(
        ctx,
        range,
        &pairing_chip,
        &g1_chip,
        &g2_chip,
        &vk,
        &p,
        &public_inputs.vec,
    );

    (input, Groth16VerifierComponentOutput { success })
}
