use std::str::FromStr;

use axiom_eth::{
    halo2_base::{gates::RangeChip, utils::biguint_to_fe, AssignedValue, Context},
    utils::hilo::HiLo,
    Field,
};
use groth_verifier::types::*;
use halo2_ecc::{bn254::FpChip, ecc::EccChip, fields::vector::FieldVector};
use num_bigint::BigUint;
use num_traits::One;

use crate::ecdsa::utils::load_fp_from_hilo;

// HiLoPoint<T> represents a point on the G1 curve
// and HiLoPair<T> represents a point on the G2 curve 
pub type HiLoPoint<T> = (HiLo<T>, HiLo<T>);
pub type HiLoPair<T> = (HiLoPoint<T>, HiLoPoint<T>); 

pub fn hilo_point_to_affine<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    g1_chip: &EccChip<F, FpChip<F>>,
    point: HiLoPoint<AssignedValue<F>>,
) -> G1AffineAssigned<F> {
    let fp_chip = g1_chip.field_chip();
    let x = load_fp_from_hilo(ctx, range, fp_chip, point.0);
    let y = load_fp_from_hilo(ctx, range, fp_chip, point.1);
    G1AffineAssigned::new(x, y)
}

pub fn hilo_pair_to_affine<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    g1_chip: &EccChip<F, FpChip<F>>,
    pair: HiLoPair<AssignedValue<F>>
) -> G2AffineAssigned<F> {
    let fp_chip = g1_chip.field_chip();
    let bx0 = load_fp_from_hilo(ctx, range, fp_chip, pair.0 .0);
    let bx1 = load_fp_from_hilo(ctx, range, fp_chip, pair.0 .1);
    let by0 = load_fp_from_hilo(ctx, range, fp_chip, pair.1 .0);
    let by1 = load_fp_from_hilo(ctx, range, fp_chip, pair.1 .1);
    let bx = FieldVector(vec![bx0, bx1]);
    let by = FieldVector(vec![by0, by1]);

    G2AffineAssigned::new(bx, by)
}

pub fn biguint_to_hilo<F: Field>(x: BigUint) -> HiLo<F> {
    let hi = x.clone() >> 128;
    let lo = x % (BigUint::one() << 128);
    HiLo::from_hi_lo([biguint_to_fe(&hi), biguint_to_fe(&lo)])
}

pub fn vec_to_hilo_point<F: Field>(arr: &[String]) -> HiLoPoint<F> {
    (
        biguint_to_hilo(FromStr::from_str(&arr[0]).unwrap()), 
        biguint_to_hilo(FromStr::from_str(&arr[1]).unwrap())
    )
}

pub fn vec_to_hilo_pair<F: Field>(arr: &[[String; 2]]) -> HiLoPair<F> {
    (vec_to_hilo_point(&arr[0]), vec_to_hilo_point(&arr[1]))
}
