use axiom_eth::{
    halo2_base::{
        gates::{flex_gate::threads::parallelize_core, RangeChip},
        AssignedValue, Context,
    },
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::{encode_h256_to_hilo, hilo::HiLo},
    zkevm_hashes::util::eth_types::H256,
    Field,
};
use component_derive::{component, ComponentIO, ComponentParams, Dummy};
use halo2_ecc::halo2_base::utils::{biguint_to_fe, fe_to_biguint, BigPrimeField};
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};

use self::utils::{
    biguint_to_hilo, decode_hilo_to_biguint, decode_hilo_to_h256, load_fp_from_hilo,
    load_secp256k1_pubkey,
};
use crate::{
    halo2_ecc::{
        ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
        fields::fp::FpChip,
        secp256k1::FqChip,
    },
    scaffold::{BasicComponentScaffold, BasicComponentScaffoldIO},
};
#[cfg(test)]
mod test;
pub mod utils;

/// Config params for the ECDSA component.
#[derive(Default, Clone, Serialize, Deserialize, ComponentParams)]
pub struct ECDSAComponentParams {
    pub capacity: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(from = "ECDSAComponentSerdeInput")]
#[serde(into = "ECDSAComponentSerdeInput")]
pub struct ECDSAComponentNativeInput {
    /// The public key is a Secp256k1Affine point represented as (x, y)
    pub pubkey: (Fp, Fp),
    pub r: Fq,
    pub s: Fq,
    pub msg_hash: H256,
}

impl<F: Field> From<ECDSAComponentNativeInput> for ECDSAComponentInput<F> {
    fn from(input: ECDSAComponentNativeInput) -> Self {
        ECDSAComponentInput {
            pubkey: (
                biguint_to_hilo(fe_to_biguint(&input.pubkey.0)),
                biguint_to_hilo(fe_to_biguint(&input.pubkey.1)),
            ),
            r: biguint_to_hilo(fe_to_biguint(&input.r)),
            s: biguint_to_hilo(fe_to_biguint(&input.s)),
            msg_hash: encode_h256_to_hilo(&input.msg_hash),
        }
    }
}

impl<F: Field> From<ECDSAComponentInput<F>> for ECDSAComponentNativeInput {
    fn from(input: ECDSAComponentInput<F>) -> Self {
        ECDSAComponentNativeInput {
            pubkey: (
                biguint_to_fe::<Fp>(&decode_hilo_to_biguint(input.pubkey.0)),
                biguint_to_fe::<Fp>(&decode_hilo_to_biguint(input.pubkey.1)),
            ),
            r: biguint_to_fe::<Fq>(&decode_hilo_to_biguint(input.r)),
            s: biguint_to_fe::<Fq>(&decode_hilo_to_biguint(input.s)),
            msg_hash: decode_hilo_to_h256(input.msg_hash),
        }
    }
}

/// A single input of the ECDSA component.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO, Dummy)]
pub struct ECDSAComponentInput<T: Copy> {
    pub pubkey: (HiLo<T>, HiLo<T>),
    pub r: HiLo<T>,
    pub s: HiLo<T>,
    pub msg_hash: HiLo<T>,
}

/// A single output of the ECDSA component.
/// The `success` field is 1 if the signature is valid, and 0 otherwise.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ComponentIO)]
pub struct ECDSAComponentOutput<T: Copy> {
    pub success: HiLo<T>,
}

impl<F: Field> From<ECDSAComponentOutput<F>> for H256 {
    fn from(value: ECDSAComponentOutput<F>) -> Self {
        decode_hilo_to_h256(value.success)
    }
}

impl<F: Field> From<H256> for ECDSAComponentOutput<F> {
    fn from(value: H256) -> Self {
        ECDSAComponentOutput {
            success: encode_h256_to_hilo(&value),
        }
    }
}

component!(ECDSA);

impl<F: Field> BasicComponentScaffold<F> for ECDSAComponent<F> {
    type Params = ECDSAComponentParams;

    fn virtual_assign_phase0(
        params: ECDSAComponentParams,
        builder: &mut RlcCircuitBuilder<F>,
        input: Vec<ECDSAComponentInput<F>>,
    ) -> BasicComponentScaffoldIO<F, Self> {
        let range = builder.base.range_chip();
        let pool = builder.base.pool(0);
        let res = parallelize_core(pool, input, |ctx, subquery| {
            let input = Self::assign_input(ctx, subquery);
            handle_single_ecdsa_verify(ctx, &range, input, params.limb_bits, params.num_limbs)
        });
        ((), res)
    }
}

/// Helper function for handling a single ECDSA verification.
pub fn handle_single_ecdsa_verify<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: ECDSAComponentInput<AssignedValue<F>>,
    limb_bits: usize,
    num_limbs: usize,
) -> (
    ECDSAComponentInput<AssignedValue<F>>,
    ECDSAComponentOutput<AssignedValue<F>>,
) {
    let fp_chip = FpChip::<F, Fp>::new(range, limb_bits, num_limbs);
    let fq_chip = FqChip::new(range, limb_bits, num_limbs);
    let [r, s, msg_hash] =
        [input.r, input.s, input.msg_hash].map(|x| load_fp_from_hilo(ctx, range, &fq_chip, x));
    let ecc_chip = EccChip::new(&fp_chip);
    let pubkey = load_secp256k1_pubkey(ctx, range, &fp_chip, input.pubkey);
    let success = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pubkey, r, s, msg_hash, 4, 4,
    );
    let zero = ctx.load_constant(F::ZERO);
    (
        input,
        ECDSAComponentOutput {
            success: HiLo::from_hi_lo([zero, success]),
        },
    )
}

/// Field elements are serialized as big-endian hex strings with 0x prefix.
#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ECDSAComponentSerdeInput {
    /// The public key is a Secp256k1Affine point represented as (x, y)
    pub pubkey: (String, String),
    pub r: String,
    pub s: String,
    pub msg_hash: H256,
}

impl From<ECDSAComponentNativeInput> for ECDSAComponentSerdeInput {
    fn from(input: ECDSAComponentNativeInput) -> Self {
        ECDSAComponentSerdeInput {
            pubkey: (
                format!("{:?}", input.pubkey.0),
                format!("{:?}", input.pubkey.1),
            ),
            r: format!("{:?}", input.r),
            s: format!("{:?}", input.s),
            msg_hash: input.msg_hash,
        }
    }
}

impl From<ECDSAComponentSerdeInput> for ECDSAComponentNativeInput {
    fn from(input: ECDSAComponentSerdeInput) -> Self {
        ECDSAComponentNativeInput {
            pubkey: (string_to_fe(&input.pubkey.0), string_to_fe(&input.pubkey.1)),
            r: string_to_fe(&input.r),
            s: string_to_fe(&input.s),
            msg_hash: input.msg_hash,
        }
    }
}

fn string_to_fe<F: BigPrimeField>(s: &str) -> F {
    assert!(s.starts_with("0x"), "Hex string must start with 0x");
    let num = BigUint::from_str_radix(&s[2..], 16).unwrap();
    biguint_to_fe(&num)
}
