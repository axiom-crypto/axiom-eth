use std::str::FromStr;

use anyhow::Result;
use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeChip, RangeInstructions},
        utils::{biguint_to_fe, fe_to_biguint, modulus, BigPrimeField},
        AssignedValue, Context, QuantumCell,
    },
    halo2curves::secp256k1::{Fp, Secp256k1Affine},
    utils::hilo::HiLo,
    Field,
};
use ethers_core::types::{BigEndianHash, H256};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::identities::One;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

use super::ECDSAComponentNativeInput;
use crate::halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::{EcPoint, EccChip},
    fields::{fp::FpChip, FieldChip},
};

pub fn load_fp_from_hilo<F: Field, Fp: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<F, Fp>,
    hilo: HiLo<AssignedValue<F>>,
) -> ProperCrtUint<F> {
    let [hi_val, lo_val] = hilo.hi_lo().map(|x| fe_to_biguint(x.value()));
    let fp = (hi_val << 128) + lo_val;
    assert!(fp < modulus::<Fp>());
    let fp = biguint_to_fe::<Fp>(&fp);
    let fp = fp_chip.load_private(ctx, fp);
    constrain_limbs_equality(
        ctx,
        range,
        [hilo.hi(), hilo.lo()],
        fp.limbs(),
        fp_chip.limb_bits(),
    );
    fp
}

pub fn load_secp256k1_pubkey<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<F, Fp>,
    pubkey: (HiLo<AssignedValue<F>>, HiLo<AssignedValue<F>>),
) -> EcPoint<F, ProperCrtUint<F>> {
    let [x, y] = [pubkey.0, pubkey.1].map(|c| load_fp_from_hilo(ctx, range, fp_chip, c));
    let pt = EcPoint::new(x, y);
    let chip = EccChip::new(fp_chip);
    //ensures the pubkey is valid since it does not allow (0,0)
    chip.assert_is_on_curve::<Secp256k1Affine>(ctx, &pt);
    pt
}

//should generalize this and move to halo2-lib
pub fn constrain_limbs_equality<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    [hi, lo]: [AssignedValue<F>; 2],
    limbs: &[AssignedValue<F>],
    limb_bits: usize,
) {
    assert!(limb_bits <= 128);
    assert!(limb_bits > 64);
    // limb_bits, 128 - limb_bits
    let (tmp0, limb0) = range.div_mod(ctx, lo, BigUint::one() << limb_bits, 128);
    // limb_bits - (128 - limb_bits) = 2 * limb_bits - 128 > 0
    let rem_bits = limb_bits - (128 - limb_bits);
    let (limb2, tmp1) = range.div_mod(ctx, hi, BigUint::one() << rem_bits, 128);
    let multiplier = biguint_to_fe(&(BigUint::one() << (128 - limb_bits)));
    let limb1 = range
        .gate
        .mul_add(ctx, tmp1, QuantumCell::Constant(multiplier), tmp0);
    for (l0, l1) in limbs.iter().zip_eq([limb0, limb1, limb2]) {
        ctx.constrain_equal(l0, &l1);
    }
}

pub fn biguint_to_hilo<F: Field>(x: BigUint) -> HiLo<F> {
    assert!(x.bits() <= 256);
    let hi = x.clone() >> 128;
    let lo = x % (BigUint::one() << 128);
    HiLo::from_hi_lo([biguint_to_fe(&hi), biguint_to_fe(&lo)])
}

pub fn biguint_to_h256(value: BigUint) -> H256 {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32);
    let mut padded = vec![0u8; 32 - bytes.len()];
    padded.extend_from_slice(&bytes);
    H256::from_slice(&padded)
}

pub fn decode_hilo_to_h256<F: Field>(fe: HiLo<F>) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&fe.lo().to_bytes_le()[..16]);
    bytes[16..].copy_from_slice(&fe.hi().to_bytes_le()[..16]);
    bytes.reverse();
    H256(bytes)
}

pub fn decode_hilo_to_biguint<F: Field>(fe: HiLo<F>) -> BigUint {
    let u256 = decode_hilo_to_h256(fe).into_uint();
    let mut bytes = [0u8; 32];
    u256.to_big_endian(&mut bytes);
    BigUint::from_bytes_be(&bytes)
}

pub fn verify_signature(input: ECDSAComponentNativeInput) -> Result<bool> {
    let pubkey_x = fe_to_biguint(&input.pubkey.0);
    let pubkey_y = fe_to_biguint(&input.pubkey.1);
    let r = fe_to_biguint(&input.r);
    let s = fe_to_biguint(&input.s);

    let secp = Secp256k1::verification_only();

    let pubkey_serialized = format!("04{:x}{:x}", pubkey_x, pubkey_y);
    let pk = PublicKey::from_str(&pubkey_serialized).unwrap();
    let msg = Message::from_digest_slice(input.msg_hash.as_bytes()).unwrap();

    let r_bytes = r.to_bytes_be();
    let s_bytes = s.to_bytes_be();
    let sig_bytes = [&r_bytes[..], &s_bytes[..]].concat();
    let sig = Signature::from_compact(&sig_bytes).unwrap();
    let res = secp.verify_ecdsa(&msg, &sig, &pk);

    Ok(res.is_ok())
}

pub mod testing {
    use axiom_eth::{
        halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus},
        halo2curves::{
            bn256::Fr,
            secp256k1::{Fq, Secp256k1Affine},
            CurveAffine,
        },
    };

    use super::biguint_to_h256;
    use crate::ecdsa::{ECDSAComponentInput, ECDSAComponentNativeInput};

    // Based on https://github.com/axiom-crypto/halo2-lib/blob/8cdbf542a70455042ff7c8cdbedb552ca174a00d/halo2-ecc/src/secp256k1/tests/ecdsa_tests.rs#L12
    pub fn custom_parameters_ecdsa(sk: u64, msg_hash: u64, k: u64) -> ECDSAComponentInput<Fr> {
        let sk_fe = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk);
        let pubkey = Secp256k1Affine::from(Secp256k1Affine::generator() * sk_fe);
        let msg_hash_fe = <Secp256k1Affine as CurveAffine>::ScalarExt::from(msg_hash);
        let msg_hash = fe_to_biguint(&msg_hash_fe);

        let k = <Secp256k1Affine as CurveAffine>::ScalarExt::from(k);
        let k_inv = k.invert().unwrap();

        let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k)
            .coordinates()
            .unwrap();
        let x = r_point.x();
        let x_bigint = fe_to_biguint(x);

        let r = x_bigint % modulus::<Fq>();
        let r_fe = biguint_to_fe::<Fq>(&r);
        let s_fe = k_inv * (msg_hash_fe + (r_fe * sk_fe));

        let ecdsa_native_input = ECDSAComponentNativeInput {
            pubkey: (pubkey.x, pubkey.y),
            r: r_fe,
            s: s_fe,
            msg_hash: biguint_to_h256(msg_hash),
        };
        ecdsa_native_input.into()
    }
}
