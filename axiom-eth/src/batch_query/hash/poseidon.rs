use std::rc::Rc;

use halo2_base::{
    halo2_proofs::halo2curves::{bn256::Fr, CurveAffine, FieldExt},
    AssignedValue,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use snark_verifier::{
    loader::{
        halo2::{Halo2Loader, Scalar},
        LoadedScalar, ScalarLoader,
    },
    util::hash::Poseidon,
};
use snark_verifier_sdk::{halo2::POSEIDON_SPEC, NativeLoader};

use crate::batch_query::EccInstructions;

use self::shim::SelectLoader;

lazy_static! {
    pub static ref POSEIDON_EMPTY_ROOTS: Vec<Fr> = generate_poseidon_empty_roots(32);
}

/// An array of field elements that can be concatenated and hashed by Poseidon hasher.
/// Assumed to be of known fixed length.
#[derive(Clone, Debug)]
pub struct PoseidonWords<L>(pub(crate) Vec<L>);

impl<L> From<L> for PoseidonWords<L> {
    fn from(x: L) -> Self {
        Self(vec![x])
    }
}

impl<L> From<Option<L>> for PoseidonWords<L> {
    fn from(x: Option<L>) -> Self {
        Self(x.into_iter().collect())
    }
}

impl<L> AsRef<[L]> for PoseidonWords<L> {
    fn as_ref(&self) -> &[L] {
        &self.0
    }
}

impl<L: Clone> PoseidonWords<L> {
    pub fn concat(&self, other: &Self) -> Self {
        Self([&self.0[..], &other.0[..]].concat())
    }
}

impl<C: CurveAffine, EccChip: EccInstructions<C::Scalar, C>> PoseidonWords<Scalar<C, EccChip>> {
    pub fn from_witness(
        loader: &Rc<Halo2Loader<C, EccChip>>,
        witness: impl AsRef<[C::Scalar]>,
    ) -> Self {
        Self(witness.as_ref().iter().map(|x| loader.assign_scalar(*x)).collect())
    }
}

/// A struct for an array of field elements that is either:
/// * of known fixed length `N`, or
/// * empty
/// If `is_some` is `None`, then the array is assumed to be of known fixed length `N`, in which case this is the same as `PoseidonWords`.
/// Otherwise `is_some` is a boolean value that indicates whether the array is empty or not.
/// In the case `is_some = Some(0)`, then `words` should still be a dummy array of the known fixed length `N`.
#[derive(Clone, Debug)]
pub struct OptPoseidonWords<L> {
    pub(crate) words: Vec<L>,
    pub(crate) is_some: Option<L>,
}

impl<L> From<L> for OptPoseidonWords<L> {
    fn from(x: L) -> Self {
        Self { words: vec![x], is_some: None }
    }
}

impl<L> From<PoseidonWords<L>> for OptPoseidonWords<L> {
    fn from(x: PoseidonWords<L>) -> Self {
        Self { words: x.0, is_some: None }
    }
}

/// Computes the Poseidon hash of an array of field elements by adding them sequentially to buffer
/// and then squeezing once.
pub fn poseidon_packed<F: FieldExt, L: LoadedScalar<F>, const T: usize, const RATE: usize>(
    hasher: &mut Poseidon<F, L, T, RATE>,
    words: PoseidonWords<L>,
) -> L {
    hasher.clear(); // reset state
    hasher.update(&words.0);
    hasher.squeeze()
}

pub(crate) fn poseidon_onion<F: FieldExt, L: LoadedScalar<F>, const T: usize, const RATE: usize>(
    hasher: &mut Poseidon<F, L, T, RATE>,
    leaves: impl IntoIterator<Item = PoseidonWords<L>>,
) -> L {
    let mut leaves = leaves.into_iter();
    let mut onion = leaves.next().expect("leaves must be non-empty");
    for leaf in leaves {
        onion = poseidon_packed(hasher, onion.concat(&leaf)).into();
    }
    onion.0[0].clone()
}

/// Computes the Poseidon Merkle root of a tree with leaves `leaves`
/// where each leaf is a either (1) a fixed length array of words or (2) empty array.
///
/// The hash of two leaves is computed by concatenating the leaves and hashing the concatenation.
/// If there is a single leaf, we hash the leaf if it has length > 1, otherwise we return the leaf itself.
/// We assume the input is never a single leaf of the empty array.
///
/// Returns the Merkle tree root as a single field element.
///
/// Assumes `leaves` is non-empty. If `leaves` has length 1, then the leaf must be a fixed length array; in this case
/// we hash the leaf if it has length > 1, otherwise we return the leaf itself.
/// Does not assume `leaves.len()` is a power of two. If it is not, the tree is padded with leaves that are empty arrays.
///
/// As an optimization, we pass in pre-computed empty Poseidon Merkle roots, where `poseidon_empty_roots[i]`
/// is the root of a tree of height `i + 1` with all empty leaves (so `poseidon_empty_roots[0] = poseidon([])`).
/// This function will panic if `poseidon_empty_roots.len()` < log2_floor( 2<sup>log2_ceil(leaves.len())</sup> - leaves.len()).
// We could optimize even more by keeping a cache of the assigned constants for `poseidon_empty_roots`,
// but we'll avoid increasing code.
pub(crate) fn poseidon_tree_root<F, L, const T: usize, const RATE: usize, W>(
    hasher: &mut Poseidon<F, L, T, RATE>,
    leaves: Vec<W>,
    poseidon_empty_roots: &[F],
) -> L
where
    F: FieldExt,
    L: LoadedScalar<F>,
    L::Loader: SelectLoader<F>,
    W: Into<OptPoseidonWords<L>>,
{
    let mut len = leaves.len();
    assert!(len > 0, "leaves must be non-empty");

    if len == 1 {
        let leaf: OptPoseidonWords<_> = leaves.into_iter().next().unwrap().into();
        assert!(leaf.is_some.is_none(), "single leaf must be fixed length array");
        let words = leaf.words;
        assert!(!words.is_empty());
        if words.len() == 1 {
            return words.into_iter().next().unwrap();
        } else {
            return poseidon_packed(hasher, PoseidonWords(words));
        }
    }

    let mut hashes = Vec::with_capacity((len + 1) / 2);
    for mut pair in leaves.into_iter().chunks(2).into_iter() {
        let left: OptPoseidonWords<L> = pair.next().unwrap().into();
        let right: OptPoseidonWords<L> =
            pair.next().map(Into::into).unwrap_or_else(|| PoseidonWords(vec![]).into());
        hashes.push(poseidon_opt_pair(hasher, left, right));
    }

    len = (len + 1) / 2;
    debug_assert_eq!(len, hashes.len());
    let mut level = 0;
    while len > 1 {
        for i in 0..(len + 1) / 2 {
            let concat = if 2 * i + 1 < len {
                vec![hashes[2 * i].clone(), hashes[2 * i + 1].clone()]
            } else {
                let empty_root = hashes[2 * i].loader().load_const(
                    poseidon_empty_roots.get(level).expect("poseidon_empty_roots too short"),
                );
                vec![hashes[2 * i].clone(), empty_root]
            };
            hashes[i] = poseidon_packed(hasher, PoseidonWords(concat));
        }
        len = (len + 1) / 2;
        level += 1;
    }
    hashes.into_iter().next().unwrap()
}

/// Computes poseidon(left, right), taking into account the possibility that either left or right may be empty.
pub fn poseidon_opt_pair<F, L, const T: usize, const RATE: usize>(
    hasher: &mut Poseidon<F, L, T, RATE>,
    left: OptPoseidonWords<L>,
    right: OptPoseidonWords<L>,
) -> L
where
    F: FieldExt,
    L: LoadedScalar<F>,
    L::Loader: SelectLoader<F>,
{
    if let Some(is_some) = left.is_some {
        let some_any = poseidon_opt_pair(hasher, PoseidonWords(left.words).into(), right.clone());
        let none_any = poseidon_opt_pair(hasher, PoseidonWords(vec![]).into(), right);
        let loader = is_some.loader().clone();
        loader.select(some_any, none_any, is_some)
    } else if let Some(is_some) = right.is_some {
        let left = PoseidonWords(left.words);
        let some_some = poseidon_packed(hasher, left.concat(&PoseidonWords(right.words)));
        let some_none = poseidon_packed(hasher, left);
        let loader = is_some.loader().clone();
        loader.select(some_some, some_none, is_some)
    } else {
        poseidon_packed(hasher, PoseidonWords([&left.words[..], &right.words[..]].concat()))
    }
}

/// Creates a Merkle proof proving inclusion of node `leaves[index]` into a tree with leaves `leaves`.
/// Assumes `leaves.len()` is a power of two.
pub fn create_merkle_proof<F, L, const T: usize, const RATE: usize>(
    hasher: &mut Poseidon<F, L, T, RATE>,
    leaves: Vec<PoseidonWords<L>>,
    index: usize,
) -> Vec<PoseidonWords<L>>
where
    F: FieldExt,
    L: LoadedScalar<F>,
{
    let mut len = leaves.len();
    assert!(len.is_power_of_two());
    let mut proof = Vec::with_capacity(len.ilog2() as usize);
    let mut idx = index;
    let mut current_hashes = leaves;
    while len > 1 {
        proof.push(current_hashes[idx ^ 1].clone());
        for i in 0..len / 2 {
            current_hashes[i] =
                poseidon_packed(hasher, current_hashes[2 * i].concat(&current_hashes[2 * i + 1]))
                    .into();
        }
        idx >>= 1;
        len /= 2;
    }
    proof
}

/// Computes the Poseidon Merkle root by traversing the Merkle proof.
pub fn traverse_merkle_proof<F, L, const T: usize, const RATE: usize>(
    hasher: &mut Poseidon<F, L, T, RATE>,
    proof: &[PoseidonWords<L>],
    leaf: PoseidonWords<L>,
    side: usize,
) -> PoseidonWords<L>
where
    F: FieldExt,
    L: LoadedScalar<F>,
{
    let mut current_hash = leaf;
    for (i, node) in proof.iter().enumerate() {
        if (side >> i) & 1 == 0 {
            current_hash = poseidon_packed(hasher, current_hash.concat(node)).into();
        } else {
            current_hash = poseidon_packed(hasher, node.concat(&current_hash)).into();
        }
    }
    current_hash
}

/// Assumes that `sel` is a bit (either 0 or 1).
/// Returns `word` if `sel` is 1, otherwise returns 0.
pub(crate) fn word_select_or_zero<F, C, EccChip>(
    loader: &Rc<Halo2Loader<C, EccChip>>,
    word: Scalar<C, EccChip>,
    sel: AssignedValue<F>,
) -> Scalar<C, EccChip>
where
    F: FieldExt,
    C: CurveAffine<ScalarExt = F>,
    EccChip: EccInstructions<F, C>,
{
    let sel = loader.scalar_from_assigned(sel);
    word * &sel
}

fn generate_poseidon_empty_roots(len: usize) -> Vec<Fr> {
    let mut hasher = Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());
    let mut empty_roots = Vec::with_capacity(len);
    empty_roots.push(poseidon_packed(&mut hasher, PoseidonWords(vec![])));
    for _ in 1..len {
        let last = *empty_roots.last().unwrap();
        empty_roots.push(poseidon_packed(&mut hasher, PoseidonWords(vec![last, last])));
    }
    empty_roots
}

mod shim {
    use snark_verifier::loader::ScalarLoader;

    pub trait SelectLoader<F: ff::PrimeField>: ScalarLoader<F> + Clone {
        fn select(
            &self,
            if_true: Self::LoadedScalar,
            if_false: Self::LoadedScalar,
            cond: Self::LoadedScalar,
        ) -> Self::LoadedScalar;
    }

    mod halo2_lib {
        use crate::batch_query::EccInstructions;
        use std::rc::Rc;

        use crate::{rlp::rlc::FIRST_PHASE, Field};
        use halo2_base::{gates::GateInstructions, halo2_proofs::halo2curves::CurveAffine};
        use snark_verifier::loader::halo2::Halo2Loader;

        use super::SelectLoader;

        impl<C, EccChip> SelectLoader<C::Scalar> for Rc<Halo2Loader<C, EccChip>>
        where
            C: CurveAffine,
            C::Scalar: Field,
            EccChip: EccInstructions<C::Scalar, C>,
        {
            fn select(
                &self,
                if_true: Self::LoadedScalar,
                if_false: Self::LoadedScalar,
                cond: Self::LoadedScalar,
            ) -> Self::LoadedScalar {
                let mut builder = self.ctx_mut();
                let ctx = builder.main(FIRST_PHASE);
                let out = self.scalar_chip().select(
                    ctx,
                    if_true.into_assigned(),
                    if_false.into_assigned(),
                    cond.into_assigned(),
                );
                self.scalar_from_assigned(out)
            }
        }
    }

    mod native {
        use halo2_base::halo2_proofs::halo2curves::FieldExt;
        use snark_verifier_sdk::NativeLoader;

        use super::SelectLoader;

        impl<F: FieldExt> SelectLoader<F> for NativeLoader {
            fn select(&self, if_true: F, if_false: F, cond: F) -> F {
                if bool::from(cond.is_zero()) {
                    if_false
                } else {
                    if_true
                }
            }
        }
    }
}
