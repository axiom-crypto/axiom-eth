use std::io::{Error, ErrorKind, Result};

use ethers_core::types::H256;
use halo2_base::{AssignedValue, Context};
use serde::{Deserialize, Serialize};
use zkevm_hashes::util::{eth_types::Field, word::Word};

use crate::impl_flatten_conversion;

use super::encode_h256_to_hilo;

/// Stored as [lo, hi], just like Word2
#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct HiLo<T>([T; 2]);

impl<T> HiLo<T> {
    /// Create a new [HiLo] from a `[lo, hi]` array.
    pub fn from_lo_hi([lo, hi]: [T; 2]) -> Self {
        Self([lo, hi])
    }
    /// Create a new [HiLo] from a `[hi, lo]` array.
    pub fn from_hi_lo([hi, lo]: [T; 2]) -> Self {
        Self([lo, hi])
    }
    pub fn hi(&self) -> T
    where
        T: Copy,
    {
        self.0[1]
    }
    pub fn lo(&self) -> T
    where
        T: Copy,
    {
        self.0[0]
    }
    pub fn hi_lo(&self) -> [T; 2]
    where
        T: Copy,
    {
        [self.hi(), self.lo()]
    }
    pub fn flatten(&self) -> [T; 2]
    where
        T: Copy,
    {
        self.hi_lo()
    }
}

impl<F: Field> HiLo<F> {
    pub fn assign(&self, ctx: &mut Context<F>) -> HiLo<AssignedValue<F>> {
        HiLo(self.0.map(|x| ctx.load_witness(x)))
    }
}

impl<T: Clone> From<Word<T>> for HiLo<T> {
    fn from(word: Word<T>) -> Self {
        Self::from_hi_lo([word.hi(), word.lo()])
    }
}

impl<T: Clone> From<HiLo<T>> for Word<T> {
    fn from(lohi: HiLo<T>) -> Self {
        Word::new(lohi.0)
    }
}

impl<F: Field> From<H256> for HiLo<F> {
    fn from(value: H256) -> Self {
        encode_h256_to_hilo(&value)
    }
}

impl<T> TryFrom<Vec<T>> for HiLo<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self> {
        let [hi, lo] = value
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid array length"))?;
        Ok(Self::from_hi_lo([hi, lo]))
    }
}

/// We will only flatten HiLo to uint128 words.
pub const BITS_PER_FE_HILO: [usize; 2] = [128, 128];
impl_flatten_conversion!(HiLo, BITS_PER_FE_HILO);

impl<T: std::fmt::Debug> std::fmt::Debug for HiLo<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HiLo").field(&self.0[1]).field(&self.0[0]).finish()
    }
}
