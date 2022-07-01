use std::io::{Error, ErrorKind, Read, Result};

use axiom_eth::halo2curves::CurveAffine;
use ethers_core::types::{Address, H256, U256};

use crate::Field;

pub fn read_address(reader: &mut impl Read) -> Result<Address> {
    let mut addr = [0u8; 20];
    reader.read_exact(&mut addr)?;
    Ok(Address::from_slice(&addr))
}

pub fn read_u256(reader: &mut impl Read) -> Result<U256> {
    let mut word = [0u8; 32];
    reader.read_exact(&mut word)?;
    Ok(U256::from_big_endian(&word))
}

pub fn read_h256(reader: &mut impl Read) -> Result<H256> {
    let mut hash = [0u8; 32];
    reader.read_exact(&mut hash)?;
    Ok(H256(hash))
}

pub fn read_field_le<F: Field>(reader: &mut impl Read) -> Result<F> {
    let mut repr = [0u8; 32];
    reader.read_exact(&mut repr)?;
    Ok(F::from_bytes_le(&repr))
}

pub fn read_field_be<F: Field>(reader: &mut impl Read) -> Result<F> {
    let mut repr = [0u8; 32];
    reader.read_exact(&mut repr)?;
    repr.reverse();
    Ok(F::from_bytes_le(&repr))
}

pub fn read_curve_compressed<C: CurveAffine>(reader: &mut impl Read) -> Result<C> {
    let mut compressed = C::Repr::default();
    reader.read_exact(compressed.as_mut())?;
    Option::from(C::from_bytes(&compressed))
        .ok_or_else(|| Error::new(ErrorKind::Other, "Invalid compressed point encoding"))
}
