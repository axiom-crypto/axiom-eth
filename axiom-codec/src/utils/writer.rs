use std::io::{Result, Write};

use axiom_eth::{halo2_base::utils::ScalarField, halo2curves::CurveAffine};
use ethers_core::types::U256;

use crate::Field;

pub fn write_u256(writer: &mut impl Write, word: U256) -> Result<()> {
    let mut buf = [0u8; 32];
    word.to_big_endian(&mut buf);
    writer.write_all(&buf)?;
    Ok(())
}

pub fn write_field_le<F: Field>(writer: &mut impl Write, fe: F) -> Result<()> {
    let repr = ScalarField::to_bytes_le(&fe);
    writer.write_all(&repr)?;
    Ok(())
}

pub fn write_field_be<F: Field>(writer: &mut impl Write, fe: F) -> Result<()> {
    let mut repr = ScalarField::to_bytes_le(&fe);
    repr.reverse();
    writer.write_all(&repr)?;
    Ok(())
}

pub fn write_curve_compressed<C: CurveAffine>(writer: &mut impl Write, point: C) -> Result<()> {
    let compressed = point.to_bytes();
    writer.write_all(compressed.as_ref())?;
    Ok(())
}
