pub use axiom_eth::utils::{encode_addr_to_field, encode_h256_to_hilo};
use ethers_core::types::{Address, H256, U256};

use crate::{Field, HiLo};

pub fn u256_to_h256(input: &U256) -> H256 {
    let mut bytes = [0; 32];
    input.to_big_endian(&mut bytes);
    H256(bytes)
}

pub fn decode_hilo_to_h256<F: Field>(fe: HiLo<F>) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&fe.lo().to_bytes_le()[..16]);
    bytes[16..].copy_from_slice(&fe.hi().to_bytes_le()[..16]);
    bytes.reverse();
    H256(bytes)
}

/// Takes U256, converts to bytes32 (big endian) and returns (hash[..16], hash[16..]) represented as big endian numbers in the prime field
pub fn encode_u256_to_hilo<F: Field>(input: &U256) -> HiLo<F> {
    let mut bytes = vec![0; 32];
    input.to_little_endian(&mut bytes);
    // repr is in little endian
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[16..]);
    let hi = F::from_bytes_le(&repr);
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[..16]);
    let lo = F::from_bytes_le(&repr);
    HiLo::from_lo_hi([lo, hi])
}

pub fn decode_hilo_to_u256<F: Field>(fe: HiLo<F>) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&fe.lo().to_bytes_le()[..16]);
    bytes[16..].copy_from_slice(&fe.hi().to_bytes_le()[..16]);
    U256::from_little_endian(&bytes)
}

pub fn decode_field_to_addr<F: Field>(fe: &F) -> Address {
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&fe.to_bytes_le()[..20]);
    bytes.reverse();
    Address::from_slice(&bytes)
}
