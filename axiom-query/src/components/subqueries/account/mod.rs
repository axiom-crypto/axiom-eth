//! # Account Subqueries Circuit
//!
//! | Account State Field     | Max bytes   |
//! |-------------------------|-------------|
//! | nonce                   | ≤8          |
//! | balance                 | ≤12         |
//! | storageRoot             | 32          |
//! | codeHash                | 32          |
//!
//! Account subquery
//! - `blockNumber` (uint32)
//! - `addr` (address = bytes20)
//! - `fieldIdx` (uint32)
//!

use std::str::FromStr;

use ethers_core::types::H256;

/// Circuit and Component Implementation.
pub mod circuit;
/// Types
pub mod types;

#[cfg(test)]
pub mod tests;

pub const STORAGE_ROOT_INDEX: usize = 2;

lazy_static::lazy_static! {
    /// keccak(rlp("")) = keccak(0x80)
    pub static ref KECCAK_RLP_EMPTY_STRING: H256 = H256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
}

#[cfg(test)]
#[test]
fn test_null_mpt_root() {
    use ethers_core::utils::keccak256;
    assert_eq!(KECCAK_RLP_EMPTY_STRING.as_bytes(), &keccak256(vec![0x80]));
}
