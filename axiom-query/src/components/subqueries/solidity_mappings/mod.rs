//! # Solidity Nested Mapping Subqueries Circuit
//!
//! SolidityNestedMapping
//! - `blockNumber` (uint32)
//! - `addr` (address = bytes20)
//! - `mappingSlot` (uint256)
//! - `mappingDepth` (uint8) -- in `(0, 4]`
//! - `keys` \[key0, key1, key2, key3\] (bytes32\[4\])

/// Circuit and Component Implementation.
pub mod circuit;
/// Types
pub mod types;

#[cfg(test)]
pub mod tests;
