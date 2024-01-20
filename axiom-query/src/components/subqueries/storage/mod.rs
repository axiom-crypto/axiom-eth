//! # Storage Subqueries Circuit
//!
//! Storage subquery
//! - `blockNumber` (uint32)
//! - `addr` (address = bytes20)
//! - `slot` (uint256)
//!

/// Circuit and Component Implementation.
pub mod circuit;
/// Types
pub mod types;

#[cfg(test)]
pub mod tests;
