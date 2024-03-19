//! # Verify Compute Circuit
//!
//! Verifies the user proof (`computeQuery`) and calculates the query hash
//! by de-committing subquery results and subquery hashes from two public instances.
//!
//! The Axiom Aggregation Circuit **must** check that these public instances agree
//! with the public instances from the Subquery Aggregation Circuit.
//!
pub mod circuit;
/// Compute `dataQueryHash` and `queryHash`
pub mod query_hash;
pub mod types;
pub mod utils;

#[cfg(test)]
pub mod tests;
