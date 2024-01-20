//! # Axiom Aggregation 1 Circuit
//!
//! The first layer of Axiom aggregation.
//!
//! This aggregates the Subquery Aggregation circuit, the Verify Compute circuit, and the Keccak final aggregation circuit.
//! It checks that the commitments to subquery results and subquery hashes from Subquery Aggregation circuit
//! match those in the Verify Compute circuit.
//! It also checks that all Keccak commitments agree among the circuits.

pub mod circuit;
pub mod types;

#[cfg(test)]
pub mod tests;
