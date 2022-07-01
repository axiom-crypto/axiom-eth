//! # Subquery Aggregation Circuit
//!
//! Aggregation all subquery circuits and resultsRoot circuit.
//! Currently these are all of the components _except_ the keccak component.
//!
//! The reasoning is that the keccak component should be aggregated separately
//! and run in parallel to the Subquery Aggregation Circuit and all other components.

pub mod circuit;
pub mod types;

#[cfg(test)]
pub mod tests;
