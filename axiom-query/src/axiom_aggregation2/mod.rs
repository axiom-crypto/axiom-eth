//! # Axiom Aggregation 2 Circuit
//!
//! The second (and currently final) layer of Axiom aggregation.
//! This circuit aggregates the single snark of the Axiom Aggregation 1 circuit. It exposes the same
//! public instances but also adds a `payee` instance.

pub mod circuit;

#[cfg(test)]
pub mod tests;
