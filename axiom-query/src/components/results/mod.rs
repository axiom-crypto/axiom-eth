//! # Calculate Subquery Results Root and Subquery Hashes Component Circuit
//!
//! This component circuit is responsible for:
//! - Taking in **ordered** list of **ungrouped** subqueries with results and
//!   checking the results are all valid with respect to promise commitments of
//!   the individual subquery components, which are **grouped** by subquery type.
//! - Computing the subquery hashes of each subquery in the ordered list.

use axiom_codec::constants::NUM_SUBQUERY_TYPES;

/// Circuit and Component Implementation.
pub mod circuit;
/// Compute resultsRoot keccak
pub mod results_root;
/// Subquery hash computation handler
pub mod subquery_hash;
/// Contains the logic of joining virtual tables of different subquery types together into one big table.
/// The virtual tables are of different widths: rather than resizing them directly in-circuit, we only compute
/// the RLC of the resized tables, so that the result is a table with the RLCs of the resized tables, all joined together.
pub mod table;
/// Types
pub mod types;

#[cfg(test)]
pub mod tests;

pub const ENABLE_ALL_SUBQUERY_TYPES: [bool; NUM_SUBQUERY_TYPES] = [true; NUM_SUBQUERY_TYPES];
