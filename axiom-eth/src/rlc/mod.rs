//! Custom gate, chip, and circuit builder for use with RLC computations

/// Chip with functions using RLC
pub mod chip;
/// Circuit builder for RLC
pub mod circuit;
/// Utility functions for concatenating variable length arrays
pub mod concat_array;
#[cfg(test)]
pub mod tests;
/// Types
pub mod types;
/// Module for managing the virtual region corresponding to RLC columns
pub mod virtual_region;

pub mod utils;

/// FirstPhase of challenge API
pub const FIRST_PHASE: usize = 0;
/// RLC is hard-coded to take place in SecondPhase
pub const RLC_PHASE: usize = 1;
