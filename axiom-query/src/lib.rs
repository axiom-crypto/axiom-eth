#![feature(io_error_other)]
#![feature(associated_type_defaults)]

pub use axiom_codec;
pub use axiom_eth;

use axiom_eth::halo2_proofs::halo2curves::ff;
pub use axiom_eth::{Field, RawField};

pub mod axiom_aggregation1;
pub mod axiom_aggregation2;
/// Components Complex
pub mod components;
/// Global configuration constants
pub mod global_constants;
pub mod subquery_aggregation;
pub mod utils;
pub mod verify_compute;

#[cfg(feature = "keygen")]
pub mod keygen;

/// This means we can concatenate arrays with individual max length 2^32.
pub const DEFAULT_RLC_CACHE_BITS: usize = 32;
