#![feature(trait_alias)]
#![feature(io_error_other)]

pub use axiom_eth::utils::hilo::HiLo;
pub use axiom_eth::Field;

/// Constants
pub mod constants;
pub mod decoder;
pub mod encoder;
/// Special constants used in subquery specification
pub mod special_values;
pub mod types;
pub mod utils;

pub const VERSION: u8 = 0x02;
