/// Instructions for aggregating a circuit using `snark-verifier` SDK
#[cfg(feature = "aggregation")]
pub mod aggregation;
pub mod dummy;
#[cfg(feature = "keygen")]
pub mod keygen;
/// Circuit pinning instructions
pub mod pinning;
