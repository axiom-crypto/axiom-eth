//! We need to compute hash concentation and Merkle tree root for Poseidon and Keccak,
//! both in Halo2 and Native (Rust)
//!
//! We use the [`snark-verifier`] implementation of Poseidon which uses the `Loader` trait
//! to deal with Halo2 and Native loader simultaneously.

mod keccak;
mod poseidon;
pub use keccak::*;
pub use poseidon::*;
