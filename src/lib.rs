#![allow(unused_imports, dead_code, unused_variables)]
#![feature(int_log)]
// different memory allocator options:
// empirically jemalloc still seems to give best speeds for witness generation
#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub mod eth;
pub mod keccak;
pub mod mpt;
pub mod rlp;

#[cfg(feature = "input_gen")]
pub mod input_gen;
