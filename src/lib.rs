#![allow(unused_imports, unused_variables)]

// different memory allocator options:
// empirically jemalloc still seems to give best speeds for witness generation
//#[cfg(not(target_env = "msvc"))]
//use jemallocator::Jemalloc;

//#[cfg(not(target_env = "msvc"))]
//#[global_allocator]
//static GLOBAL: Jemalloc = Jemalloc;

pub mod eth;
pub mod keccak;
pub mod mpt;
pub mod rlp;
