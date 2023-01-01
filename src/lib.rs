#![allow(clippy::too_many_arguments)]
#![feature(int_log)]
#![feature(arc_unwrap_or_clone)]

pub mod block_header;
pub mod util;

#[cfg(feature = "providers")]
pub mod providers;

use std::fmt::Display;

pub use halo2_mpt::keccak::zkevm::util::eth_types::Field;

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Network {
    Mainnet,
    Goerli,
}

impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Goerli => write!(f, "goerli"),
        }
    }
}
