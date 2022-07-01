use super::{
    util::{bytes_be_to_u128, encode_h256_to_field, EthConfigParams},
    Field, Network,
};
use crate::{
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::{RlcContextPair, RlcFixedTrace, RlcTrace, FIRST_PHASE, RLC_PHASE},
        RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness,
    },
    util::{bytes_be_var_to_fixed, decode_field_to_h256},
    EthChip, EthCircuitBuilder, ETH_LOOKUP_BITS,
};
use core::{
    iter::{self, once},
    marker::PhantomData,
};
use ethers_core::types::H256;
#[cfg(feature = "providers")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions, RangeChip},
    utils::bit_length,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use itertools::Itertools;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, env::var};

/* // No longer used, For testing only
#[derive(Serialize, Deserialize, Debug, Clone)]
struct EthBlockHeaderChainInstance {
    pub prev_hash: H256,
    pub end_hash: H256,
    pub start_block_number: u32,
    pub end_block_number: u32,
    merkle_mountain_range: Vec<H256>,
}

impl EthBlockHeaderChainInstance {
    pub fn new(
        prev_hash: H256,
        end_hash: H256,
        start_block_number: u32,
        end_block_number: u32,
        merkle_mountain_range: Vec<H256>,
    ) -> Self {
        Self { prev_hash, end_hash, start_block_number, end_block_number, merkle_mountain_range }
    }
    fn to_instance<F: Field>(&self) -> Vec<F> {
        // * prevHash: uint256 represented as 2 uint128s
        // * endHash:  uint256 represented as 2 uint128s
        // * startBlockNumber || endBlockNumber: 0..0 || uint32 || 0..0 || uint32 as u64 (exactly 64 bits)
        // * merkleRoots: Vec<uint256>, each represented as 2 uint128s
        let [prev_hash, end_hash] =
            [&self.prev_hash, &self.end_hash].map(|hash| encode_h256_to_field::<F>(hash));
        let block_numbers =
            F::from(((self.start_block_number as u64) << 32) + (self.end_block_number as u64));
        let merkle_mountain_range = self
            .merkle_mountain_range
            .iter()
            .flat_map(|hash| encode_h256_to_field::<F>(hash))
            .collect_vec();

        [&prev_hash[..], &end_hash[..], &[block_numbers], &merkle_mountain_range].concat()
    }

    fn from_instance<F: Field>(instance: &[F]) -> Self {
        let prev_hash = decode_field_to_h256(&instance[0..2]);
        let end_hash = decode_field_to_h256(&instance[2..4]);
        let block_numbers = instance[4].to_repr(); // little endian
        let start_block_number = u32::from_le_bytes(block_numbers[4..8].try_into().unwrap());
        let end_block_number = u32::from_le_bytes(block_numbers[..4].try_into().unwrap());
        let merkle_mountain_range =
            instance[5..].chunks(2).map(|chunk| decode_field_to_h256(chunk)).collect_vec();

        Self::new(prev_hash, end_hash, start_block_number, end_block_number, merkle_mountain_range)
    }
}
*/
