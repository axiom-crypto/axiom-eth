use axiom_eth::utils::encode_h256_to_hilo;
use ethers_core::types::H256;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::Field;

#[derive(Serialize, Deserialize)]
pub struct EthBlockHeaderChainInstance {
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
    pub fn to_instance<F: Field>(&self) -> Vec<F> {
        // * prevHash: uint256 represented as 2 uint128s
        // * endHash:  uint256 represented as 2 uint128s
        // * startBlockNumber || endBlockNumber: 0..0 || uint32 || 0..0 || uint32 as u64 (exactly 64 bits)
        // * merkleRoots: Vec<uint256>, each represented as 2 uint128s
        let [prev_hash, end_hash] =
            [&self.prev_hash, &self.end_hash].map(|hash| encode_h256_to_hilo::<F>(hash));
        let block_numbers =
            F::from(((self.start_block_number as u64) << 32) + (self.end_block_number as u64));
        let merkle_mountain_range = self
            .merkle_mountain_range
            .iter()
            .flat_map(|hash| encode_h256_to_hilo::<F>(hash).hi_lo())
            .collect_vec();

        [&prev_hash.hi_lo()[..], &end_hash.hi_lo()[..], &[block_numbers], &merkle_mountain_range]
            .concat()
    }

    /*fn from_instance<F: Field>(instance: &[F]) -> Self {
    let prev_hash = decode_f(&instance[0..2]);
    let end_hash = decode_field_to_h256(&instance[2..4]);
    let block_numbers = instance[4].to_repr(); // little endian
    let start_block_number = u32::from_le_bytes(block_numbers[4..8].try_into().unwrap());
    let end_block_number = u32::from_le_bytes(block_numbers[..4].try_into().unwrap());
    let merkle_mountain_range =
        instance[5..].chunks(2).map(|chunk| decode_field_to_h256(chunk)).collect_vec();

    Self::new(prev_hash, end_hash, start_block_number, end_block_number, merkle_mountain_range)
    }*/
}

/*
// OLD, no longer needed except for debugging
let chain_instance = {
    // basically the same logic as `join_previous_instances` except in native rust
    let instance_start_idx = usize::from(initial_depth + 1 != max_depth) * 4 * LIMBS;
    let [instance0, instance1] = [0, 1].map(|i| {
        EthBlockHeaderChainInstance::from_instance(
            &snarks[i].instances[0][instance_start_idx..],
        )
    });

    let mut roots = Vec::with_capacity((1 << (max_depth - initial_depth)) + initial_depth);
    let cutoff = 1 << (max_depth - initial_depth - 1);
    roots.extend_from_slice(&instance0.merkle_mountain_range[..cutoff]);
    roots.extend_from_slice(&instance1.merkle_mountain_range[..cutoff]);
    if num_blocks <= 1 << (max_depth - 1) {
        assert_eq!(
            instance0.end_block_number - instance0.start_block_number,
            num_blocks - 1
        );
        roots.extend_from_slice(&instance0.merkle_mountain_range[cutoff..]);
    } else {
        assert_eq!(instance0.end_hash, instance1.prev_hash);
        assert_eq!(
            instance0.end_block_number - instance0.start_block_number,
            (1 << (max_depth - 1)) - 1
        );
        assert_eq!(instance0.end_block_number, instance1.start_block_number - 1);
        assert_eq!(
            instance1.end_block_number - instance0.start_block_number,
            num_blocks - 1
        );
        roots.extend_from_slice(&instance1.merkle_mountain_range[cutoff..]);
    };
    EthBlockHeaderChainInstance {
        prev_hash: instance0.prev_hash,
        end_hash: if num_blocks <= 1 << (max_depth - 1) {
            instance0.end_hash
        } else {
            instance1.end_hash
        },
        start_block_number: instance0.start_block_number,
        end_block_number: instance0.start_block_number + num_blocks - 1,
        merkle_mountain_range: roots,
    }
};*/

// RootAggregation
/* // Only for testing
    let leaves =
        &inner.chain_instance.merkle_mountain_range[..num_blocks as usize >> initial_depth];
    let mut new_mmr = get_merkle_mountain_range(leaves, max_depth - initial_depth);
    new_mmr.extend_from_slice(
        &inner.chain_instance.merkle_mountain_range[1 << (max_depth - initial_depth)..],
    );
    inner.chain_instance.merkle_mountain_range = new_mmr;
*/
