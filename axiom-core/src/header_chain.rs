use std::{iter, marker::PhantomData};

use axiom_eth::{
    block_header::{
        get_block_header_rlp_max_lens_from_extra, get_boundary_block_data, EthBlockHeaderChip,
        EthBlockHeaderWitness,
    },
    halo2_base::{
        gates::{GateInstructions, RangeInstructions},
        AssignedValue,
        QuantumCell::Constant,
    },
    mpt::MPTChip,
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::assign_vec,
    utils::{
        build_utils::aggregation::CircuitMetadata, eth_circuit::EthCircuitInstructions,
        keccak::decorator::RlcKeccakCircuitImpl,
    },
};
use itertools::Itertools;

use crate::Field;

pub type EthBlockHeaderChainCircuit<F> = RlcKeccakCircuitImpl<F, EthBlockHeaderChainInput<F>>;

/// The input datum for the block header chain circuit. It is used to generate a circuit.
///
/// The public instances:
/// * prev_hash (hi-lo)
/// * end_hash (hi-lo)
/// * solidityPacked(["uint32", "uint32"], [start_block_number, end_block_number]) (F)
/// * merkle_roots: [HiLo<F>; max_depth + 1]
#[derive(Clone, Debug)]
pub struct EthBlockHeaderChainInput<F> {
    /// The private inputs, which are the RLP encodings of the block headers
    header_rlp_encodings: Vec<Vec<u8>>,
    num_blocks: u32, // num_blocks in [1, 2 ** max_depth]
    max_depth: usize,
    /// Configuration parameters of the maximum number of bytes in the extra data field.
    /// This is mostly to distinguish between mainnet and Goerli (or other forks).
    max_extra_data_bytes: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> EthBlockHeaderChainInput<F> {
    /// Handles resizing of each `header_rlp_encodings` to max length and also
    /// resizes the number of rlp encodings to 2^max_depth.
    pub fn new(
        mut header_rlp_encodings: Vec<Vec<u8>>,
        num_blocks: u32,
        max_depth: usize,
        max_extra_data_bytes: usize,
    ) -> Self {
        let (header_rlp_max_bytes, _) =
            get_block_header_rlp_max_lens_from_extra(max_extra_data_bytes);
        // pad to correct length with dummies
        let dummy_block_rlp = header_rlp_encodings[0].clone();
        header_rlp_encodings.resize(1 << max_depth, dummy_block_rlp);
        for header_rlp in header_rlp_encodings.iter_mut() {
            header_rlp.resize(header_rlp_max_bytes, 0u8);
        }
        Self {
            header_rlp_encodings,
            num_blocks,
            max_depth,
            max_extra_data_bytes,
            _marker: PhantomData,
        }
    }
}

/// Data passed from phase0 to phase1
#[derive(Clone, Debug)]
pub struct EthBlockHeaderchainWitness<F: Field> {
    pub max_extra_data_bytes: usize,
    /// The chain of blocks, where the hash of block_chain\[i\] is proved to be the parent hash of block_chain\[i+1\]
    pub block_chain: Vec<EthBlockHeaderWitness<F>>,
    pub num_blocks_minus_one: AssignedValue<F>,
    pub indicator: Vec<AssignedValue<F>>,
}

impl<F: Field> EthCircuitInstructions<F> for EthBlockHeaderChainInput<F> {
    type FirstPhasePayload = EthBlockHeaderchainWitness<F>;

    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let chip = EthBlockHeaderChip::new(mpt.rlp, self.max_extra_data_bytes);
        let keccak = mpt.keccak();

        // ======== FIRST PHASE ===========
        let ctx = builder.base.main(0);
        // ==== Load private inputs =====
        let num_blocks = ctx.load_witness(F::from(self.num_blocks as u64));
        let num_blocks_minus_one = chip.gate().sub(ctx, num_blocks, Constant(F::ONE));
        // `num_blocks_minus_one` should be < 2^max_depth.
        // We check this for safety, although it is not technically necessary because `num_blocks_minus_one` will equal the difference of the start, end block numbers, which are public inputs
        chip.range().range_check(ctx, num_blocks_minus_one, self.max_depth);

        // ==== Load RLP encoding and decode ====
        let max_len = get_block_header_rlp_max_lens_from_extra(self.max_extra_data_bytes).0;
        let block_headers = self
            .header_rlp_encodings
            .iter()
            .map(|header| assign_vec(ctx, header.clone(), max_len))
            .collect_vec();
        let block_chain_witness =
            chip.decompose_block_header_chain_phase0(builder, keccak, block_headers);
        // All keccaks must be done in FirstPhase, so we compute the merkle mountain range from the RLP decoded witnesses now
        let ctx = builder.base.main(0);
        let num_leaves_bits = chip.gate().num_to_bits(ctx, num_blocks, self.max_depth + 1);
        let block_hashes = block_chain_witness
            .iter()
            .map(|witness| witness.block_hash.output_bytes.as_ref().to_vec())
            .collect_vec();
        // mountain range in bytes
        let mountain_range = keccak.merkle_mountain_range(ctx, &block_hashes, &num_leaves_bits);
        let mountain_range = mountain_range
            .into_iter()
            .zip(num_leaves_bits.into_iter().rev())
            .flat_map(|((_hash_bytes, hash_u128s), bit)| {
                // if the bit is 0, then we set the hash root to 0
                hash_u128s.map(|hash_u128| chip.gate().mul(ctx, hash_u128, bit))
            })
            .collect_vec();

        let indicator =
            chip.gate().idx_to_indicator(ctx, num_blocks_minus_one, block_chain_witness.len());
        let (prev_block_hash, end_block_hash, block_numbers) =
            get_boundary_block_data(ctx, chip.gate(), &block_chain_witness, &indicator);
        let assigned_instances = iter::empty()
            .chain(prev_block_hash)
            .chain(end_block_hash)
            .chain(iter::once(block_numbers))
            .chain(mountain_range)
            .collect_vec();
        builder.base.assigned_instances[0] = assigned_instances;

        EthBlockHeaderchainWitness {
            max_extra_data_bytes: self.max_extra_data_bytes,
            block_chain: block_chain_witness,
            num_blocks_minus_one,
            indicator,
        }
    }

    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        witness: Self::FirstPhasePayload,
    ) {
        let chip = EthBlockHeaderChip::new(mpt.rlp, witness.max_extra_data_bytes);
        let _block_chain_trace = chip.decompose_block_header_chain_phase1(
            builder,
            witness.block_chain,
            Some((witness.num_blocks_minus_one, witness.indicator)),
        );
    }
}

impl<F: Field> CircuitMetadata for EthBlockHeaderChainInput<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        vec![2 + 2 + 1 + 2 * (self.max_depth + 1)]
    }
}
