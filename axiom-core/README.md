# AxiomV2Core ZK Circuits

# Proving and Verifying Key Generation

For instructions on how to generate the exact proving and verifying keys we use in production on Ethereum Mainnet, see [here](./KEYGEN.md).

# Public Instance Formats

Any `Snark` has an associated `Vec<Fr>` of public instances. We describe the format for the ones relevant to the `AxiomV2Core` circuits below.

## `EthBlockHeaderChainCircuit`

```rust
pub struct EthBlockHeaderChainInput<F> {
    header_rlp_encodings: Vec<Vec<u8>>,
    num_blocks: u32, // num_blocks in [0, 2 ** max_depth)
    max_depth: usize,
    network: Network,
    _marker: PhantomData<F>,
}
```

This depends on a `max_depth` parameter. The public instances are:

- `prev_hash`: `H256` as two `Fr` elements in hi-lo format
- `end_hash`: `H256` as two `Fr` elements in hi-lo format
- `start_block_number . end_block_number`: we assume both numbers are `u32` and encode them to a single `Fr` element as `start_block_number * 2^32 + end_block_number`
- `merkle_mountain_range`: a sequence of `max_depth + 1` `H256` elements, each encoded as two `Fr` elements in hi-lo format

Notes:

- `prev_hash` is the parent hash of block number `start_block_number`
- `end_hash` is the block hash of block number `end_block_number`
- `end_block_number - start_block_number` is constrained to be `<= 2^max_depth`
  - This was previously assumed in `axiom-eth` `v0.1.1` but not enforced because the block numbers are public instances, but we now enforce it for safety
- `merkle_mountain_range` is ordered from largest peak (depth `max_depth`) first to smallest peak (depth `0`) last

## `EthBlockHeaderChainIntermediateAggregationCircuit`

```rust
pub struct EthBlockHeaderChainIntermediateAggregationInput {
    num_blocks: u32,
    snarks: Vec<Snark>,
    pub max_depth: usize,
    pub initial_depth: usize,
}
```

This circuit takes two [`EthBlockHeaderChainCircuit`s](#ethblockheaderchaincircuit) and aggregates them. The public instances are:

- `4 * LIMBS = 12` `Fr` elements for the two BN254 `G1` points representing the _accumulator_, used by the verifier for a pairing check
- `prev_hash`: `H256` as two `Fr` elements in hi-lo format
- `end_hash`: `H256` as two `Fr` elements in hi-lo format
- `start_block_number . end_block_number`: we assume both numbers are `u32` and encode them to a single `Fr` element as `start_block_number * 2^32 + end_block_number`
- `merkle_mountain_range`: a sequence of `2^{max_depth - initial_depth} + initial_depth` `H256` elements, each encoded as two `Fr` elements in hi-lo format

Notes:

- Same notes as [`EthBlockHeaderChainCircuit`](#ethblockheaderchaincircuit) **except** that `merkle_mountain_range` is not actually a Merkle mountain range: we recover a Merkle mountain range of length `max_depth + 1` by forming a Merkle mountain range from leaves `merkle_mountain_range[..2^{max_depth - initial_depth}]` and then appending `merkle_mountain_range[2^{max_depth - initial_depth}..]` to the end of it.
  - The reason is that we want to delay Keccaks

## `EthBlockHeaderChainRootAggregationCircuit`

```rust
pub struct EthBlockHeaderChainRootAggregationInput {
    /// See [EthBlockHeaderChainIntermediateAggregationInput]
    pub inner: EthBlockHeaderChainIntermediateAggregationInput,
    /// Succinct verifying key (generator of KZG trusted setup) should match `inner.snarks`
    pub svk: Svk,
    prev_acc_indices: Vec<Vec<usize>>,
}
```

This circuit takes two [`EthBlockHeaderChainIntermediateAggregationCircuit`s](#ethblockheaderchainintermediateaggregationcircuit) and aggregates them. The public instances are:

- `4 * LIMBS = 12` `Fr` elements for the two BN254 `G1` points representing the _accumulator_, used by the verifier for a pairing check
- `prev_hash`: `H256` as two `Fr` elements in hi-lo format
- `end_hash`: `H256` as two `Fr` elements in hi-lo format
- `start_block_number . end_block_number`: we assume both numbers are `u32` and encode them to a single `Fr` element as `start_block_number * 2^32 + end_block_number`
- `merkle_mountain_range`: a sequence of `max_depth + 1` `H256` elements, each encoded as two `Fr` elements in hi-lo format

Notes:

- Same notes as [`EthBlockHeaderChainCircuit`](#ethblockheaderchaincircuit)
- This circuit is the same as [`EthBlockHeaderChainIntermediateAggregationCircuit`](#ethblockheaderchainintermediateaggregationcircuit) except that it does do the final Keccaks to form the full Merkle mountain range

## Passthrough Aggregation Circuit

This is from [`axiom-eth`](../axiom-eth/src/utils/merkle_aggregation.rs).

```rust
pub struct InputMerkleAggregation {
    pub snarks: Vec<EnhancedSnark>,
}
```

We will only use this where `snarks` has length 1 and consists of a single snark. In this case it is an `AggregationCircuit` that purely passes through the public instances of the single snark in `snarks`, discarding old accumulators (there is no Merkle root computation because there is only one snark).

We will use this snark on [`EthBlockHeaderChainRootAggregationCircuit`] or itself if we want multiple rounds of passthrough aggregation.
The public instances are exactly the same as for [`EthBlockHeaderChainRootAggregationCircuit`].
