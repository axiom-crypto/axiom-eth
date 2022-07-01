# AxiomV1 SNARK Verifier Circuits

# Public Instance Formats

Any `Snark` has an associated `Vec<Fr>` of public instances. We describe the format for the ones relevant to the core AxiomV1 circuits below.

## `EthBlockHeaderChainCircuit`

```rust
pub struct EthBlockHeaderChainCircuit<F> {
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

## `EthBlockHeaderChainAggregationCircuit`

```rust
pub struct EthBlockHeaderChainAggregationCircuit {
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

## `EthBlockHeaderChainFinalAggregationCircuit`

```rust
pub struct EthBlockHeaderChainFinalAggregationCircuit(pub EthBlockHeaderChainAggregationCircuit);
```

This circuit takes two [`EthBlockHeaderChainAggregationCircuit`s](#ethblockheaderchainaggregationcircuit) and aggregates them. The public instances are:

- `4 * LIMBS = 12` `Fr` elements for the two BN254 `G1` points representing the _accumulator_, used by the verifier for a pairing check
- `prev_hash`: `H256` as two `Fr` elements in hi-lo format
- `end_hash`: `H256` as two `Fr` elements in hi-lo format
- `start_block_number . end_block_number`: we assume both numbers are `u32` and encode them to a single `Fr` element as `start_block_number * 2^32 + end_block_number`
- `merkle_mountain_range`: a sequence of `max_depth + 1` `H256` elements, each encoded as two `Fr` elements in hi-lo format

Notes:

- Same notes as [`EthBlockHeaderChainCircuit`](#ethblockheaderchaincircuit)
- This circuit is the same as [`EthBlockHeaderChainAggregationCircuit`](#ethblockheaderchainaggregationcircuit) except that it does do the final Keccaks to form the full Merkle mountain range

## `PublicAggregationCircuit`

```rust
pub struct PublicAggregationCircuit {
    pub snarks: Vec<Snark>,
    pub has_prev_accumulators: bool,
}
```

This circuit aggregates snarks and re-exposes previous public inputs. The public instances are:

- `4 * LIMBS = 12` `Fr` elements for the two BN254 `G1` points representing the _accumulator_, used by the verifier for a pairing check
- Sequentially appends the public instances from each `Snark` in `snarks`
  - If `has_prev_accumulators` is true, then it assumes all previous snarks are already aggregation circuits and does not re-expose the old accumulators (the first `4 * LIMBS` elements) as public inputs.

## `EthBlockStorageCircuit`

```rust
pub struct EthBlockStorageCircuit {
    pub inputs: EthBlockStorageInput,
    pub network: Network,
}
```

The public instances are:

- `block_hash`: `H256` as two `Fr` elements in hi-lo format
- `block_number`: `u32` as a single `Fr` element
- `address`: `H160` as a single `Fr` element
- Sequence of `inputs.slots.len()` pairs of `(slot, value)` where
  - `slot`: `H256` as two `Fr` elements in hi-lo format
  - `value`: `U256` as two `Fr` elements in hi-lo format (big endian)

# `AxiomV1Core` SNARK Verifier

This snark is created by calling

```bash
cargo run --bin header_chain --release -- --start 0 --end 1023 --max-depth 10 --initial-depth 7 --final evm --extra-rounds 1 --calldata --create-contract
```

This recursively creates the following snarks in a tree:

```
PublicAggregationCircuit (10) -> PublicAggregationCircuit (10) -> EthBlockHeaderChainFinalAggregationCircuit (10) -> EthBlockHeaderChainAggregationCircuit (9) -> ... -> EthBlockHeaderChainAggregationCircuit (8) -> EthBlockHeaderChainCircuit (7)
```

where the number in parenthesis is a tracker of the `max_depth` for the circuit. We do two rounds of `PublicAggregationCircuit` to minimize final verification gas cost.

The public instances are the same as for [`EthBlockHeaderChainFinalAggregationCircuit`](#ethblockheaderchainfinalaggregationcircuit).

# `AxiomV1Core` Historical SNARK Verifier

This snark is created by calling

```bash
cargo run --bin header_chain --release -- --start 0 --end 1023 --max-depth 17 --initial-depth 7 --final evm --extra-rounds 1 --calldata --create-contract
```

This recursively creates the following snarks in a tree:

```
PublicAggregationCircuit (17) -> PublicAggregationCircuit (17) -> EthBlockHeaderChainFinalAggregationCircuit (17) -> EthBlockHeaderChainAggregationCircuit (16) -> ... -> EthBlockHeaderChainAggregationCircuit (8) -> EthBlockHeaderChainCircuit (7)
```

where the number in parenthesis is a tracker of the `max_depth` for the circuit.

The public instances are the same as for [`EthBlockHeaderChainFinalAggregationCircuit`](#ethblockheaderchainfinalaggregationcircuit).

# `AxiomV1StoragePf` SNARK Verifier

This snark is created by calling

```bash
cargo run --bin storage_proof --release -- --path data/storage/task.t.json --create-contract
```

with this [`task.t.json`](../../data/storage/task.t.json) file. In particular `inputs.slots.len() = 10`.

This recursively creates the following snarks:

```
PublicAggregationCircuit -> EthBlockStorageCircuit
```
