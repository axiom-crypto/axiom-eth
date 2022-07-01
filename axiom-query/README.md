# AxiomV2Query ZK Circuits

# Proving and Verifying Key Generation

For instructions on how to generate the exact proving and verifying keys we use in production on Ethereum Mainnet, see [here](./KEYGEN.md).

# Overview

## [Subquery Components](./src/components/subqueries/)

These are the component circuits that prove all subqueries of a single type:

- [header](./src/components/subqueries/block_header/)
- [account](./src/components/subqueries/account/)
- [storage](./src/components/subqueries/storage/)
- [transaction](./src/components/subqueries/transaction/)
- [receipt](./src/components/subqueries/receipt/)
- [solidity mappings](./src/components/subqueries/solidity_mappings/)

These circuits all use the [Component Circuit Framework](../axiom-eth/src/utils/README.md).
They each consist of a `ComponentCircuitImpl` with `RlcCircuitBuilder`, a single `PromiseLoader` for keccak, and a single `PromiseLoader` for a dependent subquery type (or none in the case of header).
The `CoreBuilder` in each case specifies the business logic of the circuit in `virtual_assign_phase{0,1}` but there is no special raw assignment: the raw assignments are all done by `RlcCircuitBuilder` and the `PromiseLoader`s. The virtual table output by each circuit is the table of `(subquery, value)` pairs for that subquery type. The `subquery` type is different for each circuit, but we specify a `flatten` function for each type which uniformizes the way to compute the Poseidon-based commitment to the virtual output table.

For each circuit, one needs to specify:

- the types of the virtual table output
- the component type to make promise calls to:
  - header: none (but it depends on an external blockhash MMR)
  - account: header
  - storage: account
  - tx: header
  - receipt: header
  - solidity: storage

What is hidden from the `CoreBuilder` implementation are the other parts of `ComponentCircuitImpl`:

- the `PromiseLoader`s are correctly loading the promise table and adding dynamic lookups
- the promise table commitment is being computed correctly

The unchecked assumption of each circuit are:

- the promise table commitments for keccak and the called component circuit will be matched with the actual output commitments of those circuits

**Disclaimer:** there is still a fair amount of copy-paste code between subquery circuit implementations. We are working to reduce this further.

## [Results Root Component Circuit](./src/components/results/)

This circuit also uses the [Component Circuit Framework](../axiom-eth/src/utils/README.md) but is a bit special compared to the subquery circuits. It is a component circuit with **no** component output. However it does make promise calls to every other subquery component circuit.
These promise tables are _a priori_ grouped by subquery types. Moreover they may contain intermediate subqueries that were only needed to check correctness of the user subquery (e.g., a tx subquery needs a corresponding header subquery to check the transaction root). In order to compute the `queryHash` and `resultsRoot`, we need the _ordered_ list of user subqueries and results. We do this by "joining" the promise tables of different types into one big lookup table and then doing dynamic lookups to check.

The join is currently done in the `table` module; it will be moved to `MultiPromiseLoader` in a coming PR.

The reason this component circuit has no component output is that the true outputs of the circuit are: `resultsRoot`, `resultsRootPoseidon`, and `subqueryHash`s. These are outward/user facing outputs, and for future compatibilty their format depends on the number of subqueries (e.g., `resultsRoot` is a padded Merkle root up to next power of 2 of `numSubqueries`). As such there is no automatic way to compute these commitments and we have custom implementations for them.

## [Keccak Component Shard Circuit](https://github.com/axiom-crypto/halo2-lib/blob/release-0.4.1-rc/hashes/zkevm/src/keccak/component/circuit/shard.rs)

The base `KeccakComponentShardCircuit` in `halo2-lib/zkevm-hashes` is a component circuit by our [definition](../axiom-eth/src/utils/README.md#definition-of-component-circuit).
We have added adapters to [`axiom-eth`](../axiom-eth/src/keccak/README.md) so that it can be promise called as a component circuit in our framework.

## [Merkle Aggregation Circuits](../axiom-eth/src/utils/merkle_aggregation.rs)

Above we have described the component **shard** circuits. For any component type, multiple shard circuits will be aggregated together (exact configurations will be determined after benchmarking) using `InputMerkleAggregation`. As such we will have component aggregation circuits for each component type where the output commitment is a Merkle root of shard output commitments.
We note that this is fully supported by the Subquery Aggregation Circuit and Axiom Aggregation 1 Circuit because the public instance format of the shard and aggregation circuit of a given component type will be exactly the same, excluding accumulators. The Subquery Aggregation Circuit and Axiom Aggregation 1 Circuit know when to remove old accumulators from previous instances of aggregates snarks, so the treatment is uniform.

## [Verify Compute Circuit](./src/verify_compute/)

This circuit aggregates a user submitted compute snark (in the form of `AxiomV2ComputeQuery`).
It then decommits a claimed `resultsRootPoseidon` and the claimed Poseidon commitment to `subqueryHashes`. It then requires calling keccaks to combine subquery results and `computeQuery`
to compute the full `queryHash`.

This is not a component circuit, but it is implemented using `EthCircuitImpl`, which uses `PromiseLoader` to call the keccak component.

## [Subquery Aggregation Circuit](./src/subquery_aggregation/)

This is a universal aggregation circuit that aggregates all subquery circuits and the results root circuit. Since the results root circuit calls each subquery circuit, this aggregation circuit will check the public instance equalities between all promise commitments and output commitments of subquery component circuits.

It will also check that all keccak promise commitments are equal, but this promise commitment is still not checked.

The public outputs of the subquery aggregation circuit are:

- those of the results root circuit,
- the blockhash MMR from the header circuit
- keccak promise commitment
- accumulator and aggregate vkey hash from the universal aggregation

After this aggregation one can forget about the subquery and results root circuits.

## [Axiom Aggregation 1 Circuit](./src/axiom_aggregation1/)

This circuit will aggregate:

- Verify Compute Circuit
- Subquery Aggregation Circuit
- Keccak Component Final Aggregation Circuit

In other words, it aggregates all remaining circuits. It will check that the `resultsRootPoseidon` and `subqueryHashes` commits in Verify Compute and Subquery Aggregation circuits match. It will also check that the keccak promise and output commitments match.

## [Axiom Aggregation 2 Circuit](./src/axiom_aggregation2/)

This aggregates [Axiom Aggregation 1 Circuit](#axiom-aggregation-1-circuit). It is essentially a passthrough circuit, but we also add a `payee` public instance (this is to prevent transaction frontrunning in the mempool).

# Circuit Public IO Formats

We start from circuits that touch the smart contract and work back towards dependencies.

## Axiom Aggregation 2 (final, for EVM)

This is the snark that will be verified by a fixed verifier on EVM.

### Public IO

The public IO is given by:

- `accumulator` (384 bytes)
- `sourceChainId` (uint64, in F)
- `computeResultsHash` (bytes32, in hi-lo)
- `queryHash` (bytes32, in hi-lo)
- `querySchema` (bytes32, in hi-lo)
- `blockhashMMRKeccak` (bytes32, in hi-lo)
- `aggVkeyHash` (bytes32, in F)
- `payee` (address, in F)
  (It doesn't save any EVM keccaks to hash these all together in-circuit, so we can keep multiple public instances.)

This will be a fixed `AggregationCircuit` with `Universality::Full` that can verify any circuit with a fixed config. The fixed config will be that of another `AggregationCircuit` (aka single phase `BaseCircuitParams`). We call the previous circuit the final EVM verifies the `AxiomAggregation1Circuit`.

- The `AxiomAggregation2Circuit` will just pass through public instances of the `AxiomAggregation1Circuit` it is verifying **and add a payee instance**.
- It also computes a new `aggVkeyHash` using `AxiomAggregation1Circuit.aggVkeyHash` and the `k, preprocessed_digest` of `AxiomAggregation1Circuit` itself.
- The `k` and selectors of this `AxiomAggregation2Circuit` must be fixed - our on-chain verifier does not allow universality.
- `AxiomAggregation2Circuit` will be configured to use few columns for cheapest on-chain verification.

## Axiom Aggregation 1 Circuit

### Public IO

This is the same as the [Public IO of Axiom Aggregation 2](#axiom-aggregation-2-final-for-evm) except there is **no payee field**.

- `accumulator` (384 bytes)
- `sourceChainId` (uint64, in F)
- `computeResultsHash` (bytes32, in hi-lo)
- `queryHash` (bytes32, in hi-lo)
- `querySchema` (bytes32, in hi-lo)
- `blockhashMMRKeccak` (bytes32, in hi-lo)
- `aggVkeyHash` (bytes32, in F)

This is an `AggregationCircuit` with `Universality::Full`

- `k` and selectors can be variable: this means we can have multiple `ControllerAggregationCircuit`s (I guess this makes this a trait)
  - Any such circuit can do anything that only requires `BaseCircuitBuilder`, in particular it can verify an arbitrary fixed number of snarks
  - But it cannot do dynamic lookups (requires new columns), or RLC (unless we decide to add a fixed number of RLC columns to be supported)
- Ideally proof generation takes <10s on g5.48xl

This circuit will aggregate:

- `VerifyComputeCircuit`
- `SubqueryAggregationCircuit`
- `KeccakFinalAggregationCircuit`

The `AxiomAggregation2` and `AxiomAggregation1` circuits could be combined if we had a universal verifier in EVM (such as [here](https://github.com/han0110/halo2-solidity-verifier/tree/feature/solidity-generator)), but previous experience says that the `AxiomAggregation1` circuit is large enough that two layers of aggregation is faster than one big layer anyways.

## Verify Compute Circuit

### Public IO

- [not used] Component managed `output_commit` (F) which should be ignored since this circuit has no virtual output
- `promiseCommitment` (F) - in this case this is `poseidon(promiseKeccakComponent)`
- `accumulator` (384 bytes)
- `sourceChainId` (uint64, in F)
- `computeResultsHash` (bytes32, in hi-lo)
- `queryHash` (bytes32, in hi-lo)
- `querySchema` (bytes32, in hi-lo)
- `resultsRootPoseidon` (F)
- `promiseSubqueryHashes` (F)

Does the following:

- Verify the compute snark.
  - The `k` and vkey of the snark is committed to in `queryHash`. Therefore we do not have any other (Poseidon) `aggVkeyHash` since this is the only snark we're aggregating.
- Compute `dataQueryHash` from `subqueryHashes`
- Compute `queryHash` from `dataQueryHash` and `computeQuery`
- Compute `querySchema`
- Compute `computeResultsHash`
  - Requires looking up compute subqueries in data results with **dynamic lookup**

Depends on external commitment to computations done in the `ResultsRoot` circuit, which computes the actual subquery results and subquery hashes.

We separate the calculation of query hash into this circuit and not into the circuits that are aggregated by `SubqueryAggregationCircuit` below because the final `queryHash` calculation cannot be parallelized, whereas we could in the future parallelize everything in `SubqueryAggregationCircuit` into multiple data shards.

## Subquery Aggregation Circuit

We can have multiple implementations of these, and each can be literally any circuit - no limitations on number of columns, gates, lookups, etc. This provides us a lot of flexibility, and allows us to add new variants later on without changing `FinalVerifier` and `ControllerAggregationCircuit`.

### Public IO

- `accumulator` (384 bytes)
- `promiseKeccakComponent` (F) is the re-exposed keccak component promise commit from previous aggregated component snarks
- `aggVkeyHash` (F)
- `resultsRootPoseidon` (F)
- `commitSubqueryHashes` (F)
- `blockhashMMRKeccak` (bytes32, in hi-lo)

The `SubqueryAggregationCircuit` will:

- Aggregate the following circuits (for each type it may either be the shard circuit or the [Merkle Aggregation Circuit](#merkle-aggregation-circuit) of circuits of that type):
  - ResultsRoot
  - Header
  - Account
  - Storage
  - Tx
  - Receipt
  - Solidity
- Constrain equalities of data component commits between component "calls".
- Constrain the keccak component promise in each aggregated component is equal, and then re-expose this promise as a public instance

## Results Root Component Circuit

### Public IO

- [not used] Component managed `output_commit`. This component has no virtual table as output, and should not be called directly.
- `promiseComponentsCommit` (F) - poseidon hash of all promises, including keccak
- `resultsRootPoseidon` (F)
- `commitSubqueryHashes` (F)

`commitSubqueryHashes` is the Poseidon commitment to a _variable number_ `numSubqueries` of keccak subquery hashes. We choose to do a variable length Poseidon for more flexibility so the total subquery capacity in this circuit does not have to match the `userMaxSubqueries` in the `VerifyCompute` circuit. As a consequence, this `commitSubqueryHashes` also commits to `numSubqueries`.

## Header Component Circuit

### Public IO

- `commitHeaderComponent` (F)
- `promiseCommitment` (F)
- `blockhashMMRKeccak` (bytes32, in hi-lo)

## Account Component Circuit

### Public IO

- `commitAccountComponent` (F)
- `promiseCommitment` (F)

## Storage Component Circuit

### Public IO

- `commitStorageComponent` (F)
- `promiseCommitment` (F)

## Transaction Component Circuit

### Public IO

- `commitTxComponent` (F)
- `promiseCommitment` (F)

## Receipt Component Circuit

### Public IO

- `commitReceiptComponent` (F)
- `promiseCommitment` (F)

## Solidity Component Circuit

### Public IO

- `commitSolidityComponent` (F)
- `promiseCommitment` (F)

## Keccak Component Shard Circuit

### Public IO

- `keccakComponentCommit` (F)

## Merkle Aggregation Circuit

Above we have specified the public IO of component **shard** circuits. We will have multiple configurations where we use the MerkleAggregationCircuit to aggregate multiple shard circuits of the same component type into a new MerkleAggregationCircuit.

The public IO of the new MerkleAggregationCircuit will consist of the `accumulator` (384 bytes), followed by the exact same instance format as the shard circuit. The output commit is now a Merkle root of shard output commits. The promise commitments of all shards are constrained to be equal.

# Reference Diagram

The following diagram is for reference only. The exact configuration and number of circuits will depend on the aggregation configuration used.

![diagram](https://lucid.app/publicSegments/view/bcfc1a84-c274-4f1d-a747-898ca1ec07f5/image.png)
