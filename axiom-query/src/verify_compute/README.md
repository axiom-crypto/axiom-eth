# Verify Compute Circuit

## Query Schema

The Verify Compute circuit is an `AggregationCircuit` with `VerifierUniverality::Full` that verifies a user supplied `compute_snark`.
Unlike internal universal aggregation circuits that hash part of the verifying key of the aggregated snark into `aggVkeyHash`, here we uniquely tag the verifying key of
`compute_snark` by calculating a `query_schema` inside the Verify Compute circuit and exposing it as a public output.

In the Axiom V2 Query protocol, we will use _different_ Verify Compute circuits in different aggregation strategies. The guarantee is that:

> If a `compute_snark` is verified by the Axiom V2 Query protocol, then its `query_schema` is a **unique** identifier for the circuit that was used to create the `compute_snark`.

We explain below how this guarantee is achieved.

### Background

The `halo2` [`VerifyingKey`](https://github.com/axiom-crypto/halo2/blob/f335ffc4440620e3afaa5ba3373764b60a528c51/halo2_proofs/src/plonk.rs#L47) contains the full context of a concrete circuit and the `halo2` proof protocol ensures that if a proof verifies against a `VerifyingKey` and a trusted setup, then the proof is valid precisely for the concrete circuit the `VerifyingKey` was constructed from. This is what is used when you verify a proof directly in Rust using `halo2`.

The `snark-verifier` crate re-formats the `VerifyingKey` struct into the [`PlonkProtocol`](https://github.com/axiom-crypto/snark-verifier/blob/5c5791fb27c48b004c93d5a4e168f971d4350ce5/snark-verifier/src/verifier/plonk/protocol.rs#L54) struct using the [`compile`](https://github.com/axiom-crypto/snark-verifier/blob/5c5791fb27c48b004c93d5a4e168f971d4350ce5/snark-verifier/src/system/halo2.rs#L82) function. This struct still contains the full context of the circuit used to generate a proof and is all that is needed to verify a proof.

An aggregation circuit created using `snark-verifier-sdk` will verify a given snark against its `PlonkProtocol`, but defer the final pairing check in the KZG opening by RLC-ing the `G1Affine` points in the pairing check into a running `KzgAccumulator`, which is added to the public instances of the aggregation circuit. Only the final EVM or Rust native verifier will read these `G1Affine` points from the public instances and do the final pairing check.

In a plain aggregation circuit with `VerifierUniversality::None`, all parts of the `PlonkProtocol` are loaded as constants in the aggregation circuit. In an aggregation circuit with `VerifierUniversality::Full`, the following parts of `PlonkProtocol` are loaded as witnesses:

- the `log_2` domain size `k`
- the transcript initial state (optional starting value of the transcript)
- the `preprocessed` commitments to the fixed columns and commitment to the permutation argument (sigma polynomials)

Even with `VerifierUniversality::Full`, the following properties of the `PlonkProtocol` of the snark(s) to be aggregated are hard-coded into the aggregation circuit, meaning they are loaded either explicitly or implicitly as constants and changes to these parameters determine different aggregation circuits:

- the number of instance columns and number of instances per column
- the number of challenges and number of challenge phases
- the number of advice columns (in each phase)
- the custom gates used by the circuit
- whether the snark to be aggregated has a `KzgAccumulator` in its public instances that needs a deferred pairing check, and if so, what public instance indices they are located at

Here is the `PlonkProtocol` struct in full:

```rust
pub struct PlonkProtocol<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    // Loaded as witnesses in `Universality::Full`:
    /// Working domain.
    pub domain: Domain<C::Scalar>,
    /// Prover and verifier common initial state to write to transcript if any.
    pub transcript_initial_state: Option<L::LoadedScalar>,
    /// Commitments of preprocessed polynomials.
    pub preprocessed: Vec<L::LoadedEcPoint>,

    // Always loaded as constants:
    /// Number of instances in each instance polynomial.
    pub num_instance: Vec<usize>,
    /// Number of witness polynomials in each phase.
    pub num_witness: Vec<usize>,
    /// Number of challenges to squeeze from transcript after each phase.
    pub num_challenge: Vec<usize>,
    /// Evaluations to read from transcript.
    pub evaluations: Vec<Query>,
    /// [`crate::pcs::PolynomialCommitmentScheme`] queries to verify.
    pub queries: Vec<Query>,
    /// Structure of quotient polynomial.
    pub quotient: QuotientPolynomial<C::Scalar>,
    /// Instance polynomials committing key if any.
    pub instance_committing_key: Option<InstanceCommittingKey<C>>,
    /// Linearization strategy.
    pub linearization: Option<LinearizationStrategy>,
    /// Indices (instance polynomial index, row) of encoded accumulators
    pub accumulator_indices: Vec<Vec<(usize, usize)>>,
}
```

In our use cases the `instance_committing_key` and `linearization` are always `None` so we do not discuss them.

### Encoded Query Schema

We define

```javascript
encoded_query_schema = solidityPacked(
  ["uint8", "uint16", "uint8", "bytes32", "bytes32[]"],
  [k, result_len, onchain_vkey_len, onchain_vkey]
);

query_schema = keccak(encoded_query_schema);
```

where `k` is the `log_2` size of the domain (number of rows in the circuit), `result_len` is the length of `compute_results` in the public instances of `compute_snark`, where `onchain_vkey_len = onchain_vkey.len()` for `onchain_vkey: bytes32[]`.

We will define `onchain_vkey` so that it is a serialization of `PlonkProtocol` **under the assumption** that the `PlonkProtocol` is from a circuit created using a `halo2-base` `BaseCircuitBuilder` or `axiom-eth` `RlcCircuitBuilder`, where the circuit _may_ be an aggregation circuit. This `onchain_vkey` is submitted on-chain as calldata as part of a `sendQuery` call, so it is designed to be the minimal context required to reconstruct the `PlonkProtocol` of the `compute_snark` to be verified.

We define the `onchain_vkey: bytes32[]` as the concatenation of the following fields:

- `encoded_circuit_metadata: bytes32` - this is loaded as a constant (see below)
- `transcript_initial_state: bytes32` (`Fr`) - this is loaded as a witness
- `preprocessed: bytes32[]` (`Vec<G1Compressed>`) - this is loaded as a witness

The parts of `PlonkProtocol` that are loaded as witnesses in the Verify Compute circuit are all included in the `encoded_query_schema`. We now explain how the constant parts are accounted for.

We define `encoded_circuit_metadata` as an encoding into a `bytes32` of:

- `version: u8` - a reserved byte for versioning in case `halo2-base` or `halo2` changes
- `num_instance: Vec<usize>`
- `RlcCircuitParams` except `k`
- `is_aggregation: bool`

This encoding is done outside of the circuit, and the encoded `bytes32` is loaded _as a constant_ in the Verify Compute circuit. This can be done because all variables that are encoded are constant in the circuit.
To ensure that what is encoded in `encoded_circuit_metadata` indeed matches what is used in the Verify Compute circuit, we generate the `PlonkProtocol` from the `encoded_circuit_metadata` and the provided `compute_snark` itself.

Explicitly, `encoded_circuit_metadata` will be a packing of the following struct into a `bytes32`:

```rust
pub struct AxiomV2CircuitMetadata {
    /// Version byte for domain separation on version of Axiom client, halo2-lib, snark-verifier.
    /// If `version = x`, this should be thought of as Axiom Query v2.x
    pub version: u8,
    /// Number of instances in each instance polynomial
    pub num_instance: Vec<u32>,
    /// Number of challenges to squeeze from transcript after each phase.
    pub num_challenge: Vec<u8>,

    /// Boolean for whether this is an Aggregation Circuit which has a KZG accumulator in the public instances. If true, it must be the first 12 instances.
    pub is_aggregation: bool,

    // RlcCircuitParams:
    /// The number of advice columns per phase
    pub num_advice_per_phase: Vec<u16>,
    /// The number of special advice columns that have range lookup enabled per phase
    pub num_lookup_advice_per_phase: Vec<u8>,
    /// Number of advice columns for the RLC custom gate
    pub num_rlc_columns: u16,
    /// The number of fixed columns
    pub num_fixed: u8,

    // This is specific to the current Verify Compute Circuit implementation and provided just for data availability:
    /// The maximum number of user outputs. Used to determine where to split off `compute_snark`'s public instances between user outputs and data subqueries.
    /// This does **not** include the old accumulator elliptic curve points if
    /// the `compute_snark` is from an aggregation circuit.
    pub user_max_outputs: usize,
}
```

The actual encoding is defined [here](../utils/client_circuit/metadata.rs).

> The Axiom V2 Query protocol will only create Verify Compute circuits that verify snarks created using `RlcCircuitBuilder` or `BaseCircuitBuilder`, where the circuits _may_ be aggregation circuits.

This can be checked by inspection of the circuits used in production.

Given this, the `encoded_query_schema` contains all information needed to reconstruct `PlonkProtocol`. Therefore `query_schema` is a unique identifier for `PlonkProtocol` and hence the circuit that `compute_snark` came from.

## Query Hash

The Verify Compute Circuit also computes the commitment to the entire query by calculating

```javascript
query_hash = keccak(encoded_query);
encoded_query = solidityPacked(
  ["uint8", "uint64", "bytes32", "bytes"],
  [version, source_chain_id, data_query_hash, encoded_compute_query]
);
encoded_compute_query = solidityPacked(
  ["bytes", "uint32", "bytes"],
  [encoded_query_schema, proof_len, compute_proof]
);
```

where `proof_len = compute_proof.len()` in bytes and

```javascript
compute_proof = solidityPacked(
  ["bytes32[2]", "bytes32[]", "bytes"],
  [compute_accumulator, compute_results, compute_proof_transcript]
);
```

where

- `compute_accumulator` is either `[bytes32(0), bytes32(0)]` if there is no accumulator, or `[lhs, rhs]` where `lhs, rhs` are compressed `G1Affine` points as `bytes32` representing the KZG accumulator,
- `compute_results` are the public instances of the `compute_snark`, converted from hi-lo form to `bytes32`, that cannot be recovered from data subqueries. The length of `compute_results` equals `result_len`.
- `compute_proof_transcript` is the actual `Vec<u8>` halo2 proof.

## Data Query Format

Each data query consists of the fields:

```rust
pub struct AxiomV2DataQuery {
    pub source_chain_id: u64,
    pub subqueries: Vec<Subquery>,
}
```

and each subquery consists of the fields:

```rust
pub struct Subquery {
    /// uint16 type of subquery
    pub subquery_type: SubqueryType,
    /// Subquery data encoded, _without_ the subquery type. Length is variable and **not** resized.
    pub encoded_subquery_data: Bytes,
}
```

where `SubqueryType` is an enum represented as `uint16`.

We commit to the data query by:

- `dataQueryHash` (bytes32): The Keccak hash of `sourceChainId` concatenated with the array with entries given by:
  - `subquery_hash = keccak(solidityPacked(["uint16", "bytes"], [subquery_type, encoded_subquery_data])`

The individual `subquery_hash`s are already computed by the [Results Root Circuit](../components/results/), so
the Verify Compute Circuit just concatenates them all and computes `keccak` of the concatenation.
