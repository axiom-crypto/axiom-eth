# Axiom ZK Circuits

This repository builds on [halo2-lib](https://github.com/axiom-crypto/halo2-lib/tree/main) and [snark-verifier](https://github.com/axiom-crypto/snark-verifier/) to create a library of zero-knowledge proof circuits that [Axiom](https://axiom.xyz) uses to read data from the Ethereum virtual machine (EVM).

This monorepo consists of multiple crates:

## `axiom-eth`

This is the main library of chips and frameworks for building ZK circuits that prove data from the Ethereum virtual machine (EVM). For more details, see the [README](./axiom-eth/README.md).

## `axiom-core`

This contains the ZK circuits that generate proofs for the `AxiomV2Core` smart contract. These circuits read the RLP encoded block headers for a chain of blocks and verify that the block headers form a chain. They output a Merkle Mountain Range of the block hashes of the chain. This crate also contains aggregation circuits to aggregate multiple circuits for the purpose of proving longer chains. For more details, see the [README](./axiom-core/README.md).

## `axiom-query`

This contains the ZK circuits that generate proofs for the `AxiomV2Query` smart contract. For more details, see the [README](./axiom-query/README.md).

### `axiom-codec`

This crate does not contain any ZK circuits, but it contains Rust types for Axiom queries and specifies how to encode/decode them to field elements for in-circuit use.
