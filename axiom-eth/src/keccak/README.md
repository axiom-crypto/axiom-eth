# Keccak Chip

This module provides adapters and trait implementations to enable the [`KeccakComponentShardCircuit`](https://github.com/axiom-crypto/halo2-lib/tree/main/hashes/zkevm/src/keccak) to fall under the [Component Framework](../utils/README.md).

The keccak component circuit outputs a virtual table of `(key, value)` pairs where `key` is of type `Vec<u8>` and `value` is of type `H256`. We represent the `H256` in hi-lo form as two field elements. The complication is in the `key`, which is a variable length byte array of possibly arbitrary length.
To handle this in ZK, we must instead encode `(key,value)` as a different virtual table with fixed length keys but where a single logical `(key,value)` can take up multiple rows in the new fixed length key table.

For keccak, the format of the fixed length key table is specified in [zkEVM hashes](https://github.com/axiom-crypto/halo2-lib/tree/main/hashes/zkevm/src/keccak).
What is provided in the [promise](./promise.rs) submodule is a way to perform promise calls into the keccak component circuit.
Promise calls are done as follows: the caller circuit loaded the fixed length key virtual table as private witnesses and computes the commitment to the table to exactly match the output commitment computation of the keccak component circuit.
Then it creates a raw Halo2 table where it RLCs the entries of the fixed length key table in a way that encodes the variable lengths.
Finally for each keccak promise call, the variable length input bytes are first packed into field elements in a way that matches the packing done in the virtual table. Then the packed field elements are RLCed together with the variable length. This RLC value is dynamically looked up against the raw Halo2 table to verify the promise call.
