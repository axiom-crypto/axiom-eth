/*!
# Transaction Subqueries Circuit

Transaction subquery
* Raw EVM transaction layout reference: <https://hackmd.io/VJKKTZJaR3CmAKR_8o5vsA>
* `blockNumber` (uint32)
* `txIdx` (uint16)
* `fieldOrCalldataIdx` (uint32)
    * If in `[0, 100)` -- refers to the `fieldIdx` (**see below for definition**)
    * If in `[100, infty)` -- represents `100 + calldataIdx`, where for a given value of `calldataIdx`, we return bytes `[4 + 32 * calldataIdx, 4 + 32 * calldataIdx + 32)`. This byte alignment is to return chunks of the ABI encoding.
    * If in `[100000, infty)` -- represents `100000 + contractDataIdx`, where for a given value of `contractDataIdx`, we return bytes`[32 * contractDataIdx, 32 * contractDataIdx + 32)`
    * Should be indexed so that the same `fieldIdx` represents the same thing across transaction types.
    * We will add a special `TX_TYPE_FIELD_IDX` (51) for the transaction type.
    * We will add a special `BLOCK_NUMBER_FIELD_IDX` (52) for the block number.
    * We will add a special `TX_IDX_FIELD_IDX` (53) for the transaction index.
    * We will add a special `FUNCTION_SELECTOR_FIELD_IDX` (54) for the function selector, which will return either the function selector (first 4 bytes of calldata) or one of 2 special values:
        * If it’s a pure EOA transfer, then it will return `NO_CALLDATA_SELECTOR` (bytes32(61)).
        * If it’s a contract deploy transaction, it will return `CONTRACT_DEPLOY_SELECTOR` (bytes32(60))
    * The `CALLDATA_FIELD_IDX` (55) corresponding to calldata will return the Keccak hash of the calldata.
    * We will exclude access to access lists in V2.
    * [Nice to have **(not yet supported)**] We will later add a special `TX_TX_HASH_FIELD_IDX` (56) for the transaction hash.

The `fieldIdx` is defined as an enum that is **independent of transaction type**:

| TxField                | `fieldIdx` |
|------------------------|-------|
| ChainId                | 0     |
| Nonce                  | 1     |
| MaxPriorityFeePerGas   | 2     |
| MaxFeePerGas           | 3     |
| GasLimit               | 4     |
| To                     | 5     |
| Value                  | 6     |
| Data                   | 7     |
| GasPrice               | 8     |
| v                      | 9     |
| r                      | 10    |
| s                      | 11    |

This numbering is chosen so that for a Type 2 (EIP-1559) Transaction, the `fieldIdx` corresponds to the index of the field in the RLP list representing the transaction, with the exception that `accessList` at `fieldIdx = 8`  is disabled in V2. For other transaction types, we still use the table above to determine the `fieldIdx` corresponding to a transaction field, and the ZK circuit will re-map to the correct RLP list index.
*/

/// Circuit and Component Implementation.
pub mod circuit;
/// Types
pub mod types;

#[cfg(test)]
pub mod tests;

/// The `fieldIdx` corresponding to the `data` field in a transaction. Note this definition is _independent_
/// of the transaction type -- it is specific to the subquery spec.
const TX_DATA_FIELD_IDX: usize = 7;
