/*!
# Receipt Subqueries Circuit

Receipt
* Raw EVM receipt layout reference: <https://hackmd.io/@axiom/H1TYkiBt2>
* `blockNumber` (uint32)
* `txIdx` (uint16)
* `fieldOrLogIdx` (uint32)
    * If in `[0, 4)` -- refers to the field.
        * If the `fieldIdx = 3` corresponds to `logsBloom`, the `result` will be only the first 32 bytes.  We will add a special `LOGS_BLOOM_FIELD_IDX` (70) so that if `fieldIdx = LOGS_BLOOM_FIELD_IDX + logsBloomIdx`, the result will be bytes `[32 * logsBloomIdx, 32 * logsBloomIdx + 32)` for `logsBloomIdx` in `[0, 8)`.
        * The `fieldIdx` is defined as an enum:
            | ReceiptField           | `fieldIdx` |
            |------------------------|-------|
            | Status                 | 0     |
            | PostState              | 1     |
            | CumulativeGas          | 2     |
            | LogsBloom              | 3     |
            | Logs                   | 4     |
    * If in `[100, infty)` -- represents `100 + logIdx`
    * As with Transaction, we will have a special `RECEIPT_TX_TYPE_FIELD_IDX` (51) for transaction type, `RECEIPT_BLOCK_NUMBER_FIELD_IDX` (52) for block number, and `RECEIPT_TX_IDX_FIELD_IDX` (53) for transaction index.
    * [Nice to have **(not yet supported)**] We will later add a special `RECEIPT_TX_HASH_FIELD_IDX` (54) for the transaction hash.
* `topicOrDataOrAddressIdx` (uint32)
    * If in `[0, 4)` -- refers to the topic.
    * If equal to `50` -- refers to the address.
    * If in `[100, infty)` -- represents `100 + dataIdx`, where for a given value of `dataIdx` we return bytes `[32 * dataIdx, 32 * dataIdx + 32)` of the data.  This byte alignment is to return chunks of the ABI encoding.
* `eventSchema` (bytes32) -- Either `bytes32(0x0)` in which case it is a no-op, or the query **must** have `fieldOrLogIdx` in `[100, infty)` and constrains `topic[0]` of the log to equal `eventSchema`.

*/

/// Circuit and Component Implementation.
pub mod circuit;
/// Types
pub mod types;

#[cfg(test)]
pub mod tests;

const DUMMY_LOG: [u8; 4] = [0xc3, 0x80, 0xc0, 0x80];
