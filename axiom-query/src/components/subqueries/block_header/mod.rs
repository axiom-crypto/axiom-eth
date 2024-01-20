//! # Block Header Subqueries Circuit
//!
//! | Block Header Field        | Max bytes     |
//! |---------------------------|---------------|
//! | parentHash                | 32            |
//! | ommersHash                | 32            |
//! | beneficiary               | 20            |
//! | stateRoot                 | 32            |
//! | transactionsRoot          | 32            |
//! | receiptsRoot              | 32            |
//! | logsBloom                 | 256           |
//! | difficulty                | ≤7            |
//! | number                    | ≤4            |
//! | gasLimit                  | ≤4            |
//! | gasUsed                   | ≤4            |
//! | timestamp                 | ≤4            |
//! | extraData                 | ≤32 (mainnet) |
//! | mixHash                   | 32            |
//! | nonce                     | 8             |
//! | basefee (post-1559)       | ≤32 or 0      |
//! | withdrawalsRoot (post-4895) | 32 or 0     |
//!
//! Header subquery
//! - `blockNumber` (uint32)
//! - `fieldIdx` (uint32)
//! - If the `fieldIdx` corresponds to `logsBloom`,
//!   the `result` will be only the first 32 bytes.
//!   We will add a special `LOGS_BLOOM_FIELD_IDX` so that if
//!   `fieldIdx = LOGS_BLOOM_FIELD_IDX + logsBloomIdx`,
//!   the result will be bytes `[32 * logsBloomIdx, 32 * logsBloomIdx + 32)`
//!   for `logsBloomIdx` in `[0, 8)`.
//!
//! **Note:** We will always truncate `extraData` to 32 bytes
//! (for Goerli `extraData` can be longer, but we ignore the extra bytes).

/// Circuit and Component Implementation.
pub mod circuit;
/// Verify all block hashes against a given Merkle Mountain Range. Used in [circuit]
pub mod mmr_verify;
/// Types
pub mod types;

#[cfg(test)]
pub mod tests;

pub const MMR_MAX_NUM_PEAKS: usize = 32; // assuming block number stays in u32, < 2^32
