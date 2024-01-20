use axiom_eth::halo2curves::bn256::G1Affine;
use ethers_core::types::{Address, Bytes, H256, U256};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct AxiomV2ComputeQuery {
    pub k: u8,
    pub result_len: u16,
    // Should be bytes32[]
    /// The onchain vkey
    pub vkey: Vec<H256>,
    /// This is actually the concatenation of public instances and proof transcript
    pub compute_proof: Bytes,
}

#[derive(Clone, Debug)]
pub struct AxiomV2ComputeSnark {
    /// (lhs G1 of pairing, rhs G1 of pairing) if this snark is from an aggregation circuit.
    pub kzg_accumulator: Option<(G1Affine, G1Affine)>,
    pub compute_results: Vec<H256>,
    pub proof_transcript: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct AxiomV2DataQuery {
    pub source_chain_id: u64,
    pub subqueries: Vec<Subquery>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SubqueryResult {
    pub subquery: Subquery,
    /// The output of the subquery. In V2, always bytes32.
    pub value: Bytes,
}

impl Default for SubqueryResult {
    fn default() -> Self {
        Self { subquery: Subquery::default(), value: Bytes::from([0u8; 32]) }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Subquery {
    /// uint16 type of subquery
    pub subquery_type: SubqueryType,
    /// Subquery data encoded, _without_ the subquery type. Length is variable and **not** resized.
    pub encoded_subquery_data: Bytes,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Serialize_repr,
    Deserialize_repr,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[repr(u16)]
pub enum SubqueryType {
    #[default]
    Null = 0, // For lookup tables, important to have a null type
    Header = 1,
    Account = 2,
    Storage = 3,
    Transaction = 4,
    Receipt = 5,
    SolidityNestedMapping = 6,
    // BeaconValidator = 7,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnySubquery {
    Null,
    Header(HeaderSubquery),
    Account(AccountSubquery),
    Storage(StorageSubquery),
    Transaction(TxSubquery),
    Receipt(ReceiptSubquery),
    SolidityNestedMapping(SolidityNestedMappingSubquery),
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct HeaderSubquery {
    pub block_number: u32,
    pub field_idx: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct AccountSubquery {
    pub block_number: u32,
    pub addr: Address,
    pub field_idx: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct StorageSubquery {
    pub block_number: u32,
    pub addr: Address,
    pub slot: U256,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct TxSubquery {
    /// The block number with the requested transaction.
    pub block_number: u32,
    /// The index of the transaction in the block.
    pub tx_idx: u16,
    /// Special index to specify what subquery value to extract from the transaction.
    pub field_or_calldata_idx: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptSubquery {
    /// The block number with the requested transaction.
    pub block_number: u32,
    /// The index of the transaction in the block.
    pub tx_idx: u16,
    /// Special index to specify what subquery value to extract from the transaction.
    pub field_or_log_idx: u32,
    pub topic_or_data_or_address_idx: u32,
    pub event_schema: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct SolidityNestedMappingSubquery {
    pub block_number: u32,
    pub addr: Address,
    pub mapping_slot: U256,
    /// Should be equal to `keys.len()`
    pub mapping_depth: u8,
    pub keys: Vec<H256>,
}
