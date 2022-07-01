use std::io;

use ethers_core::types::{Bytes, H256};

use crate::{
    constants::*,
    types::field_elements::*,
    types::native::*,
    utils::native::{encode_addr_to_field, encode_h256_to_hilo, encode_u256_to_hilo},
    Field,
};

pub const NUM_FE_HEADER: usize = 2;
pub const NUM_FE_ACCOUNT: usize = 3;
pub const NUM_FE_STORAGE: usize = 4;
pub const NUM_FE_TX: usize = 3;
pub const NUM_FE_RECEIPT: usize = 6;
pub const NUM_FE_SOLIDITY_NESTED_MAPPING: usize =
    NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS + MAX_SOLIDITY_MAPPING_KEYS * 2;
pub const NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS: usize = 5;
pub const NUM_FE_SOLIDITY_NESTED_MAPPING_MIN: usize = 7; // assumes >=1 key
pub const NUM_FE_ANY: [usize; NUM_SUBQUERY_TYPES] = [
    0,
    NUM_FE_HEADER,
    NUM_FE_ACCOUNT,
    NUM_FE_STORAGE,
    NUM_FE_TX,
    NUM_FE_RECEIPT,
    NUM_FE_SOLIDITY_NESTED_MAPPING,
];

/// The index of the mapping depth in [`FieldSolidityNestedMappingSubquery`].
pub const FIELD_SOLIDITY_NESTED_MAPPING_DEPTH_IDX: usize = 4;
/// The index of the mapping depth in [`SubqueryKey`], where the first index holds the subquery type.
pub const FIELD_ENCODED_SOLIDITY_NESTED_MAPPING_DEPTH_IDX: usize =
    FIELD_SOLIDITY_NESTED_MAPPING_DEPTH_IDX + 1;

// The following constants describe how to convert from the field element
// encoding into the bytes encoding, by specifying the fixed width bytes each field
// element represented (in big endian order).
pub const BYTES_PER_FE_HEADER: [usize; NUM_FE_HEADER] = [4, 4];
pub const BITS_PER_FE_HEADER: [usize; NUM_FE_HEADER] = [32, 32];
pub const BYTES_PER_FE_ACCOUNT: [usize; NUM_FE_ACCOUNT] = [4, 20, 4];
pub const BITS_PER_FE_ACCOUNT: [usize; NUM_FE_ACCOUNT] = [32, 160, 32];
pub const BYTES_PER_FE_STORAGE: [usize; NUM_FE_STORAGE] = [4, 20, 16, 16];
pub const BITS_PER_FE_STORAGE: [usize; NUM_FE_STORAGE] = [32, 160, 128, 128];
pub const BYTES_PER_FE_TX: [usize; NUM_FE_TX] = [4, 2, 4];
pub const BITS_PER_FE_TX: [usize; NUM_FE_TX] = [32, 16, 32];
pub const BYTES_PER_FE_RECEIPT: [usize; NUM_FE_RECEIPT] = [4, 2, 4, 4, 16, 16];
pub const BITS_PER_FE_RECEIPT: [usize; NUM_FE_RECEIPT] = [32, 16, 32, 32, 128, 128];
pub const BYTES_PER_FE_SOLIDITY_NESTED_MAPPING: [usize; NUM_FE_SOLIDITY_NESTED_MAPPING] =
    bytes_per_fe_solidity_nested_mapping();
pub const BITS_PER_FE_SOLIDITY_NESTED_MAPPING: [usize; NUM_FE_SOLIDITY_NESTED_MAPPING] =
    bits_per_fe_solidity_nested_mapping();
pub const BYTES_PER_FE_ANY: [&[usize]; NUM_SUBQUERY_TYPES] = [
    &[],
    &BYTES_PER_FE_HEADER,
    &BYTES_PER_FE_ACCOUNT,
    &BYTES_PER_FE_STORAGE,
    &BYTES_PER_FE_TX,
    &BYTES_PER_FE_RECEIPT,
    &BYTES_PER_FE_SOLIDITY_NESTED_MAPPING,
];
pub const BYTES_PER_FE_SUBQUERY_OUTPUT: usize = 16;

pub const BITS_PER_FE_SUBQUERY_RESULT: [usize; SUBQUERY_RESULT_LEN] = [128; SUBQUERY_RESULT_LEN];
pub const SUBQUERY_OUTPUT_BYTES: usize = MAX_SUBQUERY_OUTPUTS * BYTES_PER_FE_SUBQUERY_OUTPUT;

const fn bytes_per_fe_solidity_nested_mapping() -> [usize; NUM_FE_SOLIDITY_NESTED_MAPPING] {
    let mut bytes_per = [16; MAX_SUBQUERY_INPUTS];
    bytes_per[0] = 4;
    bytes_per[1] = 20;
    bytes_per[2] = 16;
    bytes_per[3] = 16;
    bytes_per[4] = 1;
    bytes_per
}
const fn bits_per_fe_solidity_nested_mapping() -> [usize; NUM_FE_SOLIDITY_NESTED_MAPPING] {
    let mut bits_per = [128; MAX_SUBQUERY_INPUTS];
    bits_per[0] = 32;
    bits_per[1] = 160;
    bits_per[2] = 128;
    bits_per[3] = 128;
    bits_per[4] = 8;
    bits_per
}

pub const BITS_PER_FE_SUBQUERY_OUTPUT: usize = BYTES_PER_FE_SUBQUERY_OUTPUT * 8;

impl<F: Field> From<H256> for SubqueryOutput<F> {
    fn from(value: H256) -> Self {
        let mut output = [F::ZERO; MAX_SUBQUERY_OUTPUTS];
        let hilo = encode_h256_to_hilo(&value);
        output[0] = hilo.hi();
        output[1] = hilo.lo();
        Self(output)
    }
}

impl<F: Field> TryFrom<Bytes> for SubqueryOutput<F> {
    type Error = io::Error;
    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            Err(io::Error::new(io::ErrorKind::InvalidData, "result length is not 32"))
        } else {
            let result = H256::from_slice(&bytes[..]);
            let hilo = encode_h256_to_hilo(&result);
            let mut result = [F::ZERO; MAX_SUBQUERY_OUTPUTS];
            result[0] = hilo.hi();
            result[1] = hilo.lo();
            Ok(Self(result))
        }
    }
}

impl<F: Field> TryFrom<SubqueryResult> for FlattenedSubqueryResult<F> {
    type Error = io::Error;
    fn try_from(result: SubqueryResult) -> Result<Self, Self::Error> {
        let result: FieldSubqueryResult<F> = result.try_into()?;
        Ok(result.into())
    }
}

impl<F: Field> TryFrom<SubqueryResult> for FieldSubqueryResult<F> {
    type Error = io::Error;
    fn try_from(result: SubqueryResult) -> Result<Self, Self::Error> {
        let subquery = result.subquery.try_into()?;
        let value = result.value.try_into()?;
        Ok(FieldSubqueryResult { subquery, value })
    }
}

impl<F: Field> TryFrom<Subquery> for FieldSubquery<F> {
    type Error = io::Error;
    fn try_from(subquery: Subquery) -> Result<Self, Self::Error> {
        let subquery = AnySubquery::try_from(subquery)?;
        Ok(subquery.into())
    }
}

impl<F: Field> From<AnySubquery> for FieldSubquery<F> {
    fn from(subquery: AnySubquery) -> Self {
        match subquery {
            AnySubquery::Null => FieldSubquery {
                subquery_type: SubqueryType::Null,
                encoded_subquery_data: Default::default(),
            },
            AnySubquery::Header(subquery) => FieldHeaderSubquery::from(subquery).into(),
            AnySubquery::Account(subquery) => FieldAccountSubquery::from(subquery).into(),
            AnySubquery::Storage(subquery) => FieldStorageSubquery::from(subquery).into(),
            AnySubquery::Transaction(subquery) => FieldTxSubquery::from(subquery).into(),
            AnySubquery::Receipt(subquery) => FieldReceiptSubquery::from(subquery).into(),
            AnySubquery::SolidityNestedMapping(subquery) => {
                FieldSolidityNestedMappingSubquery::from(subquery).into()
            }
        }
    }
}

impl<F: Field> From<HeaderSubquery> for FieldHeaderSubquery<F> {
    fn from(subquery: HeaderSubquery) -> Self {
        Self {
            block_number: F::from(subquery.block_number as u64),
            field_idx: F::from(subquery.field_idx as u64),
        }
    }
}

impl<T> FieldHeaderSubquery<T> {
    pub fn flatten(self) -> [T; NUM_FE_HEADER] {
        [self.block_number, self.field_idx]
    }
}

impl<F: Field> From<FieldHeaderSubquery<F>> for FieldSubquery<F> {
    fn from(subquery: FieldHeaderSubquery<F>) -> Self {
        let mut encoded_subquery_data = [F::ZERO; MAX_SUBQUERY_INPUTS];
        encoded_subquery_data[..NUM_FE_HEADER].copy_from_slice(&subquery.flatten());
        Self { subquery_type: SubqueryType::Header, encoded_subquery_data }
    }
}

impl<F: Field> From<AccountSubquery> for FieldAccountSubquery<F> {
    fn from(subquery: AccountSubquery) -> Self {
        Self {
            block_number: F::from(subquery.block_number as u64),
            addr: encode_addr_to_field(&subquery.addr),
            field_idx: F::from(subquery.field_idx as u64),
        }
    }
}

impl<T> FieldAccountSubquery<T> {
    pub fn flatten(self) -> [T; NUM_FE_ACCOUNT] {
        [self.block_number, self.addr, self.field_idx]
    }
}

impl<F: Field> From<FieldAccountSubquery<F>> for FieldSubquery<F> {
    fn from(value: FieldAccountSubquery<F>) -> Self {
        let mut encoded_subquery_data = [F::ZERO; MAX_SUBQUERY_INPUTS];
        encoded_subquery_data[..NUM_FE_ACCOUNT].copy_from_slice(&value.flatten());
        Self { subquery_type: SubqueryType::Account, encoded_subquery_data }
    }
}

impl<F: Field> From<StorageSubquery> for FieldStorageSubquery<F> {
    fn from(subquery: StorageSubquery) -> Self {
        Self {
            block_number: F::from(subquery.block_number as u64),
            addr: encode_addr_to_field(&subquery.addr),
            slot: encode_u256_to_hilo(&subquery.slot),
        }
    }
}

impl<T: Copy> FieldStorageSubquery<T> {
    pub fn flatten(self) -> [T; NUM_FE_STORAGE] {
        [self.block_number, self.addr, self.slot.hi(), self.slot.lo()]
    }
}

impl<F: Field> From<FieldStorageSubquery<F>> for FieldSubquery<F> {
    fn from(value: FieldStorageSubquery<F>) -> Self {
        let mut encoded_subquery_data = [F::ZERO; MAX_SUBQUERY_INPUTS];
        encoded_subquery_data[..NUM_FE_STORAGE].copy_from_slice(&value.flatten());
        Self { subquery_type: SubqueryType::Storage, encoded_subquery_data }
    }
}

impl<F: Field> From<TxSubquery> for FieldTxSubquery<F> {
    fn from(subquery: TxSubquery) -> Self {
        Self {
            block_number: F::from(subquery.block_number as u64),
            tx_idx: F::from(subquery.tx_idx as u64),
            field_or_calldata_idx: F::from(subquery.field_or_calldata_idx as u64),
        }
    }
}

impl<T> FieldTxSubquery<T> {
    pub fn flatten(self) -> [T; NUM_FE_TX] {
        [self.block_number, self.tx_idx, self.field_or_calldata_idx]
    }
}

impl<F: Field> From<FieldTxSubquery<F>> for FieldSubquery<F> {
    fn from(value: FieldTxSubquery<F>) -> Self {
        let mut encoded_subquery_data = [F::ZERO; MAX_SUBQUERY_INPUTS];
        encoded_subquery_data[..NUM_FE_TX].copy_from_slice(&value.flatten());
        Self { subquery_type: SubqueryType::Transaction, encoded_subquery_data }
    }
}

impl<F: Field> From<ReceiptSubquery> for FieldReceiptSubquery<F> {
    fn from(subquery: ReceiptSubquery) -> Self {
        Self {
            block_number: F::from(subquery.block_number as u64),
            tx_idx: F::from(subquery.tx_idx as u64),
            field_or_log_idx: F::from(subquery.field_or_log_idx as u64),
            topic_or_data_or_address_idx: F::from(subquery.topic_or_data_or_address_idx as u64),
            event_schema: encode_h256_to_hilo(&subquery.event_schema),
        }
    }
}

impl<T: Copy> FieldReceiptSubquery<T> {
    pub fn flatten(self) -> [T; NUM_FE_RECEIPT] {
        [
            self.block_number,
            self.tx_idx,
            self.field_or_log_idx,
            self.topic_or_data_or_address_idx,
            self.event_schema.hi(),
            self.event_schema.lo(),
        ]
    }
}

impl<F: Field> From<FieldReceiptSubquery<F>> for FieldSubquery<F> {
    fn from(value: FieldReceiptSubquery<F>) -> Self {
        let mut encoded_subquery_data = [F::ZERO; MAX_SUBQUERY_INPUTS];
        encoded_subquery_data[..NUM_FE_RECEIPT].copy_from_slice(&value.flatten());
        Self { subquery_type: SubqueryType::Receipt, encoded_subquery_data }
    }
}

impl<F: Field> From<SolidityNestedMappingSubquery> for FieldSolidityNestedMappingSubquery<F> {
    fn from(mut subquery: SolidityNestedMappingSubquery) -> Self {
        assert!(subquery.keys.len() <= MAX_SOLIDITY_MAPPING_KEYS);
        subquery.keys.resize(MAX_SOLIDITY_MAPPING_KEYS, H256::zero());

        Self {
            block_number: F::from(subquery.block_number as u64),
            addr: encode_addr_to_field(&subquery.addr),
            mapping_slot: encode_u256_to_hilo(&subquery.mapping_slot),
            mapping_depth: F::from(subquery.mapping_depth as u64),
            keys: subquery
                .keys
                .iter()
                .map(|k| encode_h256_to_hilo(k))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }
}

impl<T: Copy> FieldSolidityNestedMappingSubquery<T> {
    pub fn flatten(self) -> [T; NUM_FE_SOLIDITY_NESTED_MAPPING] {
        assert_eq!(5 + self.keys.len() * 2, NUM_FE_SOLIDITY_NESTED_MAPPING);
        let mut result = [self.block_number; NUM_FE_SOLIDITY_NESTED_MAPPING]; // default will be overwritten in all indices so doesn't matter
        result[0] = self.block_number;
        result[1] = self.addr;
        result[2] = self.mapping_slot.hi();
        result[3] = self.mapping_slot.lo();
        result[4] = self.mapping_depth;
        for (i, key) in self.keys.iter().enumerate() {
            result[5 + i * 2] = key.hi();
            result[5 + i * 2 + 1] = key.lo();
        }
        result
    }
}

impl<F: Field> From<FieldSolidityNestedMappingSubquery<F>> for FieldSubquery<F> {
    fn from(value: FieldSolidityNestedMappingSubquery<F>) -> Self {
        let mut encoded_subquery_data = [F::ZERO; MAX_SUBQUERY_INPUTS];
        encoded_subquery_data[..NUM_FE_SOLIDITY_NESTED_MAPPING].copy_from_slice(&value.flatten());
        Self { subquery_type: SubqueryType::SolidityNestedMapping, encoded_subquery_data }
    }
}
