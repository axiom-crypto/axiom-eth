use std::io::{Error, ErrorKind, Result};

use crate::{
    constants::MAX_SOLIDITY_MAPPING_KEYS,
    encoder::field_elements::{
        NUM_FE_SOLIDITY_NESTED_MAPPING, NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS,
    },
    types::field_elements::{
        FieldAccountSubquery, FieldHeaderSubquery, FieldReceiptSubquery,
        FieldSolidityNestedMappingSubquery, FieldStorageSubquery, FieldTxSubquery,
        FlattenedSubqueryResult, SubqueryKey, SubqueryOutput, SUBQUERY_KEY_LEN,
        SUBQUERY_RESULT_LEN,
    },
    HiLo,
};

impl<T> TryFrom<Vec<T>> for FlattenedSubqueryResult<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self> {
        if value.len() != SUBQUERY_RESULT_LEN {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid array length"));
        }
        let mut key = value;
        let value = key.split_off(SUBQUERY_KEY_LEN);
        let key = key.try_into().map_err(|_| Error::other("should never happen"))?;
        let value = value.try_into().map_err(|_| Error::other("should never happen"))?;
        Ok(Self { key: SubqueryKey(key), value: SubqueryOutput(value) })
    }
}

impl<T> TryFrom<Vec<T>> for FieldHeaderSubquery<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self> {
        let [block_number, field_idx] = value
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid array length"))?;
        Ok(Self { block_number, field_idx })
    }
}

impl<T> TryFrom<Vec<T>> for FieldAccountSubquery<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self> {
        let [block_number, addr, field_idx] = value
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid array length"))?;
        Ok(Self { block_number, addr, field_idx })
    }
}

impl<T> TryFrom<Vec<T>> for FieldStorageSubquery<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self> {
        let [block_number, addr, slot_hi, slot_lo] = value
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid array length"))?;
        Ok(Self { block_number, addr, slot: HiLo::from_hi_lo([slot_hi, slot_lo]) })
    }
}

impl<T> TryFrom<Vec<T>> for FieldTxSubquery<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self> {
        let [block_number, tx_idx, field_or_calldata_idx] = value
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid array length"))?;
        Ok(Self { block_number, tx_idx, field_or_calldata_idx })
    }
}

impl<T> TryFrom<Vec<T>> for FieldReceiptSubquery<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self> {
        let [block_number, tx_idx, field_or_log_idx, topic_or_data_or_address_idx, event_schema_hi, event_schema_lo] =
            value
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid array length"))?;
        Ok(Self {
            block_number,
            tx_idx,
            field_or_log_idx,
            topic_or_data_or_address_idx,
            event_schema: HiLo::from_hi_lo([event_schema_hi, event_schema_lo]),
        })
    }
}

impl<T> TryFrom<Vec<T>> for FieldSolidityNestedMappingSubquery<T> {
    type Error = Error;

    fn try_from(mut value: Vec<T>) -> Result<Self> {
        if value.len() != NUM_FE_SOLIDITY_NESTED_MAPPING {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid array length"));
        }
        let keys = value.split_off(NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS);
        let [block_number, addr, slot_hi, slot_lo, mapping_depth] =
            value.try_into().map_err(|_| Error::other("should never happen"))?;
        let mut keys_iter = keys.into_iter();
        let keys: Vec<_> = (0..MAX_SOLIDITY_MAPPING_KEYS)
            .map(|_| {
                let key_hi = keys_iter.next().unwrap();
                let key_lo = keys_iter.next().unwrap();
                HiLo::from_hi_lo([key_hi, key_lo])
            })
            .collect();
        Ok(Self {
            block_number,
            addr,
            mapping_slot: HiLo::from_hi_lo([slot_hi, slot_lo]),
            mapping_depth,
            keys: keys.try_into().map_err(|_| Error::other("max keys wrong length"))?,
        })
    }
}
