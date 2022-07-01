use std::{fmt::Debug, ops::Deref};

use axiom_components::ecdsa::ECDSAComponentInput;
use serde::{Deserialize, Serialize};

use crate::{
    constants::{MAX_SOLIDITY_MAPPING_KEYS, MAX_SUBQUERY_INPUTS, MAX_SUBQUERY_OUTPUTS},
    Field, HiLo,
};

use super::native::SubqueryType;

pub const SUBQUERY_KEY_LEN: usize = 1 + MAX_SUBQUERY_INPUTS;
pub const SUBQUERY_RESULT_LEN: usize = SUBQUERY_KEY_LEN + MAX_SUBQUERY_OUTPUTS;

/// Subquery type and data
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubqueryKey<T>(pub [T; SUBQUERY_KEY_LEN]);

/// Only the output of the subquery. Does not include subquery data.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubqueryOutput<T>(pub [T; MAX_SUBQUERY_OUTPUTS]);

impl<T> Deref for SubqueryKey<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Deref for SubqueryOutput<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlattenedSubqueryResult<T> {
    pub key: SubqueryKey<T>,
    pub value: SubqueryOutput<T>,
}

impl<T> FlattenedSubqueryResult<T> {
    pub fn new(key: SubqueryKey<T>, value: SubqueryOutput<T>) -> Self {
        Self { key, value }
    }
}

impl<T: Clone> FlattenedSubqueryResult<T> {
    pub fn flatten(&self) -> [T; SUBQUERY_RESULT_LEN] {
        self.to_fixed_array()
    }

    pub fn to_fixed_array(&self) -> [T; SUBQUERY_RESULT_LEN] {
        [&self.key.0[..], &self.value.0[..]].concat().try_into().unwrap_or_else(|_| unreachable!())
    }
}

/// You should probably use [FlattenedSubqueryResult] instead.
#[derive(Clone, Copy, Debug)]
pub struct FieldSubqueryResult<F: Field> {
    pub subquery: FieldSubquery<F>,
    pub value: SubqueryOutput<F>,
}

impl<F: Field> FieldSubqueryResult<F> {
    pub fn flatten(self) -> FlattenedSubqueryResult<F> {
        FlattenedSubqueryResult { key: self.subquery.flatten(), value: self.value }
    }
    pub fn to_fixed_array(self) -> [F; SUBQUERY_RESULT_LEN] {
        self.flatten().to_fixed_array()
    }
}

impl<F: Field> From<FieldSubqueryResult<F>> for FlattenedSubqueryResult<F> {
    fn from(value: FieldSubqueryResult<F>) -> Self {
        value.flatten()
    }
}

impl<F: Field> From<FieldSubquery<F>> for SubqueryKey<F> {
    fn from(subquery: FieldSubquery<F>) -> Self {
        let mut key = [F::ZERO; 1 + MAX_SUBQUERY_INPUTS];
        key[0] = F::from(subquery.subquery_type as u64);
        key[1..].copy_from_slice(&subquery.encoded_subquery_data);
        Self(key)
    }
}

/// Subquery resized to fixed length. For ZK use.
/// Consider using [SubqueryKey] instead.
#[derive(Clone, Copy, Debug)]
pub struct FieldSubquery<T> {
    pub subquery_type: SubqueryType,
    pub encoded_subquery_data: [T; MAX_SUBQUERY_INPUTS],
}

impl<F: Field> FieldSubquery<F> {
    pub fn flatten(&self) -> SubqueryKey<F> {
        let mut key = [F::ZERO; SUBQUERY_KEY_LEN];
        key[0] = F::from(self.subquery_type as u64);
        key[1..].copy_from_slice(&self.encoded_subquery_data);
        SubqueryKey(key)
    }
}

// unpacked for now
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldHeaderSubquery<T> {
    pub block_number: T,
    pub field_idx: T,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldAccountSubquery<T> {
    pub block_number: T,
    pub addr: T, // F::CAPACITY >= 160
    pub field_idx: T,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldStorageSubquery<T> {
    pub block_number: T,
    pub addr: T, // F::CAPACITY >= 160
    pub slot: HiLo<T>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldTxSubquery<T> {
    pub block_number: T,
    pub tx_idx: T,
    pub field_or_calldata_idx: T,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldReceiptSubquery<T> {
    pub block_number: T,
    pub tx_idx: T,
    pub field_or_log_idx: T,
    pub topic_or_data_or_address_idx: T,
    pub event_schema: HiLo<T>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldSolidityNestedMappingSubquery<T> {
    pub block_number: T,
    pub addr: T, // F::CAPACITY >= 160
    pub mapping_slot: HiLo<T>,
    pub mapping_depth: T,
    pub keys: [HiLo<T>; MAX_SOLIDITY_MAPPING_KEYS],
}

/// A result consists of a pair of the original subquery and the output value.
/// This type is just a pair, but has nicer JSON serialization.
#[derive(Clone, Copy, Debug, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnySubqueryResult<S, T> {
    pub subquery: S,
    pub value: T,
}

impl<S, T> AnySubqueryResult<S, T> {
    pub fn new(subquery: S, value: T) -> Self {
        Self { subquery, value }
    }
}

pub type FieldHeaderSubqueryResult<T> = AnySubqueryResult<FieldHeaderSubquery<T>, HiLo<T>>;
pub type FieldAccountSubqueryResult<T> = AnySubqueryResult<FieldAccountSubquery<T>, HiLo<T>>;
pub type FieldStorageSubqueryResult<T> = AnySubqueryResult<FieldStorageSubquery<T>, HiLo<T>>;
pub type FieldTxSubqueryResult<T> = AnySubqueryResult<FieldTxSubquery<T>, HiLo<T>>;
pub type FieldReceiptSubqueryResult<T> = AnySubqueryResult<FieldReceiptSubquery<T>, HiLo<T>>;
pub type FieldSolidityNestedMappingSubqueryResult<T> =
    AnySubqueryResult<FieldSolidityNestedMappingSubquery<T>, HiLo<T>>;
pub type FieldECDSASubqueryResult<T> = AnySubqueryResult<ECDSAComponentInput<T>, T>;
