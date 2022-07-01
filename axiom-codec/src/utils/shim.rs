use axiom_eth::{impl_flatten_conversion, impl_logical_input, Field};

use crate::{
    encoder::field_elements::{
        BITS_PER_FE_ACCOUNT, BITS_PER_FE_HEADER, BITS_PER_FE_RECEIPT,
        BITS_PER_FE_SOLIDITY_NESTED_MAPPING, BITS_PER_FE_STORAGE, BITS_PER_FE_SUBQUERY_RESULT,
        BITS_PER_FE_TX,
    },
    types::field_elements::{
        FieldAccountSubquery, FieldHeaderSubquery, FieldReceiptSubquery,
        FieldSolidityNestedMappingSubquery, FieldStorageSubquery, FieldTxSubquery,
        FlattenedSubqueryResult,
    },
};

// Inputs by subquery type, in field elements
impl_flatten_conversion!(FieldHeaderSubquery, BITS_PER_FE_HEADER);
impl_logical_input!(FieldHeaderSubquery, 1);
impl_flatten_conversion!(FieldAccountSubquery, BITS_PER_FE_ACCOUNT);
impl_logical_input!(FieldAccountSubquery, 1);
impl_flatten_conversion!(FieldStorageSubquery, BITS_PER_FE_STORAGE);
impl_logical_input!(FieldStorageSubquery, 1);
impl_flatten_conversion!(FieldTxSubquery, BITS_PER_FE_TX);
impl_logical_input!(FieldTxSubquery, 1);
impl_flatten_conversion!(FieldReceiptSubquery, BITS_PER_FE_RECEIPT);
impl_logical_input!(FieldReceiptSubquery, 1);
impl_flatten_conversion!(FieldSolidityNestedMappingSubquery, BITS_PER_FE_SOLIDITY_NESTED_MAPPING);
impl_logical_input!(FieldSolidityNestedMappingSubquery, 1);
impl_flatten_conversion!(FlattenedSubqueryResult, BITS_PER_FE_SUBQUERY_RESULT);
impl_logical_input!(FlattenedSubqueryResult, 0);
