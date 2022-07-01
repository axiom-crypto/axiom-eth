use std::io::{self, Read, Result};

use axiom_eth::halo2curves::bn256::G1Affine;
use byteorder::{BigEndian, ReadBytesExt};
use ethers_core::types::Bytes;

use crate::{
    constants::MAX_SOLIDITY_MAPPING_KEYS,
    types::native::{
        AccountSubquery, AnySubquery, AxiomV2ComputeSnark, HeaderSubquery, ReceiptSubquery,
        SolidityNestedMappingSubquery, StorageSubquery, Subquery, SubqueryType, TxSubquery,
    },
    utils::reader::{read_address, read_curve_compressed, read_h256, read_u256},
};

impl TryFrom<Subquery> for AnySubquery {
    type Error = io::Error;

    fn try_from(subquery: Subquery) -> Result<Self> {
        let mut reader = &subquery.encoded_subquery_data[..];
        let subquery_type = subquery.subquery_type;
        Ok(match subquery_type {
            SubqueryType::Null => AnySubquery::Null,
            SubqueryType::Header => AnySubquery::Header(decode_header_subquery(&mut reader)?),
            SubqueryType::Account => AnySubquery::Account(decode_account_subquery(&mut reader)?),
            SubqueryType::Storage => AnySubquery::Storage(decode_storage_subquery(&mut reader)?),
            SubqueryType::Transaction => AnySubquery::Transaction(decode_tx_subquery(&mut reader)?),
            SubqueryType::Receipt => AnySubquery::Receipt(decode_receipt_subquery(&mut reader)?),
            SubqueryType::SolidityNestedMapping => AnySubquery::SolidityNestedMapping(
                decode_solidity_nested_mapping_subquery(&mut reader)?,
            ),
        })
    }
}

impl TryFrom<u16> for SubqueryType {
    type Error = io::Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::Null),
            1 => Ok(Self::Header),
            2 => Ok(Self::Account),
            3 => Ok(Self::Storage),
            4 => Ok(Self::Transaction),
            5 => Ok(Self::Receipt),
            6 => Ok(Self::SolidityNestedMapping),
            // 7 => Ok(Self::BeaconValidator),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SubqueryType")),
        }
    }
}

/// Decoder from `compute_proof` in bytes into `AxiomV2ComputeSnark`.
/// `reader` should be a reader on `compute_proof` in `AxiomV2ComputeQuery`.
pub fn decode_compute_snark(
    mut reader: impl Read,
    result_len: u16,
    is_aggregation: bool,
) -> Result<AxiomV2ComputeSnark> {
    let kzg_accumulator = if is_aggregation {
        let lhs = read_curve_compressed::<G1Affine>(&mut reader)?;
        let rhs = read_curve_compressed::<G1Affine>(&mut reader)?;
        Some((lhs, rhs))
    } else {
        read_h256(&mut reader)?;
        read_h256(&mut reader)?;
        None
    };
    let mut compute_results = Vec::with_capacity(result_len as usize);
    for _ in 0..result_len {
        compute_results.push(read_h256(&mut reader)?);
    }
    let mut proof_transcript = vec![];
    reader.read_to_end(&mut proof_transcript)?;
    Ok(AxiomV2ComputeSnark { kzg_accumulator, compute_results, proof_transcript })
}

pub fn decode_subquery(mut reader: impl Read) -> Result<AnySubquery> {
    let subquery_type = reader.read_u16::<BigEndian>()?;
    let subquery_type = subquery_type.try_into()?;
    let mut buf = vec![];
    reader.read_to_end(&mut buf)?;
    let encoded_subquery_data = Bytes::from(buf);
    let subquery = Subquery { subquery_type, encoded_subquery_data };
    subquery.try_into()
}

pub fn decode_header_subquery(mut reader: impl Read) -> Result<HeaderSubquery> {
    let block_number = reader.read_u32::<BigEndian>()?;
    let field_idx = reader.read_u32::<BigEndian>()?;
    Ok(HeaderSubquery { block_number, field_idx })
}

pub fn decode_account_subquery(mut reader: impl Read) -> Result<AccountSubquery> {
    let block_number = reader.read_u32::<BigEndian>()?;
    let addr = read_address(&mut reader)?;
    let field_idx = reader.read_u32::<BigEndian>()?;
    Ok(AccountSubquery { block_number, addr, field_idx })
}

pub fn decode_storage_subquery(mut reader: impl Read) -> Result<StorageSubquery> {
    let block_number = reader.read_u32::<BigEndian>()?;
    let addr = read_address(&mut reader)?;
    let slot = read_u256(&mut reader)?;
    Ok(StorageSubquery { block_number, addr, slot })
}

pub fn decode_tx_subquery(mut reader: impl Read) -> Result<TxSubquery> {
    let block_number = reader.read_u32::<BigEndian>()?;
    let tx_idx = reader.read_u16::<BigEndian>()?;
    let field_or_calldata_idx = reader.read_u32::<BigEndian>()?;
    Ok(TxSubquery { block_number, tx_idx, field_or_calldata_idx })
}

pub fn decode_receipt_subquery(mut reader: impl Read) -> Result<ReceiptSubquery> {
    let block_number = reader.read_u32::<BigEndian>()?;
    let tx_idx = reader.read_u16::<BigEndian>()?;
    let field_or_log_idx = reader.read_u32::<BigEndian>()?;
    let topic_or_data_or_address_idx = reader.read_u32::<BigEndian>()?;
    let event_schema = read_h256(&mut reader)?;
    Ok(ReceiptSubquery {
        block_number,
        tx_idx,
        field_or_log_idx,
        topic_or_data_or_address_idx,
        event_schema,
    })
}

pub fn decode_solidity_nested_mapping_subquery(
    mut reader: impl Read,
) -> Result<SolidityNestedMappingSubquery> {
    let block_number = reader.read_u32::<BigEndian>()?;
    let addr = read_address(&mut reader)?;
    let mapping_slot = read_u256(&mut reader)?;
    let mapping_depth = reader.read_u8()?;
    if mapping_depth as usize > MAX_SOLIDITY_MAPPING_KEYS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SolidityNestedMappingSubquery mapping_depth {} exceeds MAX_SOLIDITY_MAPPING_KEYS {}",
                mapping_depth, MAX_SOLIDITY_MAPPING_KEYS
            ),
        ));
    }
    let mut keys = Vec::with_capacity(mapping_depth as usize);
    for _ in 0..mapping_depth {
        keys.push(read_h256(&mut reader)?);
    }
    Ok(SolidityNestedMappingSubquery { block_number, addr, mapping_slot, mapping_depth, keys })
}
