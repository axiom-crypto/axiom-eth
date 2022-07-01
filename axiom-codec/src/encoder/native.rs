use std::{
    io::{Error, ErrorKind, Result, Write},
    iter,
};

use axiom_components::ecdsa::ECDSAComponentNativeInput;
use byteorder::{BigEndian, WriteBytesExt};
use ethers_core::{types::H256, utils::keccak256};

use crate::{
    constants::USER_PROOF_LEN_BYTES,
    types::native::{
        AccountSubquery, AnySubquery, AxiomV2ComputeQuery, AxiomV2ComputeSnark, AxiomV2DataQuery,
        HeaderSubquery, ReceiptSubquery, SolidityNestedMappingSubquery, StorageSubquery, Subquery,
        SubqueryResult, SubqueryType, TxSubquery,
    },
    utils::writer::{write_curve_compressed, write_field_be, write_u256},
    VERSION,
};

pub fn get_query_hash_v2(
    source_chain_id: u64,
    data_query: &AxiomV2DataQuery,
    compute_query: &AxiomV2ComputeQuery,
) -> Result<H256> {
    if source_chain_id != data_query.source_chain_id {
        return Err(Error::new(ErrorKind::InvalidInput, "source_chain_id mismatch"));
    }
    let data_query_hash = data_query.keccak();
    let encoded_compute_query = compute_query.encode()?;

    let mut encoded = vec![];
    encoded.write_u8(VERSION)?;
    encoded.write_u64::<BigEndian>(source_chain_id)?;
    encoded.write_all(data_query_hash.as_bytes())?;
    encoded.write_all(&encoded_compute_query)?;
    Ok(H256(keccak256(encoded)))
}

impl AxiomV2ComputeQuery {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.k == 0 {
            return Ok([&[0u8], &self.result_len.to_be_bytes()[..]].concat());
        }
        let encoded_query_schema = encode_query_schema(self.k, self.result_len, &self.vkey)?;
        let proof_len = self.compute_proof.len() as u32;
        let encoded_proof_len = proof_len.to_be_bytes();
        assert_eq!(encoded_proof_len.len(), USER_PROOF_LEN_BYTES);
        let encoded_compute_proof = [&encoded_proof_len[..], &self.compute_proof].concat();
        Ok([encoded_query_schema, encoded_compute_proof].concat())
    }

    pub fn keccak(&self) -> Result<H256> {
        Ok(H256(keccak256(self.encode()?)))
    }
}

impl AxiomV2ComputeSnark {
    /// Encoded `kzg_accumulator` (is any) followed by `compute_results`.
    pub fn encode_instances(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        if let Some((lhs, rhs)) = self.kzg_accumulator {
            write_curve_compressed(&mut encoded, lhs)?;
            write_curve_compressed(&mut encoded, rhs)?;
        } else {
            encoded = vec![0u8; 64];
        }
        for &output in &self.compute_results {
            encoded.write_all(&output[..])?;
        }
        Ok(encoded)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoded = self.encode_instances()?;
        encoded.write_all(&self.proof_transcript)?;
        Ok(encoded)
    }
}

impl AxiomV2DataQuery {
    pub fn keccak(&self) -> H256 {
        get_data_query_hash(self.source_chain_id, &self.subqueries)
    }
}

pub fn get_data_query_hash(source_chain_id: u64, subqueries: &[Subquery]) -> H256 {
    let subquery_hashes = subqueries.iter().flat_map(|subquery| subquery.keccak().0);
    let encoded: Vec<_> =
        iter::empty().chain(source_chain_id.to_be_bytes()).chain(subquery_hashes).collect();
    H256(keccak256(encoded))
}

pub fn get_query_schema_hash(k: u8, result_len: u16, vkey: &[H256]) -> Result<H256> {
    if k == 0 {
        return Ok(H256::zero());
    }
    let encoded_query_schema = encode_query_schema(k, result_len, vkey)?;
    Ok(H256(keccak256(encoded_query_schema)))
}

pub fn encode_query_schema(k: u8, result_len: u16, vkey: &[H256]) -> Result<Vec<u8>> {
    if k >= 28 {
        return Err(Error::new(ErrorKind::InvalidInput, "k must be less than 28"));
    }
    if k == 0 {
        unreachable!()
    }
    let mut encoded = Vec::with_capacity(3 + vkey.len() * 32);
    encoded.write_u8(k)?;
    encoded.write_u16::<BigEndian>(result_len)?;
    let vkey_len: u8 = vkey
        .len()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "vkey len exceeds u8"))?;
    encoded.write_u8(vkey_len)?;
    for fe in vkey {
        encoded.write_all(fe.as_bytes())?;
    }
    Ok(encoded)
}

impl Subquery {
    pub fn encode(&self) -> Vec<u8> {
        let sub_type = (self.subquery_type as u16).to_be_bytes();
        let subquery_data = self.encoded_subquery_data.as_ref();
        [&sub_type[..], subquery_data].concat()
    }
    pub fn keccak(&self) -> H256 {
        H256(keccak256(self.encode()))
    }
}

impl SubqueryResult {
    pub fn encode(&self) -> Vec<u8> {
        let subquery = self.subquery.encode();
        let value = self.value.as_ref();
        [&subquery[..], value].concat()
    }
    pub fn keccak(&self) -> H256 {
        H256(keccak256(self.encode()))
    }
}

pub fn encode_header_subquery(writer: &mut impl Write, subquery: HeaderSubquery) -> Result<()> {
    let HeaderSubquery { block_number, field_idx } = subquery;
    writer.write_u32::<BigEndian>(block_number)?;
    writer.write_u32::<BigEndian>(field_idx)?;
    Ok(())
}

pub fn encode_account_subquery(writer: &mut impl Write, subquery: AccountSubquery) -> Result<()> {
    let AccountSubquery { block_number, addr, field_idx } = subquery;
    writer.write_u32::<BigEndian>(block_number)?;
    writer.write_all(&addr[..])?;
    writer.write_u32::<BigEndian>(field_idx)?;
    Ok(())
}

pub fn encode_storage_subquery(writer: &mut impl Write, subquery: StorageSubquery) -> Result<()> {
    let StorageSubquery { block_number, addr, slot } = subquery;
    writer.write_u32::<BigEndian>(block_number)?;
    writer.write_all(&addr[..])?;
    write_u256(writer, slot)?;
    Ok(())
}

pub fn encode_tx_subquery(writer: &mut impl Write, subquery: TxSubquery) -> Result<()> {
    let TxSubquery { block_number, tx_idx, field_or_calldata_idx } = subquery;
    writer.write_u32::<BigEndian>(block_number)?;
    writer.write_u16::<BigEndian>(tx_idx)?;
    writer.write_u32::<BigEndian>(field_or_calldata_idx)?;
    Ok(())
}

pub fn encode_receipt_subquery(writer: &mut impl Write, subquery: ReceiptSubquery) -> Result<()> {
    let ReceiptSubquery {
        block_number,
        tx_idx,
        field_or_log_idx,
        topic_or_data_or_address_idx,
        event_schema,
    } = subquery;
    writer.write_u32::<BigEndian>(block_number)?;
    writer.write_u16::<BigEndian>(tx_idx)?;
    writer.write_u32::<BigEndian>(field_or_log_idx)?;
    writer.write_u32::<BigEndian>(topic_or_data_or_address_idx)?;
    writer.write_all(&event_schema[..])?;
    Ok(())
}

pub fn encode_solidity_nested_mapping_subquery(
    writer: &mut impl Write,
    subquery: SolidityNestedMappingSubquery,
) -> Result<()> {
    let SolidityNestedMappingSubquery { block_number, addr, mapping_slot, mapping_depth, mut keys } =
        subquery;
    writer.write_u32::<BigEndian>(block_number)?;
    writer.write_all(&addr[..])?;
    write_u256(writer, mapping_slot)?;
    writer.write_u8(mapping_depth)?;
    keys.resize(mapping_depth as usize, H256::zero());
    for key in keys {
        writer.write_all(&key[..])?;
    }
    Ok(())
}

pub fn encode_ecdsa_component_native_input(
    writer: &mut impl Write,
    input: ECDSAComponentNativeInput,
) -> Result<()> {
    let ECDSAComponentNativeInput { pubkey, r, s, msg_hash } = input;
    write_field_be(writer, pubkey.0)?;
    write_field_be(writer, pubkey.1)?;
    write_field_be(writer, r)?;
    write_field_be(writer, s)?;
    writer.write_all(&msg_hash[..])?;
    Ok(())
}

impl From<HeaderSubquery> for Subquery {
    fn from(value: HeaderSubquery) -> Self {
        let mut bytes = vec![];
        encode_header_subquery(&mut bytes, value).unwrap();
        Self { subquery_type: SubqueryType::Header, encoded_subquery_data: bytes.into() }
    }
}

impl From<AccountSubquery> for Subquery {
    fn from(value: AccountSubquery) -> Self {
        let mut bytes = vec![];
        encode_account_subquery(&mut bytes, value).unwrap();
        Self { subquery_type: SubqueryType::Account, encoded_subquery_data: bytes.into() }
    }
}

impl From<StorageSubquery> for Subquery {
    fn from(value: StorageSubquery) -> Self {
        let mut bytes = vec![];
        encode_storage_subquery(&mut bytes, value).unwrap();
        Self { subquery_type: SubqueryType::Storage, encoded_subquery_data: bytes.into() }
    }
}

impl From<TxSubquery> for Subquery {
    fn from(value: TxSubquery) -> Self {
        let mut bytes = vec![];
        encode_tx_subquery(&mut bytes, value).unwrap();
        Self { subquery_type: SubqueryType::Transaction, encoded_subquery_data: bytes.into() }
    }
}

impl From<ReceiptSubquery> for Subquery {
    fn from(value: ReceiptSubquery) -> Self {
        let mut bytes = vec![];
        encode_receipt_subquery(&mut bytes, value).unwrap();
        Self { subquery_type: SubqueryType::Receipt, encoded_subquery_data: bytes.into() }
    }
}

impl From<SolidityNestedMappingSubquery> for Subquery {
    fn from(value: SolidityNestedMappingSubquery) -> Self {
        let mut bytes = vec![];
        encode_solidity_nested_mapping_subquery(&mut bytes, value).unwrap();
        Self {
            subquery_type: SubqueryType::SolidityNestedMapping,
            encoded_subquery_data: bytes.into(),
        }
    }
}

impl From<ECDSAComponentNativeInput> for Subquery {
    fn from(value: ECDSAComponentNativeInput) -> Self {
        let mut bytes = vec![];
        encode_ecdsa_component_native_input(&mut bytes, value).unwrap();
        Self { subquery_type: SubqueryType::ECDSA, encoded_subquery_data: bytes.into() }
    }
}

impl From<AnySubquery> for Subquery {
    fn from(value: AnySubquery) -> Self {
        match value {
            AnySubquery::Null => {
                Self { subquery_type: SubqueryType::Null, encoded_subquery_data: vec![].into() }
            }
            AnySubquery::Header(subquery) => subquery.into(),
            AnySubquery::Account(subquery) => subquery.into(),
            AnySubquery::Storage(subquery) => subquery.into(),
            AnySubquery::Transaction(subquery) => subquery.into(),
            AnySubquery::Receipt(subquery) => subquery.into(),
            AnySubquery::SolidityNestedMapping(subquery) => subquery.into(),
            AnySubquery::ECDSA(subquery) => subquery.into(),
        }
    }
}

impl From<HeaderSubquery> for AnySubquery {
    fn from(value: HeaderSubquery) -> Self {
        AnySubquery::Header(value)
    }
}
impl From<AccountSubquery> for AnySubquery {
    fn from(value: AccountSubquery) -> Self {
        AnySubquery::Account(value)
    }
}
impl From<StorageSubquery> for AnySubquery {
    fn from(value: StorageSubquery) -> Self {
        AnySubquery::Storage(value)
    }
}
impl From<TxSubquery> for AnySubquery {
    fn from(value: TxSubquery) -> Self {
        AnySubquery::Transaction(value)
    }
}
impl From<ReceiptSubquery> for AnySubquery {
    fn from(value: ReceiptSubquery) -> Self {
        AnySubquery::Receipt(value)
    }
}
impl From<SolidityNestedMappingSubquery> for AnySubquery {
    fn from(value: SolidityNestedMappingSubquery) -> Self {
        AnySubquery::SolidityNestedMapping(value)
    }
}

impl From<ECDSAComponentNativeInput> for AnySubquery {
    fn from(value: ECDSAComponentNativeInput) -> Self {
        AnySubquery::ECDSA(value)
    }
}
