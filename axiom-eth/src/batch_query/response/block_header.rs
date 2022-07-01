//! Block Header Response
use std::cell::RefCell;

use super::{mmr_verify::verify_mmr_proof, *};
use crate::{
    batch_query::{
        hash::{
            bytes_select_or_zero, keccak_packed, poseidon_packed, poseidon_tree_root,
            word_select_or_zero, OptPoseidonWords, POSEIDON_EMPTY_ROOTS,
        },
        DummyEccChip, EccInstructions,
    },
    block_header::{
        assign_vec, get_block_header_rlp_max_lens, EthBlockHeaderChip, EthBlockHeaderTraceWitness,
        BLOCK_HEADER_FIELD_IS_VAR_LEN, BLOCK_NUMBER_INDEX, EXTRA_DATA_INDEX,
        MIN_NUM_BLOCK_HEADER_FIELDS, NUM_BLOCK_HEADER_FIELDS,
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::FIRST_PHASE,
        RlpChip,
    },
    util::{bytes_be_to_u128, is_zero_vec, load_bool},
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, Network, ETH_LOOKUP_BITS,
};
use ethers_core::types::{Block, H256};
#[cfg(feature = "providers")]
use ethers_providers::{JsonRpcClient, Provider};
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::G1Affine,
    utils::{bit_length, ScalarField},
    Context,
    QuantumCell::Existing,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::halo2::POSEIDON_SPEC;

/// | Block Header Field        | Max bytes     |
/// |---------------------------|---------------|
/// | parentHash                | 32            |
/// | ommersHash                | 32            |
/// | beneficiary               | 20            |
/// | stateRoot                 | 32            |
/// | transactionsRoot          | 32            |
/// | receiptsRoot              | 32            |
/// | logsBloom                 | 256           |
/// | difficulty                | ≤7            |
/// | number                    | ≤4            |
/// | gasLimit                  | ≤4            |
/// | gasUsed                   | ≤4            |
/// | timestamp                 | ≤4            |
/// | extraData                 | ≤32 (mainnet) |
/// | mixHash                   | 32            |
/// | nonce                     | 8             |
/// | basefee (post-1559)       | ≤6 or 0       |
/// | withdrawalsRoot (post-4895) | 32 or 0     |
///
/// Struct that stores block header fields as an array of `ByteArray`s. The first [`MIN_NUM_BLOCK_HEADER_FIELDS`]
/// fields are of known fixed length, and the rest are either fixed length byte arrays or empty byte arrays.
/// For fields of `uint` type with variable length byte lens, the byte arrays are left padded with 0s to the max fixed length.
///
/// We do something special for extraData because it is a variable length array of arbitrary bytes. In that case we
/// store `extraDataLength . extraDataRightPadded` as an array of field elements, where `extraDataRightPadded`
/// is right padded with 0s to max fixed length.
///
/// Entry in the array consists of (bytes, is_some)
#[derive(Clone, Debug)]
pub struct BlockHeader<F: ScalarField> {
    pub as_list: [(FixedByteArray<F>, Option<AssignedValue<F>>); NUM_BLOCK_HEADER_FIELDS],
    extra_data_len: AssignedValue<F>,
}

/// A single response to a block header query.
///
/// | Field                     | Max bytes |
/// |---------------------------|--------------|
/// | blockHash                 | 32           |
/// | blockNumber               | ≤4           |
///
/// ```
/// block_response = hash(blockHash. blockNumber. hash_tree_root(block_header))
/// ```
/// This struct stores all the data necessary to compute the above hash.
///
/// We store `blockNumber` twice because it needs to be accesses frequently with less hashing.
#[derive(Clone, Debug)]
pub struct BlockResponse<F: ScalarField> {
    pub block_hash: FixedByteArray<F>,
    pub block_header: BlockHeader<F>,
}

impl<F: Field> BlockResponse<F> {
    pub fn from_witness(
        witness: &EthBlockHeaderTraceWitness<F>,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> Self {
        let block_hash = FixedByteArray(witness.block_hash.clone());
        let extra_data_len = witness.rlp_witness.field_witness[EXTRA_DATA_INDEX].field_len;
        let block_header = BLOCK_HEADER_FIELD_IS_VAR_LEN
            .iter()
            .zip_eq(witness.rlp_witness.field_witness.iter())
            .enumerate()
            .map(|(i, (is_var_len, witness))| {
                if i == EXTRA_DATA_INDEX {
                    (FixedByteArray(witness.field_cells.clone()), None)
                } else if i < MIN_NUM_BLOCK_HEADER_FIELDS {
                    // these fields are non-optional
                    let field = if *is_var_len {
                        // left pad with 0s to max len
                        ByteArray::from(witness).to_fixed(ctx, gate)
                    } else {
                        // checks to make sure actually fixed len
                        witness.into()
                    };
                    (field, None)
                } else {
                    let field = ByteArray::from(witness);
                    let var_len = field.var_len.unwrap();
                    let is_empty = gate.is_zero(ctx, var_len);
                    let is_some = gate.not(ctx, is_empty);
                    let padded_field = if *is_var_len {
                        // left pad with 0s to max length
                        field.to_fixed(ctx, gate).0
                    } else {
                        field.bytes
                    };
                    (FixedByteArray(padded_field), Some(is_some))
                }
            })
            .collect_vec();
        Self {
            block_hash,
            block_header: BlockHeader { as_list: block_header.try_into().unwrap(), extra_data_len },
        }
    }

    pub fn keccak(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        keccak: &mut KeccakChip<F>,
    ) -> FixedByteArray<F> {
        let block_number_bytes = &self.block_header.as_list[BLOCK_NUMBER_INDEX].0;
        keccak_packed(ctx, gate, keccak, self.block_hash.concat(block_number_bytes))
    }

    pub fn poseidon<C, EccChip, const T: usize, const RATE: usize>(
        &self,
        loader: &Rc<Halo2Loader<C, EccChip>>,
        poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
        poseidon_empty_roots: &[F],
    ) -> Scalar<C, EccChip>
    where
        F: Field,
        C: CurveAffine<ScalarExt = F>,
        EccChip: EccInstructions<F, C>,
    {
        let header_as_words = self
            .block_header
            .as_list
            .iter()
            .enumerate()
            .map(|(i, (bytes, is_some))| {
                let mut words = bytes.to_poseidon_words(loader);
                if i == EXTRA_DATA_INDEX {
                    // extra data is variable length, so we record (extraData.length . extraDataRightPadded)
                    let extra_data_len =
                        loader.scalar_from_assigned(self.block_header.extra_data_len);
                    words = PoseidonWords::from(extra_data_len).concat(&words);
                }
                OptPoseidonWords {
                    words: words.0,
                    is_some: is_some.map(|x| loader.scalar_from_assigned(x)),
                }
            })
            .collect_vec();

        let block_number_words = PoseidonWords(header_as_words[8].words.clone());
        let header_poseidon = poseidon_tree_root(poseidon, header_as_words, poseidon_empty_roots);

        let block_hash = self.block_hash.to_poseidon_words(loader);
        poseidon_packed(
            poseidon,
            block_hash.concat(&block_number_words).concat(&header_poseidon.into()),
        )
    }
}

/// See [`MultiBlockCircuit`] for more details.
///
/// Returns `(keccak_tree_root(block_responses.keccak), block_responses.keccak)`
pub fn get_block_response_keccak_root<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    keccak: &mut KeccakChip<F>,
    block_responses: &[BlockResponse<F>],
    not_empty: Vec<AssignedValue<F>>,
) -> (FixedByteArray<F>, Vec<FixedByteArray<F>>) {
    let block_responses = block_responses
        .iter()
        .zip_eq(not_empty)
        .map(|(block_response, not_empty)| {
            let hash = block_response.keccak(ctx, gate, keccak);
            bytes_select_or_zero(ctx, gate, hash, not_empty)
        })
        .collect_vec();
    let keccak_root = keccak.merkle_tree_root(ctx, gate, &block_responses);
    (FixedByteArray(bytes_be_to_u128(ctx, gate, &keccak_root)), block_responses)
}

/// See [`MultiBlockCircuit`] for more details.
///
pub fn get_block_response_poseidon_roots<F, C, EccChip, const T: usize, const RATE: usize>(
    loader: &Rc<Halo2Loader<C, EccChip>>,
    poseidon: &mut Poseidon<F, Scalar<C, EccChip>, T, RATE>,
    block_responses: &[BlockResponse<F>],
    not_empty: Vec<AssignedValue<F>>,
    poseidon_empty_roots: &[F],
) -> Vec<AssignedValue<F>>
where
    F: Field,
    C: CurveAffine<ScalarExt = F>,
    EccChip: EccInstructions<F, C>,
{
    let block_responses = block_responses
        .iter()
        .zip_eq(not_empty)
        .map(|(block_response, not_empty)| {
            let hash = block_response.poseidon(loader, poseidon, poseidon_empty_roots);
            word_select_or_zero(loader, hash, not_empty)
        })
        .collect_vec();
    let poseidon_root =
        poseidon_tree_root(poseidon, block_responses, poseidon_empty_roots).into_assigned();
    vec![poseidon_root]
}

// switching to just Fr for simplicity:

/// The input datum for the circuit to generate multiple block responses. It is used to generate a circuit.
/// Additionally checks that all block hashes in a response column are in a given
/// Merkle Mountain Range (MMR). The MMR will be a commitment to a contiguous list of block hashes, for block
/// numbers `[0, mmr_list_len)`.
///
/// Assumptions:
///
///
/// Assumptions:
/// * `header_rlp_encodings`, `not_empty`, `block_hashes`, `block_numbers`, `headers_poseidon`, `mmr_proofs` have the same length, which is a power of two.
/// * `header_rlp_encodings` has length greater than 1: the length 1 case still works but cannot be aggregated because
/// the single leaf of `block_responses[0].keccak` would get Poseidon hashed into a single word, whereas in a larger
/// tree it gets concatenated before hashing.
/// * `mmr_list_len < 2^MMR_MAX_NUM_PEAKS`
/// * `mmr_list_len >= 2^BLOCK_BATCH_DEPTH`, i.e., `mmr_num_peaks > BLOCK_BATCH_DEPTH` where `mmr_num_peaks := bit_length(mmr_list_len)`
///
/// The public instances of this circuit are [`BLOCK_INSTANCE_SIZE`] field elements:
/// * Keccak merkle tree root of `keccakPacked(blockHash[i] . blockNumber[i])` over all queries: two field elements in hi-lo u128 format
/// * Poseidon merkle tree root of `block_responses[i].poseidon` over all queries: single field element
/// * `keccak256(abi.encodePacked(mmr[BLOCK_BATCH_DEPTH..]))` as 2 field elements, H256 in hi-lo form.
/// * `keccak256(abi.encodePacked(mmr[..BLOCK_BATCH_DEPTH]))` as 2 field elements, H256 in hi-lo form.
///
/// Above `block_responses` refers to the hash of `BlockResponse`s generated by the circuit for all queries.
///
/// To be clear, `abi.encodedPacked(mmr[d..]) = mmr[d] . mmr[d + 1] . ... . mmr[mmr_num_peaks - 1]` where `.` is concatenation of byte arrays.
///
/// If a block entry has `not_empty = false`, then the MMR proof is skipped.
#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct MultiBlockCircuit {
    /// The RLP-encoded block headers
    pub header_rlp_encodings: Vec<Vec<u8>>,
    /// Private input to allow block_responses[i] to be `(Fr::zero(), H256::zero())` for empty entry
    // This is needed so we don't need to do the MMR proof
    pub not_empty: Vec<bool>,
    pub network: Network,

    /// Merkle Mountain Range of block hashes for blocks `[0, mmr_list_len)`, in *increasing* order of peak size.
    /// Resized with 0x0 to a fixed length.
    pub mmr: [H256; MMR_MAX_NUM_PEAKS],
    /// Length of the original list that `mmr` is a commitment to.
    pub mmr_list_len: usize,
    /// `mmr_proofs[i]` is a Merkle proof of `block_hashes[i]` into `mmr`. Resized so `mmr_proofs[i].len() = mmr.len() - 1`
    pub mmr_proofs: Vec<[H256; MMR_MAX_NUM_PEAKS - 1]>,
}

pub const MMR_MAX_NUM_PEAKS: usize = 32; // assuming block number stays in u32, < 2^32
/// The AxiomV1Core smart contract only stores Merkle Mountain Range of Merkle roots of block hashes of contiguous segments
/// of blocks of length 2<sup>BLOCK_BATCH_DEPTH</sup>.
pub const BLOCK_BATCH_DEPTH: usize = 10;

pub const BLOCK_INSTANCE_SIZE: usize = 7;
pub(crate) const KECCAK_BLOCK_RESPONSE_INDEX: usize = 0;
pub(crate) const BLOCK_RESPONSE_POSEIDON_INDEX: usize = 2;
pub const BLOCK_POSEIDON_ROOT_INDICES: &[usize] = &[BLOCK_RESPONSE_POSEIDON_INDEX];
pub const BLOCK_KECCAK_ROOT_INDICES: &[usize] = &[KECCAK_BLOCK_RESPONSE_INDEX];

impl MultiBlockCircuit {
    /// Creates circuit inputs from raw RLP encodings. Panics if number of blocks is not a power of 2.
    pub fn new(
        mut header_rlps: Vec<Vec<u8>>,
        not_empty: Vec<bool>,
        network: Network,
        mut mmr: Vec<H256>,
        mmr_list_len: usize,
        mmr_proofs: Vec<Vec<H256>>,
    ) -> Self {
        assert!(header_rlps.len() > 1);
        assert_eq!(header_rlps.len(), not_empty.len());
        assert!(header_rlps.len().is_power_of_two(), "Number of blocks must be a power of 2");
        // resize RLPs
        let (header_rlp_max_bytes, _) = get_block_header_rlp_max_lens(network);
        for rlp in &mut header_rlps {
            rlp.resize(header_rlp_max_bytes, 0);
        }
        assert_eq!(header_rlps.len(), mmr_proofs.len());

        mmr.resize(MMR_MAX_NUM_PEAKS, H256::zero());
        let mmr_proofs = mmr_proofs
            .into_iter()
            .map(|mut proof| {
                proof.resize(MMR_MAX_NUM_PEAKS - 1, H256::zero());
                proof.try_into().unwrap()
            })
            .collect();
        Self {
            header_rlp_encodings: header_rlps,
            not_empty,
            network,
            mmr: mmr.try_into().unwrap(),
            mmr_list_len,
            mmr_proofs,
        }
    }

    /// Creates circuit inputs using JSON-RPC provider. Panics if provider error or any block is not found.
    ///
    /// Assumes that `network` is the same as the provider's network.
    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        block_numbers: Vec<u64>,
        not_empty: Vec<bool>,
        network: Network,
        mmr: Vec<H256>,
        mmr_list_len: usize,
        mmr_proofs: Vec<Vec<H256>>,
    ) -> Self {
        use crate::providers::{get_block_rlp, get_blocks};

        let header_rlp_encodings = get_blocks(provider, block_numbers)
            .unwrap()
            .into_iter()
            .map(|block| get_block_rlp(&block.expect("block not found")))
            .collect();
        Self::new(header_rlp_encodings, not_empty, network, mmr, mmr_list_len, mmr_proofs)
    }

    pub fn resize_from(
        mut header_rlps: Vec<Vec<u8>>,
        mut not_empty: Vec<bool>,
        network: Network,
        mmr: Vec<H256>,
        mmr_list_len: usize,
        mut mmr_proofs: Vec<Vec<H256>>,
        new_len: usize,
    ) -> Self {
        header_rlps.resize_with(new_len, || GENESIS_BLOCK_RLP.to_vec());
        not_empty.resize(new_len, false);
        mmr_proofs.resize(new_len, vec![]);
        Self::new(header_rlps, not_empty, network, mmr, mmr_list_len, mmr_proofs)
    }
}

impl EthPreCircuit for MultiBlockCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();
        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let max_len = get_block_header_rlp_max_lens(self.network).0;
        let header_rlp_encodings = self
            .header_rlp_encodings
            .into_iter()
            .map(|rlp| assign_vec(ctx, rlp, max_len))
            .collect_vec();
        let witness = chip.decompose_block_headers_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            header_rlp_encodings,
            self.network,
        );
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let block_responses =
            witness.iter().map(|w| BlockResponse::from_witness(w, ctx, range.gate())).collect_vec();
        let not_empty =
            self.not_empty.into_iter().map(|b| load_bool(ctx, range.gate(), b)).collect_vec();

        let mmr_keccaks = assign_and_verify_block_mmr(
            ctx,
            &range,
            &mut keccak,
            self.mmr,
            self.mmr_proofs,
            &block_responses,
            not_empty.clone(),
        );

        // keccak responses
        let (keccak_root, _) = get_block_response_keccak_root(
            ctx,
            range.gate(),
            &mut keccak,
            &block_responses,
            not_empty.clone(),
        );
        // poseidon responses
        let loader =
            Halo2Loader::<G1Affine, _>::new(DummyEccChip(range.gate()), builder.gate_builder);
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());

        let mut assigned_instances = keccak_root.0;
        assigned_instances.extend(
            get_block_response_poseidon_roots(
                &loader,
                &mut poseidon,
                &block_responses,
                not_empty,
                &POSEIDON_EMPTY_ROOTS,
            )
            .into_iter()
            .chain(mmr_keccaks),
        );

        builder.gate_builder = loader.take_ctx();

        // ================= SECOND PHASE ================
        EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<Fr>,
                  rlp: RlpChip<Fr>,
                  keccak_rlcs: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {
                // ======== SECOND PHASE ===========
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                chip.decompose_block_headers_phase1(builder, witness);
            },
        )
    }
}

pub fn assign_and_verify_block_mmr<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    keccak: &mut KeccakChip<F>,
    mmr: [H256; MMR_MAX_NUM_PEAKS],
    mmr_proofs: Vec<[H256; MMR_MAX_NUM_PEAKS - 1]>,
    block_responses: &[BlockResponse<F>],
    not_empty: Vec<AssignedValue<F>>,
) -> Vec<AssignedValue<F>> {
    let gate = range.gate();
    // assign witnesses
    let mmr =
        mmr.into_iter().map(|peak| FixedByteArray::new(ctx, range, peak.as_bytes())).collect_vec();
    let mmr_bits = mmr
        .iter()
        .map(|peak| {
            let no_peak = is_zero_vec(ctx, gate, &peak.0);
            gate.not(ctx, no_peak)
        })
        .collect_vec();
    let mmr_list_len = gate.inner_product(
        ctx,
        mmr_bits.clone(),
        gate.pow_of_two().iter().take(mmr_bits.len()).map(|x| Constant(*x)),
    );
    // verify mmr proofs
    block_responses.iter().zip(mmr_proofs).zip_eq(not_empty).for_each(
        |((response, mmr_proof), not_empty)| {
            let block_hash = response.block_hash.clone();
            let block_number_be = &response.block_header.as_list[BLOCK_NUMBER_INDEX].0 .0;
            // this is done again later in poseidon, so a duplicate for code conciseness
            let block_number = bytes_be_to_u128(ctx, gate, block_number_be).pop().unwrap();
            let mmr_proof = mmr_proof
                .into_iter()
                .map(|node| FixedByteArray::new(ctx, range, node.as_bytes()))
                .collect_vec();
            verify_mmr_proof(
                ctx,
                range,
                keccak,
                &mmr,
                mmr_list_len,
                &mmr_bits,
                block_number,
                block_hash,
                mmr_proof,
                not_empty,
            );
        },
    );
    // mmr_num_peaks = bit_length(mmr_list_len) = MMR_MAX_NUM_PEAKS - num_leading_zeros(mmr_list_len)
    let mut is_leading = Constant(F::one());
    let mut num_leading_zeros = ctx.load_zero();
    for bit in mmr_bits.iter().rev() {
        // is_zero = 1 - bit
        // is_leading = is_leading * (is_zero)
        is_leading = Existing(gate.mul_not(ctx, *bit, is_leading));
        num_leading_zeros = gate.add(ctx, num_leading_zeros, is_leading);
    }
    let max_num_peaks = gate.get_field_element(MMR_MAX_NUM_PEAKS as u64);
    let num_peaks = gate.sub(ctx, Constant(max_num_peaks), num_leading_zeros);
    let truncated_num_peaks =
        gate.sub(ctx, num_peaks, Constant(gate.get_field_element(BLOCK_BATCH_DEPTH as u64)));
    range.range_check(ctx, truncated_num_peaks, bit_length(MMR_MAX_NUM_PEAKS as u64)); // ensures not negative
    let truncated_mmr_bytes =
        gate.mul(ctx, truncated_num_peaks, Constant(gate.get_field_element(32u64)));
    let keccak_id = keccak.keccak_var_len(
        ctx,
        range,
        mmr[BLOCK_BATCH_DEPTH..].iter().flat_map(|bytes| bytes.0.clone()).collect(),
        None,
        truncated_mmr_bytes,
        0,
    );
    let keccak_bytes = keccak.var_len_queries[keccak_id].output_assigned.clone();
    let historical_mmr_keccak = bytes_be_to_u128(ctx, gate, &keccak_bytes);

    let recent_mmr_keccak_bytes = keccak_packed(
        ctx,
        gate,
        keccak,
        FixedByteArray(mmr[..BLOCK_BATCH_DEPTH].iter().flat_map(|bytes| bytes.0.clone()).collect()),
    );
    let recent_mmr_keccak = bytes_be_to_u128(ctx, gate, recent_mmr_keccak_bytes.as_ref());
    [historical_mmr_keccak, recent_mmr_keccak].concat()
}

pub const GENESIS_BLOCK_RLP: &[u8] = &[
    249, 2, 20, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212,
    26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 215, 248, 151, 79, 181, 172, 120, 217,
    172, 9, 155, 154, 213, 1, 139, 237, 194, 206, 10, 114, 218, 209, 130, 122, 23, 9, 218, 48, 88,
    15, 5, 68, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91,
    72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 86, 232, 31, 23, 27,
    204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1,
    98, 47, 181, 227, 99, 180, 33, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 4, 0, 0, 0, 0, 128, 130, 19, 136, 128, 128, 160,
    17, 187, 232, 219, 78, 52, 123, 78, 140, 147, 124, 28, 131, 112, 228, 181, 237, 51, 173, 179,
    219, 105, 203, 219, 122, 56, 225, 229, 11, 27, 130, 250, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0, 0, 0, 0, 66,
];

lazy_static! {
    pub static ref GENESIS_BLOCK: Block<H256> = serde_json::from_str(r#"
    {"hash":"0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","number":"0x0","gasUsed":"0x0","gasLimit":"0x1388","extraData":"0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x0","difficulty":"0x400000000","totalDifficulty":"0x400000000","sealFields":[],"uncles":[],"transactions":[],"size":"0x21c","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000042","baseFeePerGas":null}
    "#).unwrap();
}
