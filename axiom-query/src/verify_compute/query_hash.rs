use std::iter;

use axiom_codec::{constants::SOURCE_CHAIN_ID_BYTES, HiLo};
use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeChip, RangeInstructions},
        safe_types::{SafeBool, SafeByte, SafeBytes32, SafeTypeChip},
        AssignedValue, Context,
        QuantumCell::Constant,
    },
    keccak::{types::KeccakVarLenQuery, KeccakChip},
    snark_verifier::loader::halo2::halo2_ecc::bigint::{big_is_zero, OverflowInteger},
    snark_verifier_sdk::{halo2::aggregation::AssignedTranscriptObject, BITS, LIMBS},
    utils::{uint_to_bytes_be, uint_to_bytes_le},
};
use itertools::Itertools;

use crate::Field;

pub(super) use bn254_specific::*;

/// `subquery_hashes` has been resized with dummies to `max_num_subqueries` length (known as compile time). This represents a variable length array of hashes with true length given by `num_subqueries`.
///
/// ## Output
/// - `data_query_hash` (bytes32)
/// - `encoded_source_chain_id` (big-endian bytes)
pub fn get_data_query_hash<F: Field>(
    ctx: &mut Context<F>,
    keccak: &KeccakChip<F>,
    source_chain_id: AssignedValue<F>, // u64
    subquery_hashes: &[SafeBytes32<F>],
    num_subqueries: AssignedValue<F>,
) -> (KeccakVarLenQuery<F>, Vec<SafeByte<F>>) {
    let range = keccak.range();
    let encoded_source_chain_id =
        uint_to_bytes_be(ctx, range, &source_chain_id, SOURCE_CHAIN_ID_BYTES); // u64
    let encoded: Vec<_> = iter::empty()
        .chain(encoded_source_chain_id.iter().map(|b| *b.as_ref()))
        .chain(subquery_hashes.iter().flat_map(|subquery_hash| subquery_hash.value().to_vec()))
        .collect();
    let encoded_len = range.gate.mul_add(
        ctx,
        Constant(F::from(32)),
        num_subqueries,
        Constant(F::from(SOURCE_CHAIN_ID_BYTES as u64)),
    );
    (
        keccak.keccak_var_len(ctx, encoded, encoded_len, SOURCE_CHAIN_ID_BYTES),
        encoded_source_chain_id,
    )
}

// Everything involving vkey or proof are specific to BN254:
// Make module public for docs.
pub mod bn254_specific {
    use axiom_codec::constants::{ENCODED_K_BYTES, USER_PROOF_LEN_BYTES, USER_RESULT_LEN_BYTES};
    use axiom_eth::{
        halo2_base::safe_types::VarLenBytesVec,
        halo2curves::bn256::Fr,
        rlc::{
            chip::RlcChip,
            circuit::builder::RlcContextPair,
            concat_array::{concat_var_fixed_array_phase0, concat_var_fixed_array_phase1},
            types::{AssignedVarLenVec, ConcatVarFixedArrayWitness},
        },
        utils::circuit_utils::bytes::encode_const_u8_to_safe_bytes,
    };

    use crate::utils::client_circuit::metadata::AxiomV2CircuitMetadata;

    use super::*;

    type F = Fr;

    /// Length of `encoded_query_schema` and `compute_proof_transcript` are known at compile time.
    /// keccak(version . source_chain_id . data_query_hash . encoded_compute_query)
    #[allow(clippy::too_many_arguments)]
    pub fn get_query_hash_v2(
        ctx: &mut Context<F>,
        keccak: &KeccakChip<F>,
        encoded_source_chain_id: &[SafeByte<F>], // 8 big-endian bytes
        data_query_hash: &KeccakVarLenQuery<F>,
        encoded_query_schema: &[SafeByte<F>],
        compute_accumulator: Option<Vec<AssignedValue<F>>>,
        compute_results: &AssignedVarLenVec<F>,
        compute_proof_transcript: Vec<AssignedTranscriptObject>,
        nonempty_compute_query: SafeBool<F>,
    ) -> (KeccakVarLenQuery<F>, ConcatVarFixedArrayWitness<F>) {
        let range = keccak.range();
        let gate = range.gate();
        let encoded_version = encode_const_u8_to_safe_bytes(ctx, axiom_codec::VERSION);
        let data_query_hash = data_query_hash.output_bytes.value();

        let (encoded_compute_query, concat_proof_witness) = encode_compute_query_phase0(
            ctx,
            range,
            encoded_query_schema,
            compute_accumulator,
            compute_results,
            compute_proof_transcript,
        );
        // if nonempty_compute_query = false, then `encoded_compute_query` should equal `[0u8]`
        let nonempty = *nonempty_compute_query.as_ref();
        let true_k = gate.mul(ctx, nonempty, encoded_compute_query.bytes()[0]);
        // the minimum length of encoded_compute_query, if computeQuery is empty
        let min_encoded_compute_query_len = ENCODED_K_BYTES + USER_RESULT_LEN_BYTES;
        assert!(encoded_compute_query.max_len() >= min_encoded_compute_query_len);
        let ne_compute_len = gate.sub(
            ctx,
            *encoded_compute_query.len(),
            Constant(F::from(min_encoded_compute_query_len as u64)),
        );
        // version . source_chain_id . data_query_hash
        // uint8 . uint64 . bytes32 => 1 + 8 + 32
        let min_len = (1 + SOURCE_CHAIN_ID_BYTES + 32 + min_encoded_compute_query_len) as u64;
        let encoded_len = gate.mul_add(ctx, ne_compute_len, nonempty, Constant(F::from(min_len)));
        let concatenated = iter::empty()
            .chain(encoded_version.iter().chain(encoded_source_chain_id).map(|b| *b.as_ref()))
            .chain(data_query_hash.iter().copied())
            .chain([true_k])
            .chain(encoded_compute_query.bytes().iter().skip(1).map(|b| *b.as_ref()))
            .collect_vec();
        (
            keccak.keccak_var_len(ctx, concatenated, encoded_len, min_len as usize),
            concat_proof_witness,
        )
    }

    /// Length of `encoded_query_schema` is assumed to be constant at compile time.
    /// If `nonempty_compute_query` is false, return bytes32(0).
    pub fn get_query_schema_hash(
        ctx: &mut Context<F>,
        keccak: &KeccakChip<F>,
        encoded_query_schema: &[SafeByte<F>],
        nonempty_compute_query: SafeBool<F>,
    ) -> HiLo<AssignedValue<F>> {
        let range = keccak.range();
        let encoded = encoded_query_schema.iter().map(|b| *b.as_ref()).collect();
        let query_schema = keccak.keccak_fixed_len(ctx, encoded);
        let query_schema = query_schema.hi_lo();
        let query_schema = query_schema.map(|x| range.gate.mul(ctx, x, nonempty_compute_query));
        HiLo::from_hi_lo(query_schema)
    }

    /// Length of `encoded_query_schema`, `compute_proof_transcript` are known at compile time.
    /// `compute_results` is a variable length array of HiLo field elements (two field elements represent a `bytes32`).
    ///
    /// We define `compute_proof = solidityPacked(["bytes32[2]", "bytes32[]", "bytes"], [compute_accumulator, compute_results, compute_proof_transcript])` where `compute_results` is of length `result_len` (as `bytes32[]`).
    /// Here `compute_accumulator` is either `[bytes32(0), bytes32(0)]` if no accumulator exists, or `[lhs, rhs]` where `lhs, rhs` are the `G1Affine` points, each compressed to `bytes32`.
    /// See [axiom_codec::decoder::native::decode_compute_snark] and [axiom_codec::types::native::AxiomV2ComputeSnark].
    ///
    /// We encode the concatenation of `solidityPacked(["bytes", "uint32", "bytes"], [encoded_query_schema, proof_len, compute_proof])`
    /// where `proof_len` is the [u32] length of `compute_proof` in bytes.
    ///
    /// ## Special Note
    /// - `compute_results` is actually _not_ all public instances of `proof_transcript`. We skip the instances corresponding to subquery results.
    /// ## Note on endian-ness
    /// - The encoding of `proof_transcript` is governed by the inherit implementations of `to_repr`
    ///   in `halo2curves`. These happen to be **little-endian** for BN254.
    /// - _However_, the encoding of `compute_results` is chosen to match
    ///   [axiom_eth::snark_verifier::loader::evm::encode_calldata], where `compute_results` encodes field elements
    ///   as **big-endian**.
    ///   Since it's harder to change `halo2curves` and `snark_verifier`,
    ///   we will just have to deal with this inconsistency.
    /// - The [u32] `proof_len` is encoded to [USER_PROOF_LEN_BYTES] bytes in **big endian** since
    ///   this is more compatible with Solidity packing.
    pub fn encode_compute_query_phase0(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        encoded_query_schema: &[SafeByte<F>],
        compute_accumulator: Option<Vec<AssignedValue<F>>>,
        compute_results: &AssignedVarLenVec<F>,
        compute_proof_transcript: Vec<AssignedTranscriptObject>,
    ) -> (VarLenBytesVec<F>, ConcatVarFixedArrayWitness<F>) {
        let gate = range.gate();
        // compute results length in bytes
        let mut compute_results_len = gate.mul(ctx, compute_results.len, Constant(F::from(32)));
        // compute results conversion from HiLo to bytes
        let mut compute_results = compute_results
            .values
            .iter()
            .flat_map(|fe| uint_to_bytes_be(ctx, range, fe, 16))
            .collect_vec();
        let mut max_len = compute_results.len();
        // if `compute_accumulator` exists, encode as `bytes32 . bytes32` (`CompressedG1Affine, CompressedG1Affine`) and prepend to `user_outputs`
        // else encode as `bytes32(0) . bytes32(0)`
        const NUM_ACCUMULATOR_BYTES: usize = 2 * 32;
        let encoded_compute_accumulator = if let Some(acc) = compute_accumulator {
            // KzgAccumulator from snark-verifier consists of `lhs, rhs` which are two G1Affine points for the lhs and rhs of pairing check
            let [lhs_x, lhs_y, rhs_x, rhs_y]: [_; 4] = acc
                .chunks_exact(LIMBS)
                .map(|limbs| {
                    let limbs: [_; LIMBS] = limbs.to_vec().try_into().unwrap();
                    limbs
                })
                .collect_vec()
                .try_into()
                .unwrap();
            let lhs = compress_bn254_g1_affine_point_to_bytes(ctx, range, lhs_x, lhs_y);
            let rhs = compress_bn254_g1_affine_point_to_bytes(ctx, range, rhs_x, rhs_y);
            [lhs, rhs].concat()
        } else {
            let const_zero_byte = encode_const_u8_to_safe_bytes(ctx, 0)[0];
            vec![const_zero_byte; NUM_ACCUMULATOR_BYTES]
        };
        compute_results_len =
            gate.add(ctx, compute_results_len, Constant(F::from(NUM_ACCUMULATOR_BYTES as u64)));
        compute_results = [encoded_compute_accumulator, compute_results].concat();
        max_len += NUM_ACCUMULATOR_BYTES;
        let compute_results = VarLenBytesVec::new(compute_results, compute_results_len, max_len);
        let encoded_proof = encode_proof_to_bytes(ctx, range, compute_proof_transcript);
        let concat_witness = concat_var_fixed_array_phase0(
            ctx,
            gate,
            compute_results.into(),
            encoded_proof.into_iter().map(From::from).collect(),
        );
        // encoded_compute_accumulator . compute_results (no accumulator) . compute_proof_transcript
        let compute_proof = concat_witness
            .concat
            .values
            .iter()
            .map(|byte| SafeTypeChip::unsafe_to_byte(*byte))
            .collect_vec();
        let proof_len = concat_witness.concat.len;
        let encoded_pf_len = uint_to_bytes_be(ctx, range, &proof_len, USER_PROOF_LEN_BYTES);
        // The full concatenation is variable length, but `encoded_query_schema`, `encoded_pf_len` are fixed length, so only variable-ness is in `compute_proof`
        let concat_full = [encoded_query_schema.to_vec(), encoded_pf_len, compute_proof].concat();
        let prefix_len = encoded_query_schema.len() + USER_PROOF_LEN_BYTES;
        let concat_len = gate.add(ctx, proof_len, Constant(F::from(prefix_len as u64)));
        let max_len = concat_full.len();
        let concat_var = VarLenBytesVec::new(concat_full, concat_len, max_len);
        /*{
            let len = concat_var.len().value().get_lower_32() as usize;
            println!("encodedComputeQuery");
            let enc = get_bytes(&concat_var.bytes()[..len]);
            dbg!(ethers_core::types::H256(keccak256(&enc[..])));
        }*/
        (concat_var, concat_witness)
    }

    pub fn encode_compute_query_phase1(
        rlc_pair: RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        rlc: &RlcChip<F>,
        concat_witness: ConcatVarFixedArrayWitness<F>,
    ) {
        concat_var_fixed_array_phase1(rlc_pair, gate, rlc, concat_witness);
    }

    /// Returns `solidityPacked(["uint8", "uint16", "uint8", "bytes32[]"], [k, result_len, partial_vkey_len, encoded_partial_vkey])` where `partial_vkey_len` is the length of `encoded_partial_vkey` as `bytes32[]`.
    ///
    /// We need the `result_len` encoded correctly even if `k = 0`.
    ///
    /// ## Notes
    /// - `partial_vkey_len` is known at compile time.
    /// - `is_aggregation` needs to be part of the `encoded_partial_vkey` because it specifies
    /// whether the VerifyCompute circuit will RLC the accumulator from the public instances of the compute snark into the new accumulator of the VerifyCompute circuit.
    pub fn encode_query_schema(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        k: AssignedValue<F>,
        result_len: AssignedValue<F>,
        circuit_metadata: &AxiomV2CircuitMetadata,
        transcript_initial_state: AssignedValue<F>,
        preprocessed: &[AssignedValue<F>],
    ) -> Vec<SafeByte<F>> {
        let encoded_k = uint_to_bytes_be(ctx, range, &k, ENCODED_K_BYTES); // u8
        let encoded_result_len = uint_to_bytes_be(ctx, range, &result_len, USER_RESULT_LEN_BYTES); // u16
        let encoded_onchain_vkey = encode_onchain_vkey(
            ctx,
            range,
            circuit_metadata,
            transcript_initial_state,
            preprocessed,
        );
        assert_eq!(encoded_onchain_vkey.len() % 32, 0);
        let onchain_vkey_len = encoded_onchain_vkey.len() / 32;
        let encoded_vkey_length =
            encode_const_u8_to_safe_bytes(ctx, onchain_vkey_len.try_into().unwrap()).to_vec();

        [encoded_k, encoded_result_len, encoded_vkey_length, encoded_onchain_vkey].concat()
    }

    /// Encode in virtual cells.
    /// ## Output
    /// - The encoding in bytes: `solidityPacked(["uint256", "bytes32", "bytes32[]"], [is_aggregation, transcript_initial_state, preprocessed])`. This is interpretted by the smart contract as `vkey: bytes32[]`.
    /// - Field and curve elements are encoded in **little endian**.
    /// - `is_aggregation` (boolean) is encoded as `uint256(is_aggregation)` in **big endian**.
    ///     - It is wasteful to use 32 bytes, but the smart contract expects `vkey` to be `bytes32[]`
    /// ## Assumptions
    /// - Length of `preprocessed` is assumed to be constant at compile time.
    /// - `transcript_initial_state` is a **field element**.
    /// - `preprocessed` is an array of field elements that represent an array of BN254 G1Affine points
    ///   that form the fixed commitments of the vkey. These are non-native encoded with Fq points
    ///   as big integers (ProperCrtUint) with [LIMBS] limbs of [BITS] bits each.
    ///   See [compress_bn254_g1_affine_point_to_bytes] for further details. This depends on the
    ///   specifics of [`snark_verifier_sdk`](axiom_eth::snark_verifier_sdk) and the exact compression method of BN254, so we keep it
    ///   as a private function.
    pub fn encode_onchain_vkey(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        circuit_metadata: &AxiomV2CircuitMetadata,
        transcript_initial_state: AssignedValue<F>,
        preprocessed: &[AssignedValue<F>],
    ) -> Vec<SafeByte<F>> {
        let encoded_circuit_metadata = circuit_metadata.encode().unwrap().to_fixed_bytes();
        // Load encoded_circuit_metadata as **constant** bytes32
        let encoded_circuit_metadata_const = encoded_circuit_metadata
            .map(|b| SafeTypeChip::unsafe_to_byte(ctx.load_constant(F::from(b as u64))));

        let encoded_init_state = uint_to_bytes_le(ctx, range, &transcript_initial_state, 32);
        assert_eq!(preprocessed.len() % (2 * LIMBS), 0);
        let encoded_preprocessed = preprocessed
            .chunks_exact(2 * LIMBS)
            .flat_map(|chunk| {
                let x = chunk[..LIMBS].try_into().unwrap();
                let y = chunk[LIMBS..].try_into().unwrap();
                compress_bn254_g1_affine_point_to_bytes(ctx, range, x, y)
            })
            .collect_vec();
        [encoded_circuit_metadata_const.to_vec(), encoded_init_state, encoded_preprocessed].concat()
    }

    /// The proof transcript is given as a sequence of either [Fr] field elements or G1Affine points.
    /// They are encoded in **little-endian** as described in [encode_partial_vkey].
    ///
    /// ## Output
    /// - Returns encoded proof bytes in **little endian**
    pub fn encode_proof_to_bytes(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        proof: Vec<AssignedTranscriptObject>,
    ) -> Vec<SafeByte<F>> {
        proof
            .into_iter()
            .flat_map(|obj| match obj {
                AssignedTranscriptObject::Scalar(scalar) => {
                    uint_to_bytes_le(ctx, range, &scalar, 32)
                }
                AssignedTranscriptObject::EcPoint(point) => {
                    let x = point.x().limbs().try_into().unwrap();
                    let y = point.y().limbs().try_into().unwrap();
                    compress_bn254_g1_affine_point_to_bytes(ctx, range, x, y)
                }
            })
            .collect()
    }

    /// Takes a BN254 G1Affine point, which is non-native encoded with each coordinate as a
    /// ProperCrtUint with [LIMBS] limbs with [BITS] bits each and compresses it to 32 bytes
    /// exactly following https://github.com/axiom-crypto/halo2curves/blob/main/src/derive/curve.rs#L138
    ///
    /// This relies on both the exact format of the input from [snark_verifier_sdk] and also
    /// the exact compression method for BN254 in `halo2curves`, so this is a private function.
    ///
    /// The compression uses the fact that bn254::Fq has exactly 254 bits, which is 2 bits less than 256.
    ///
    /// ## Output
    /// - Returns bytes in **little endian**.
    /// ## Assumptions
    /// - `(x, y)` is a point on BN254 G1Affine.
    /// - `x, y` are in little endian limbs.
    pub fn compress_bn254_g1_affine_point_to_bytes(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        x: [AssignedValue<F>; LIMBS],
        y: [AssignedValue<F>; LIMBS],
    ) -> Vec<SafeByte<F>> {
        let gate = range.gate();
        let x_is_zero = big_is_zero::positive(gate, ctx, OverflowInteger::new(x.to_vec(), BITS));
        let y_is_zero = big_is_zero::positive(gate, ctx, OverflowInteger::new(y.to_vec(), BITS));
        let is_identity = gate.and(ctx, x_is_zero, y_is_zero);

        // boolean
        let y_last_bit = range.get_last_bit(ctx, y[0], BITS);

        // luckily right now BITS is multiple of 8, so limb conversion to bytes is a little easier
        if BITS % 8 != 0 {
            panic!("BITS must be a multiple of 8")
        }
        // even though BITS * LIMBS > 256, we know the whole bigint fits in 256 bits, so we truncate to 32 bytes
        let mut x_bytes = x
            .iter()
            .flat_map(|limb| uint_to_bytes_le(ctx, range, limb, BITS / 8))
            .take(32)
            .collect_vec();
        // last_byte is guaranteed to be 254 % 8 = 6 bits
        let mut last_byte = *x_bytes.last().unwrap().as_ref();
        // sign = y_last_bit << 6
        // last_byte |= sign
        last_byte = gate.mul_add(ctx, y_last_bit, Constant(Fr::from(1 << 6)), last_byte);
        // if is_identity, then answer should be [0u8; 32] with last byte = 0b1000_0000
        // if is_identity, then x_bytes should be all 0s, and y_last_bit = 0, so all we have to do is |= 0b1000_0000 = 1 << 7
        last_byte = gate.mul_add(ctx, is_identity, Constant(Fr::from(1 << 7)), last_byte);
        *x_bytes.last_mut().unwrap() = SafeTypeChip::unsafe_to_byte(last_byte);

        x_bytes
    }
}
