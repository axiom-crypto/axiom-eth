use std::iter::zip;

use axiom_codec::{
    constants::FIELD_IDX_BITS,
    special_values::{
        HEADER_EXTRA_DATA_LEN_FIELD_IDX, HEADER_HASH_FIELD_IDX, HEADER_HEADER_SIZE_FIELD_IDX,
        HEADER_LOGS_BLOOM_FIELD_IDX_OFFSET,
    },
    HiLo,
};
use axiom_eth::{
    block_header::{
        get_block_header_rlp_max_lens_from_extra, EthBlockHeaderChip, EthBlockHeaderWitness,
        BLOCK_HEADER_FIELD_IS_VAR_LEN, EXTRA_DATA_INDEX, NUM_BLOCK_HEADER_FIELDS,
    },
    halo2_base::{
        gates::{flex_gate::threads::parallelize_core, GateInstructions, RangeInstructions},
        safe_types::{SafeBool, SafeTypeChip},
        utils::bit_length,
        AssignedValue, Context,
        QuantumCell::Constant,
    },
    halo2_proofs::plonk::ConstraintSystem,
    keccak::{types::ComponentTypeKeccak, KeccakChip},
    rlc::circuit::builder::RlcCircuitBuilder,
    rlc::circuit::builder::RlcContextPair,
    rlp::RlpChip,
    utils::{
        build_utils::aggregation::CircuitMetadata,
        circuit_utils::extract_array_chunk,
        component::{
            circuit::{
                ComponentBuilder, ComponentCircuitImpl, CoreBuilder, CoreBuilderOutput,
                CoreBuilderOutputParams, CoreBuilderParams,
            },
            promise_collector::PromiseCaller,
            promise_loader::single::PromiseLoader,
            types::FixLenLogical,
            utils::create_hasher,
            LogicalResult,
        },
    },
    utils::{
        circuit_utils::{
            bytes::{pack_bytes_to_hilo, select_hi_lo},
            is_equal_usize, is_in_range, min_with_usize, unsafe_lt_mask,
        },
        load_h256_to_safe_bytes32, unsafe_bytes_to_assigned,
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::common::{extract_logical_results, extract_virtual_table},
    utils::codec::{AssignedHeaderSubquery, AssignedHeaderSubqueryResult},
    Field,
};

use super::{
    mmr_verify::{assign_mmr, verify_mmr_proof, AssignedMmr},
    types::{
        CircuitInputHeaderShard, CircuitInputHeaderSubquery, ComponentTypeHeaderSubquery,
        LogicalPublicInstanceHeader,
    },
};

pub struct CoreBuilderHeaderSubquery<F: Field> {
    input: Option<CircuitInputHeaderShard<F>>,
    params: CoreParamsHeaderSubquery,
    payload: Option<(KeccakChip<F>, Vec<PayloadHeaderSubquery<F>>)>,
}

/// Specify the output format of HeaderSubquery component.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsHeaderSubquery {
    pub max_extra_data_bytes: usize,
    pub capacity: usize,
}
impl CoreBuilderParams for CoreParamsHeaderSubquery {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

/// For header circuit to read promise results.
pub type PromiseLoaderHeaderSubquery<F> = PromiseLoader<F, ComponentTypeKeccak<F>>;
pub type ComponentCircuitHeaderSubquery<F> =
    ComponentCircuitImpl<F, CoreBuilderHeaderSubquery<F>, PromiseLoaderHeaderSubquery<F>>;

impl<F: Field> CircuitMetadata for CoreBuilderHeaderSubquery<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        unreachable!()
    }
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderHeaderSubquery<F> {
    type Params = CoreParamsHeaderSubquery;

    fn new(params: Self::Params) -> Self {
        Self { input: None, params, payload: None }
    }
    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }
    fn clear_witnesses(&mut self) {
        self.payload = None;
    }
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
    fn configure_with_params(_: &mut ConstraintSystem<F>, _: Self::Params) {}
}
impl<F: Field> CoreBuilder<F> for CoreBuilderHeaderSubquery<F> {
    type CompType = ComponentTypeHeaderSubquery<F>;
    type PublicInstanceValue = LogicalPublicInstanceHeader<F>;
    type PublicInstanceWitness = LogicalPublicInstanceHeader<AssignedValue<F>>;
    type CoreInput = CircuitInputHeaderShard<F>;
    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        let (header_rlp_max_bytes, _) =
            get_block_header_rlp_max_lens_from_extra(self.params.max_extra_data_bytes);
        for request in &input.requests {
            if request.header_rlp.len() != header_rlp_max_bytes {
                anyhow::bail!("Header RLP length not resized correctly.");
            }
        }
        self.input = Some(input);
        Ok(())
    }
    // No public instances are assigned inside this function. That is done automatically.
    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_caller: PromiseCaller<F>,
    ) -> CoreBuilderOutput<F, Self::CompType> {
        // preamble: to be removed
        let keccak =
            KeccakChip::new_with_promise_collector(builder.range_chip(), promise_caller.clone());
        let range_chip = keccak.range();
        let rlp = RlpChip::new(range_chip, None);
        let mut poseidon = create_hasher();
        poseidon.initialize_consts(builder.base.main(0), keccak.gate());

        // Assumption: we already have input when calling this function.
        // TODO: automatically derive a dummy input from params.
        let input = self.input.as_ref().unwrap();
        let base_builder = &mut builder.base;
        // assign MMR and compute its keccakPacked
        let ctx = base_builder.main(0);
        let assigned_mmr = assign_mmr(ctx, range_chip, input.mmr);
        let mmr_keccak = assigned_mmr.keccak(ctx, &keccak);
        // handle subqueries
        let pool = base_builder.pool(0);
        let chip = EthBlockHeaderChip::new(rlp, self.params.max_extra_data_bytes);
        let payload = parallelize_core(pool, input.requests.clone(), |ctx, subquery| {
            handle_single_header_subquery_phase0(ctx, &chip, &keccak, &subquery, &assigned_mmr)
        });

        let vt = extract_virtual_table(payload.iter().map(|p| p.output));
        let lr: Vec<LogicalResult<F, Self::CompType>> =
            extract_logical_results(payload.iter().map(|p| p.output));

        let logical_pis =
            LogicalPublicInstanceHeader { mmr_keccak: HiLo::from_hi_lo(mmr_keccak.hi_lo()) };
        self.payload = Some((keccak, payload));

        CoreBuilderOutput {
            public_instances: logical_pis.into_raw(),
            virtual_table: vt,
            logical_results: lr,
        }
    }

    // There is no additional logic necessary for component commitments.
    fn virtual_assign_phase1(&mut self, builder: &mut RlcCircuitBuilder<F>) {
        let (keccak, payload) = self.payload.take().unwrap();
        // preamble
        let range_chip = keccak.range();
        let rlc_chip = builder.rlc_chip(&range_chip.gate);
        let rlp = RlpChip::new(range_chip, Some(&rlc_chip));

        // actual logic
        let chip = EthBlockHeaderChip::new(rlp, self.params.max_extra_data_bytes);
        builder.parallelize_phase1(payload, |(ctx_gate, ctx_rlc), payload| {
            handle_single_header_subquery_phase1((ctx_gate, ctx_rlc), &chip, payload)
        });
    }
}

/// Non-value types are right padded with zeros.
/// "Value" type in the sense of [Solidity](https://docs.soliditylang.org/en/latest/types.html). Essentially everything that's not a variable length array.
/// We should conform to how Value types are left vs right padded with zeros in EVM memory: https://ethdebug.github.io/solidity-data-representation/#table-of-direct-types
/// There is currently no type in block header that is `bytesN` where `N < 32`. If there were, we would want to *right pad* those with zeros.
/// `bytes32` is neither left nor right padded.
///
/// Currently `logsBloom` (fixed len 256 bytes) and `extraData` (var len bytes) are not left padded.
pub const BLOCK_HEADER_FIELD_SHOULD_LEFT_PAD: [bool; NUM_BLOCK_HEADER_FIELDS] = [
    true, true, true, true, true, true, false, true, true, true, true, true, false, true, true,
    true, true, true, true, true,
];

pub struct PayloadHeaderSubquery<F: Field> {
    pub header_witness: EthBlockHeaderWitness<F>,
    pub output: AssignedHeaderSubqueryResult<F>,
}

/// Assigns `subquery` to virtual cells and then handles the subquery to get result.
pub fn handle_single_header_subquery_phase0<F: Field>(
    ctx: &mut Context<F>,
    chip: &EthBlockHeaderChip<F>,
    keccak: &KeccakChip<F>,
    subquery: &CircuitInputHeaderSubquery,
    assigned_mmr: &AssignedMmr<F>,
) -> PayloadHeaderSubquery<F> {
    let gate = chip.gate();
    let range = chip.range();
    let safe = SafeTypeChip::new(range);
    let header_rlp = unsafe_bytes_to_assigned(ctx, &subquery.header_rlp);
    // parse the header RLP
    let header_witness = chip.decompose_block_header_phase0(ctx, keccak, &header_rlp);

    // verify MMR proof for this block
    let block_number = header_witness.get_number_value(ctx, gate);
    let block_hash = header_witness.block_hash.output_bytes.clone();
    let mmr_proof = (subquery.mmr_proof.iter())
        .map(|&node| load_h256_to_safe_bytes32(ctx, &safe, node))
        .collect();
    verify_mmr_proof(ctx, keccak, assigned_mmr, block_number, block_hash, mmr_proof, None);

    let field_idx = ctx.load_witness(F::from(subquery.field_idx as u64));
    range.range_check(ctx, field_idx, FIELD_IDX_BITS);
    // if `field_idx` < `HEADER_HASH_IDX`, then it is an actual header field
    let threshold = Constant(F::from(HEADER_HASH_FIELD_IDX as u64));
    let is_idx_in_header = range.is_less_than(ctx, field_idx, threshold, FIELD_IDX_BITS);
    let header_idx = gate.mul(ctx, field_idx, is_idx_in_header);

    let (_, header_fields_max_bytes) =
        get_block_header_rlp_max_lens_from_extra(chip.max_extra_data_bytes);
    // Left pad value types to 32 bytes and convert to HiLo
    let header_fixed = zip(BLOCK_HEADER_FIELD_IS_VAR_LEN, BLOCK_HEADER_FIELD_SHOULD_LEFT_PAD)
        .zip_eq(&header_witness.rlp_witness.field_witness)
        .enumerate()
        .map(|(i, ((is_var_len, left_pad), w))| {
            let inputs = w.field_cells.clone();
            let fixed_bytes = if is_var_len && left_pad {
                let len = w.field_len;
                let var_len_bytes = SafeTypeChip::unsafe_to_var_len_bytes_vec(
                    inputs,
                    len,
                    header_fields_max_bytes[i],
                );
                assert!(var_len_bytes.max_len() <= 32);
                var_len_bytes.left_pad_to_fixed(ctx, gate)
            } else {
                let len = inputs.len();
                // currently the only var len field that is not value type is `extraData`
                SafeTypeChip::unsafe_to_fix_len_bytes_vec(inputs, len)
            };
            let mut fixed_bytes = fixed_bytes.into_bytes();
            if fixed_bytes.len() > 32 {
                assert!(!left_pad);
                fixed_bytes.truncate(32);
            }
            // constrain `extraData` is 0s after length
            if i == EXTRA_DATA_INDEX {
                let mut len = w.field_len;
                if chip.max_extra_data_bytes > 32 {
                    let max_bits = bit_length(chip.max_extra_data_bytes as u64);
                    len = min_with_usize(ctx, range, len, 32, max_bits);
                }
                let mask = unsafe_lt_mask(ctx, gate, len, 32);
                for (byte, mask) in fixed_bytes.iter_mut().zip_eq(mask) {
                    *byte = SafeTypeChip::unsafe_to_byte(gate.mul(ctx, *byte, mask));
                }
            }

            // Slightly more optimal to pack to 20 bytes for `beneficiary` but HiLo is cleaner, so we'll sacrifice the optimization
            pack_bytes_to_hilo(ctx, gate, &fixed_bytes).hi_lo()
        })
        .collect_vec();
    let header_indicator = gate.idx_to_indicator(ctx, header_idx, header_fixed.len());
    let value = gate.select_array_by_indicator(ctx, &header_fixed, &header_indicator);
    let mut value = HiLo::from_hi_lo(value.try_into().unwrap());
    // time to handle special cases:
    let [return_hash, return_size, return_extra_data_len] =
        [HEADER_HASH_FIELD_IDX, HEADER_HEADER_SIZE_FIELD_IDX, HEADER_EXTRA_DATA_LEN_FIELD_IDX]
            .map(|const_idx| is_equal_usize(ctx, gate, field_idx, const_idx));
    // return block hash
    let block_hash = HiLo::from_hi_lo(header_witness.get_block_hash_hi_lo());
    value = select_hi_lo(ctx, gate, &block_hash, &value, return_hash);
    // return block size in bytes
    let block_size = HiLo::from_hi_lo([ctx.load_zero(), header_witness.rlp_witness.rlp_len]);
    value = select_hi_lo(ctx, gate, &block_size, &value, return_size);
    // return extra data length in bytes
    let extra_data = header_witness.get_extra_data();
    let extra_data_len = HiLo::from_hi_lo([ctx.load_zero(), extra_data.field_len]);
    value = select_hi_lo(ctx, gate, &extra_data_len, &value, return_extra_data_len);

    let (logs_bloom_buf, return_logs_bloom) = handle_logs_bloom(
        ctx,
        range,
        &header_witness.get_logs_bloom().field_cells,
        field_idx,
        HEADER_LOGS_BLOOM_FIELD_IDX_OFFSET,
    );
    value = select_hi_lo(ctx, gate, &logs_bloom_buf, &value, return_logs_bloom);

    // constrain that `field_idx` is valid: either
    // - `field_idx` is less than true length of block header list
    //   - this means you cannot request a field such as `withdrawalsRoot` if the block is before EIP-4895
    // - or `field_idx` is one of the special return cases `header_idx` is less than true length of block header list
    let is_valid_header_idx =
        range.is_less_than(ctx, header_idx, header_witness.get_list_len(), FIELD_IDX_BITS);
    // This sum is guaranteed to be 0 or 1:
    let is_special_case =
        gate.sum(ctx, [return_hash, return_size, return_extra_data_len, return_logs_bloom]);
    let is_valid = gate.select(ctx, is_valid_header_idx, is_special_case, is_idx_in_header);
    gate.assert_is_const(ctx, &is_valid, &F::ONE);

    PayloadHeaderSubquery {
        header_witness,
        output: AssignedHeaderSubqueryResult {
            subquery: AssignedHeaderSubquery { block_number, field_idx },
            value,
        },
    }
}

pub fn handle_single_header_subquery_phase1<F: Field>(
    ctx: RlcContextPair<F>,
    chip: &EthBlockHeaderChip<F>,
    payload: PayloadHeaderSubquery<F>,
) {
    chip.decompose_block_header_phase1(ctx, payload.header_witness);
}

/// Returns `HiLo(logs_bloom_bytes[logs_bloom_idx..logs_bloom_idx + 32]), is_in_range`
/// where `logs_bloom_idx = field_idx - logs_bloom_field_idx_offset` and
/// `is_in_range = (0..8).contains(logs_bloom_idx)`
pub(crate) fn handle_logs_bloom<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    logs_bloom_bytes: &[AssignedValue<F>],
    field_idx: AssignedValue<F>,
    logs_bloom_field_idx_offset: usize,
) -> (HiLo<AssignedValue<F>>, SafeBool<F>) {
    let offset = logs_bloom_field_idx_offset;
    let is_offset = is_in_range(ctx, range, field_idx, offset..offset + 8, FIELD_IDX_BITS);
    let gate = range.gate();
    let mut shift = gate.sub(ctx, field_idx, Constant(F::from(offset as u64)));
    shift = gate.mul(ctx, shift, *is_offset.as_ref());
    let buffer = extract_array_chunk(ctx, gate, logs_bloom_bytes, shift, 32);
    let buffer = SafeTypeChip::unsafe_to_fix_len_bytes_vec(buffer, 32);
    (pack_bytes_to_hilo(ctx, gate, buffer.bytes()), is_offset)
}

#[cfg(test)]
mod test {
    use axiom_eth::block_header::{EXTRA_DATA_INDEX, LOGS_BLOOM_INDEX};

    use super::BLOCK_HEADER_FIELD_SHOULD_LEFT_PAD;

    #[test]
    fn test_block_header_value_types() {
        for (i, &is_value) in BLOCK_HEADER_FIELD_SHOULD_LEFT_PAD.iter().enumerate() {
            if !is_value {
                assert!(i == LOGS_BLOOM_INDEX || i == EXTRA_DATA_INDEX);
            }
        }
    }
}
