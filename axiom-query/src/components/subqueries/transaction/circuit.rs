use std::iter::zip;

use axiom_codec::{
    constants::FIELD_IDX_BITS,
    encoder::field_elements::SUBQUERY_OUTPUT_BYTES,
    special_values::{
        TX_BLOCK_NUMBER_FIELD_IDX, TX_CALLDATA_HASH_FIELD_IDX, TX_CALLDATA_IDX_OFFSET,
        TX_CONTRACT_DATA_IDX_OFFSET, TX_CONTRACT_DEPLOY_SELECTOR_VALUE, TX_DATA_LENGTH_FIELD_IDX,
        TX_FUNCTION_SELECTOR_FIELD_IDX, TX_NO_CALLDATA_SELECTOR_VALUE, TX_TX_INDEX_FIELD_IDX,
        TX_TX_TYPE_FIELD_IDX,
    },
    HiLo,
};
use axiom_eth::{
    block_header::TX_ROOT_INDEX,
    halo2_base::{
        gates::{flex_gate::threads::parallelize_core, GateInstructions, RangeInstructions},
        safe_types::{SafeBool, SafeTypeChip, VarLenBytesVec},
        utils::bit_length,
        AssignedValue, Context,
        QuantumCell::Constant,
    },
    halo2_proofs::plonk::ConstraintSystem,
    keccak::{types::ComponentTypeKeccak, KeccakChip},
    mpt::MPTChip,
    rlc::circuit::builder::RlcCircuitBuilder,
    rlc::circuit::builder::RlcContextPair,
    rlp::RlpChip,
    transaction::{
        EthTransactionChip, EthTransactionChipParams, EthTransactionWitness, TRANSACTION_MAX_FIELDS,
    },
    utils::{
        build_utils::aggregation::CircuitMetadata,
        bytes_be_to_uint,
        circuit_utils::{
            bytes::{pack_bytes_to_hilo, select_hi_lo, unsafe_mpt_root_to_hi_lo},
            extract_array_chunk_and_constrain_trailing_zeros, is_equal_usize, is_gte_usize,
            is_in_range, is_lt_usize, min_with_usize, unsafe_constrain_trailing_zeros,
        },
        component::{
            circuit::{
                ComponentBuilder, ComponentCircuitImpl, CoreBuilder, CoreBuilderOutput,
                CoreBuilderOutputParams, CoreBuilderParams,
            },
            promise_collector::PromiseCaller,
            promise_loader::{combo::PromiseBuilderCombo, single::PromiseLoader},
            types::LogicalEmpty,
            utils::create_hasher,
            LogicalResult,
        },
        constrain_vec_equal,
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::{
        block_header::types::{ComponentTypeHeaderSubquery, FieldHeaderSubqueryCall},
        common::{extract_logical_results, extract_virtual_table},
    },
    utils::codec::{AssignedHeaderSubquery, AssignedTxSubquery, AssignedTxSubqueryResult},
    Field,
};

use super::{
    types::{CircuitInputTxShard, CircuitInputTxSubquery, ComponentTypeTxSubquery},
    TX_DATA_FIELD_IDX,
};

pub struct CoreBuilderTxSubquery<F: Field> {
    input: Option<CircuitInputTxShard<F>>,
    params: CoreParamsTxSubquery,
    payload: Option<(KeccakChip<F>, Vec<PayloadTxSubquery<F>>)>,
}

/// Specify the output format of TxSubquery component.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsTxSubquery {
    pub chip_params: EthTransactionChipParams,
    /// The maximum number of subqueries of this type allowed in a single circuit.
    pub capacity: usize,
    /// The maximum depth of the transactions MPT trie supported by this circuit.
    /// The depth is defined as the maximum length of a Merkle proof, where the proof always ends in a terminal node (if the proof ends in a branch, we extract the leaf and add it as a separate node).
    ///
    /// In practice this can always be set to 6, because
    /// transaction index is within u16, so rlp(txIndex) is at most 3 bytes => 6 nibbles.
    pub max_trie_depth: usize,
}
impl CoreBuilderParams for CoreParamsTxSubquery {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

type CKeccak<F> = ComponentTypeKeccak<F>;
type CHeader<F> = ComponentTypeHeaderSubquery<F>;
pub type PromiseLoaderTxSubquery<F> =
    PromiseBuilderCombo<F, PromiseLoader<F, CKeccak<F>>, PromiseLoader<F, CHeader<F>>>;
pub type ComponentCircuitTxSubquery<F> =
    ComponentCircuitImpl<F, CoreBuilderTxSubquery<F>, PromiseLoaderTxSubquery<F>>;

impl<F: Field> CircuitMetadata for CoreBuilderTxSubquery<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        unreachable!()
    }
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderTxSubquery<F> {
    type Params = CoreParamsTxSubquery;

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

impl<F: Field> CoreBuilder<F> for CoreBuilderTxSubquery<F> {
    type CompType = ComponentTypeTxSubquery<F>;
    type PublicInstanceValue = LogicalEmpty<F>;
    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;
    type CoreInput = CircuitInputTxShard<F>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        for r in &input.requests {
            if r.proof.proof.max_depth != self.params.max_trie_depth {
                anyhow::bail!(
                    "TxSubquery: request proof max depth {} does not match the configured max_depth {}",
                    r.proof.proof.max_depth,
                    self.params.max_trie_depth
                );
            }
        }
        self.input = Some(input);
        Ok(())
    }
    /// Includes computing the component commitment to the logical output (the subquery results).
    /// **In addition** performs _promise calls_ to the Header Component to verify
    /// all `(block_number, transaction_root)` pairs as additional "enriched" header subqueries.
    /// These are checked against the supplied promise commitment using dynamic lookups
    /// (behind the scenes) by `promise_caller`.
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

        let mpt = MPTChip::new(rlp, &keccak);
        let chip = EthTransactionChip::new(&mpt, self.params.chip_params);
        let base_builder = &mut builder.base;
        // actual logic
        let payload =
            parallelize_core(base_builder.pool(0), input.requests.clone(), |ctx, subquery| {
                handle_single_tx_subquery_phase0(ctx, &chip, &subquery)
            });

        let vt = extract_virtual_table(payload.iter().map(|p| p.output));
        let lr: Vec<LogicalResult<F, Self::CompType>> =
            extract_logical_results(payload.iter().map(|p| p.output));
        let ctx = base_builder.main(0);

        // promise calls to header component:
        // - for each block number in a subquery, we must make a promise call to check the transaction root of that block
        let header_tx_root_idx = ctx.load_constant(F::from(TX_ROOT_INDEX as u64));
        for p in payload.iter() {
            let block_number = p.output.subquery.block_number;
            let tx_root = p.tx_root;
            let header_subquery =
                AssignedHeaderSubquery { block_number, field_idx: header_tx_root_idx };
            let promise_tx_root = promise_caller
                .call::<FieldHeaderSubqueryCall<F>, ComponentTypeHeaderSubquery<F>>(
                    ctx,
                    FieldHeaderSubqueryCall(header_subquery),
                )
                .unwrap();
            constrain_vec_equal(ctx, &tx_root.hi_lo(), &promise_tx_root.hi_lo());
        }
        self.payload = Some((keccak, payload));
        CoreBuilderOutput { public_instances: vec![], virtual_table: vt, logical_results: lr }
    }

    fn virtual_assign_phase1(&mut self, builder: &mut RlcCircuitBuilder<F>) {
        let (keccak, payload) = self.payload.take().unwrap();
        // preamble
        let range_chip = keccak.range();
        let rlc_chip = builder.rlc_chip(&range_chip.gate);
        let rlp = RlpChip::new(range_chip, Some(&rlc_chip));
        let mpt = MPTChip::new(rlp, &keccak);
        let chip = EthTransactionChip::new(&mpt, self.params.chip_params);

        // actual logic
        builder.parallelize_phase1(payload, |(ctx_gate, ctx_rlc), payload| {
            handle_single_tx_subquery_phase1((ctx_gate, ctx_rlc), &chip, payload)
        });
    }
}

pub struct PayloadTxSubquery<F: Field> {
    pub tx_witness: EthTransactionWitness<F>,
    pub tx_root: HiLo<AssignedValue<F>>,
    pub output: AssignedTxSubqueryResult<F>,
}

/// Assigns `subquery` to virtual cells and then handles the subquery to get result.
/// **Assumes** that the transactionsRoot is verified. Returns the assigned private witnesses of
/// `(block_number, transactionsRoot)`, to be looked up against Header Component promise.
pub fn handle_single_tx_subquery_phase0<F: Field>(
    ctx: &mut Context<F>,
    chip: &EthTransactionChip<F>,
    subquery: &CircuitInputTxSubquery,
) -> PayloadTxSubquery<F> {
    let gate = chip.gate();
    let range = chip.range();
    // assign tx proof
    let tx_proof = subquery.proof.clone().assign(ctx);
    // convert transactionsRoot from bytes to HiLo for later. `parse_transaction_proof` will constrain these witnesses to be bytes
    let tx_root = unsafe_mpt_root_to_hi_lo(ctx, gate, &tx_proof.proof);
    // Check the transaction MPT proof
    let tx_witness = chip.parse_transaction_proof_phase0(ctx, tx_proof);
    let tx_type = tx_witness.transaction_type;
    range.check_less_than_safe(ctx, tx_type, 3);
    let tx_type_indicator: [_; 3] = gate.idx_to_indicator(ctx, tx_type, 3).try_into().unwrap();
    // index of `data` in rlp list
    let data_list_idx =
        gate.select_by_indicator(ctx, [5, 6, 7].map(|x| Constant(F::from(x))), tx_type_indicator);
    // We always need the `data` field, so extract it
    // this function also asserts that the MPT proof is an inclusion proof
    let data = chip.extract_field(ctx, tx_witness, data_list_idx);
    let tx_witness = data.transaction_witness; // pass through
                                               // the byte length of `data`
    let data_len = data.len;
    let data = data.field_bytes;

    let field_or_calldata_idx = ctx.load_witness(F::from(subquery.field_or_calldata_idx as u64));
    range.range_check(ctx, field_or_calldata_idx, FIELD_IDX_BITS);
    // if `field_idx` < `TX_CALLDATA_IDX_OFFSET`, then it is an actual tx rlp list item
    let is_idx_in_list =
        is_lt_usize(ctx, range, field_or_calldata_idx, TX_TX_TYPE_FIELD_IDX, FIELD_IDX_BITS);
    // if `field_or_calldata_idx` is not `field_idx`, set it to 1. (Don't put 0 because that's invalid field_idx for type 0 tx)
    let field_idx = gate.select(ctx, field_or_calldata_idx, Constant(F::ONE), is_idx_in_list);

    let list_idx = v2_map_field_idx_by_tx_type(ctx, range, field_idx, tx_type_indicator);
    let value = extract_truncated_field(ctx, range, &tx_witness, list_idx, SUBQUERY_OUTPUT_BYTES);
    // we should left pad with 0s to fixed *unless* `field_idx == TX_DATA_FIELD_IDX` (or accessList but that is not supported)
    let value_fixed = value.left_pad_to_fixed(ctx, gate);
    let is_not_value_type =
        gate.is_equal(ctx, field_idx, Constant(F::from(TX_DATA_FIELD_IDX as u64)));
    let value = zip(value.bytes(), value_fixed.bytes())
        .map(|(var, fixed)| gate.select(ctx, *var, *fixed, is_not_value_type))
        .collect_vec();
    let value = SafeTypeChip::unsafe_to_fix_len_bytes_vec(value, SUBQUERY_OUTPUT_BYTES);
    let mut value = pack_bytes_to_hilo(ctx, gate, value.bytes());

    let block_number = ctx.load_witness(F::from(subquery.block_number));
    let tx_idx = tx_witness.idx;
    // time to handle special cases:
    let [return_tx_type, return_block_num, return_tx_index, return_function_selector, return_calldata_hash, return_data_length] =
        [
            TX_TX_TYPE_FIELD_IDX,
            TX_BLOCK_NUMBER_FIELD_IDX,
            TX_TX_INDEX_FIELD_IDX,
            TX_FUNCTION_SELECTOR_FIELD_IDX,
            TX_CALLDATA_HASH_FIELD_IDX,
            TX_DATA_LENGTH_FIELD_IDX,
        ]
        .map(|const_idx| is_equal_usize(ctx, gate, field_or_calldata_idx, const_idx));
    let const_zero = ctx.load_zero();
    let from_lo = |lo| HiLo::from_hi_lo([const_zero, lo]);
    value = select_hi_lo(ctx, gate, &from_lo(tx_type), &value, return_tx_type);
    value = select_hi_lo(ctx, gate, &from_lo(block_number), &value, return_block_num);
    value = select_hi_lo(ctx, gate, &from_lo(tx_idx), &value, return_tx_index);

    // function selector case
    // index of `to` in rlp list
    let to_list_idx =
        gate.select_by_indicator(ctx, [3, 4, 5].map(|x| Constant(F::from(x))), tx_type_indicator);
    // the byte length of `to`
    let to_len = gate.select_from_idx(
        ctx,
        tx_witness.value_witness().field_witness.iter().map(|w| w.field_len),
        to_list_idx,
    );
    let function_selector = {
        // if `to_len == 0` && `data_len != 0` return `TX_CONTRACT_DEPLOY_SELECTOR`
        let mut is_contract_deploy = gate.is_zero(ctx, to_len);
        let empty_data = gate.is_zero(ctx, data_len);
        is_contract_deploy = gate.mul_not(ctx, empty_data, is_contract_deploy);
        // if `return_function_selector == 1` then `is_contractor_deploy || empty_data == 1`
        let no_sel = gate.add(ctx, is_contract_deploy, empty_data);
        let ret1 = gate.select(
            ctx,
            Constant(F::from(TX_CONTRACT_DEPLOY_SELECTOR_VALUE as u64)),
            Constant(F::from(TX_NO_CALLDATA_SELECTOR_VALUE as u64)),
            is_contract_deploy,
        );

        let len_gte_4 = is_gte_usize(ctx, range, data_len, 4, 32);
        let selector_bytes =
            data[..4].iter().map(|b| SafeTypeChip::unsafe_to_byte(*b)).collect_vec();
        let ret2 = bytes_be_to_uint(ctx, gate, &selector_bytes, 4);
        // valid if no_sel || len_gte4
        let mut is_valid = gate.or(ctx, no_sel, len_gte_4);
        is_valid = gate.select(ctx, is_valid, Constant(F::ONE), return_function_selector);
        gate.assert_is_const(ctx, &is_valid, &F::ONE);
        gate.select(ctx, ret1, ret2, no_sel)
    };
    value = select_hi_lo(ctx, gate, &from_lo(function_selector), &value, return_function_selector);
    value = select_hi_lo(ctx, gate, &from_lo(data_len), &value, return_data_length);

    let (data_buf, return_data) = handle_data(ctx, range, &data, data_len, field_or_calldata_idx);
    value = select_hi_lo(ctx, gate, &data_buf, &value, return_data);
    // dbg!(return_data.as_ref().value());

    // calldata hash case
    // IMPORTANT: we set the length to 0 so it doesn't actually request a keccak unless `return_calldata_hash == 1`
    let tmp_data_len = gate.mul(ctx, data_len, return_calldata_hash);
    let data_hash = chip.keccak().keccak_var_len(ctx, data.clone(), tmp_data_len, 0).hi_lo();
    value = select_hi_lo(ctx, gate, &HiLo::from_hi_lo(data_hash), &value, return_calldata_hash);
    // dbg!(field_or_calldata_idx.value());
    // dbg!(value.hi_lo().map(|v| *v.value()));

    // is valid if either:
    // - `is_idx_in_list` and `field_idx` is validated (validation done by `v2_map_field_idx_by_tx_type`)
    // - `field_or_calldata_idx` is one of the special cases (individual validation was done per case)
    // This sum is guaranteed to be 0 or 1 because the cases are mutually exclusive:
    let is_special_case = gate.sum(
        ctx,
        [
            return_tx_type,
            return_block_num,
            return_tx_index,
            return_function_selector,
            return_calldata_hash,
            return_data_length,
            return_data,
        ],
    );
    let is_valid = gate.or(ctx, is_idx_in_list, is_special_case);
    gate.assert_is_const(ctx, &is_valid, &F::ONE);

    PayloadTxSubquery {
        tx_witness,
        tx_root,
        output: AssignedTxSubqueryResult {
            subquery: AssignedTxSubquery { block_number, tx_idx, field_or_calldata_idx },
            value,
        },
    }
}

pub fn handle_single_tx_subquery_phase1<F: Field>(
    ctx: RlcContextPair<F>,
    chip: &EthTransactionChip<F>,
    payload: PayloadTxSubquery<F>,
) {
    chip.parse_transaction_proof_phase1(ctx, payload.tx_witness);
}

fn handle_data<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    data_bytes: &[AssignedValue<F>],
    data_len: AssignedValue<F>,
    field_idx: AssignedValue<F>,
) -> (HiLo<AssignedValue<F>>, SafeBool<F>) {
    let gate = range.gate();
    let in_calldata_range = is_in_range(
        ctx,
        range,
        field_idx,
        TX_CALLDATA_IDX_OFFSET..TX_CONTRACT_DATA_IDX_OFFSET,
        FIELD_IDX_BITS,
    );
    let in_contract_data_range =
        is_gte_usize(ctx, range, field_idx, TX_CONTRACT_DATA_IDX_OFFSET, FIELD_IDX_BITS);

    let calldata_shift = gate.sub(ctx, field_idx, Constant(F::from(TX_CALLDATA_IDX_OFFSET as u64)));
    let contract_data_shift =
        gate.sub(ctx, field_idx, Constant(F::from(TX_CONTRACT_DATA_IDX_OFFSET as u64)));
    let mut shift = gate.select(ctx, calldata_shift, contract_data_shift, in_calldata_range);
    // shift by 4 if in_calldata_range
    let buffer = (0..data_bytes.len())
        .map(|i| {
            if i + 4 < data_bytes.len() {
                gate.select(ctx, data_bytes[i + 4], data_bytes[i], in_calldata_range)
            } else {
                gate.mul_not(ctx, in_calldata_range, data_bytes[i])
            }
        })
        .collect_vec();
    let is_valid_calldata =
        is_gte_usize(ctx, range, data_len, 4, bit_length(data_bytes.len() as u64));
    let mut buffer_len = gate.sub_mul(ctx, data_len, Constant(F::from(4)), in_calldata_range);
    // if !is_valid_calldata && in_calldata_range, then set buffer_len = 0 (otherwise it's negative and will overflow)
    let buffer_len_is_negative = gate.mul_not(ctx, is_valid_calldata, in_calldata_range);
    buffer_len = gate.mul_not(ctx, buffer_len_is_negative, buffer_len);
    // is_in_range = (in_calldata_range && is_valid_calldata) || in_contract_data_range
    let is_in_range =
        gate.mul_add(ctx, in_calldata_range, is_valid_calldata, in_contract_data_range);
    shift = gate.mul(ctx, shift, is_in_range);
    let (buffer, is_lt_len) = extract_array_chunk_and_constrain_trailing_zeros(
        ctx,
        range,
        &buffer,
        buffer_len,
        shift,
        32,
        FIELD_IDX_BITS,
    );

    let is_in_range = SafeTypeChip::unsafe_to_bool(gate.and(ctx, is_in_range, is_lt_len));
    let buffer = SafeTypeChip::unsafe_to_fix_len_bytes_vec(buffer, 32);
    (pack_bytes_to_hilo(ctx, gate, buffer.bytes()), is_in_range)
}

/// Extracts the field at `field_idx` from the given rlp list decomposition of a transaction.
/// The field is truncated to the first `truncated_byte_len` bytes.
///
/// We do not use `EthTransactionChip::extract_field` because without the truncation the
/// select operation can be very expensive if the `data` field is very long.
pub fn extract_truncated_field<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    witness: &EthTransactionWitness<F>,
    list_idx: AssignedValue<F>,
    truncated_byte_len: usize,
) -> VarLenBytesVec<F> {
    let gate = range.gate();
    let tx_values = &witness.value_witness().field_witness;
    let indicator = gate.idx_to_indicator(ctx, list_idx, TRANSACTION_MAX_FIELDS);
    assert_eq!(tx_values.len(), TRANSACTION_MAX_FIELDS);
    let const_zero = ctx.load_zero();
    let mut field_bytes = (0..truncated_byte_len)
        .map(|i| {
            let entries = tx_values.iter().map(|w| *w.field_cells.get(i).unwrap_or(&const_zero));
            gate.select_by_indicator(ctx, entries, indicator.clone())
        })
        .collect_vec();
    let lens = tx_values.iter().map(|w| w.field_len);
    let mut len = gate.select_by_indicator(ctx, lens, indicator);
    // len = min(len, truncated_byte_len)
    let max_bytes = tx_values.iter().map(|w| w.field_cells.len()).max().unwrap();
    let max_bits = bit_length(max_bytes as u64);
    len = min_with_usize(ctx, range, len, truncated_byte_len, max_bits);

    unsafe_constrain_trailing_zeros(ctx, gate, &mut field_bytes, len);

    SafeTypeChip::unsafe_to_var_len_bytes_vec(field_bytes, len, truncated_byte_len)
}

// spreadsheet is easiest way to explain: https://docs.google.com/spreadsheets/d/1KoNZTr5vkcPTekzUzXCo0EycsbhuC6z-Z0vMtD4_9us/edit?usp=sharing
/// Constrains that `tx_type` is in [0,2].
/// We do not allow accessList in V2.
fn v2_map_field_idx_by_tx_type<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    field_idx: AssignedValue<F>,
    tx_type_indicator: [AssignedValue<F>; 3],
) -> AssignedValue<F> {
    let max_bits = FIELD_IDX_BITS;
    let gate = range.gate();
    let const_invalid = Constant(F::from(99));
    // a lot of hardcoded stuff
    let in_range = range.is_less_than(ctx, field_idx, Constant(F::from(12)), max_bits);
    let is_gte_4 = is_gte_usize(ctx, range, field_idx, 4, max_bits);
    let is_gas_price = gate.is_equal(ctx, field_idx, Constant(F::from(8)));
    let type_0 = {
        let is_gte_9 = is_gte_usize(ctx, range, field_idx, 9, max_bits);
        let shift_three = is_gte_9.into();
        let is_lt_9 = gate.not(ctx, is_gte_9);
        let shift_two = gate.and(ctx, is_gte_4, is_lt_9);
        let shift_one = gate.is_equal(ctx, field_idx, Constant(F::ONE));
        let mut is_valid = gate.sum(ctx, [shift_one, shift_two, shift_three]);
        is_valid = gate.and(ctx, is_valid, in_range);
        let mut idx = field_idx;
        // the three shifts are mutually exclusive
        idx = gate.sub_mul(ctx, idx, shift_three, Constant(F::from(3)));
        idx = gate.sub_mul(ctx, idx, shift_two, Constant(F::from(2)));
        idx = gate.sub_mul(ctx, idx, shift_one, Constant(F::ONE));
        idx = gate.select(ctx, Constant(F::from(1)), idx, is_gas_price);
        gate.select(ctx, idx, const_invalid, is_valid)
    };
    let type_1 = {
        let shift_one = is_gte_4;
        let is_max_priority_fee = gate.is_equal(ctx, field_idx, Constant(F::from(2)));
        let is_max_fee = gate.is_equal(ctx, field_idx, Constant(F::from(3)));
        let mut is_valid = gate.mul_not(ctx, is_max_priority_fee, in_range);
        is_valid = gate.mul_not(ctx, is_max_fee, is_valid);
        let mut idx = gate.sub_mul(ctx, field_idx, shift_one, Constant(F::ONE));
        idx = gate.select(ctx, Constant(F::from(2)), idx, is_gas_price);
        gate.select(ctx, idx, const_invalid, is_valid)
    };
    let type_2 = {
        let is_valid = gate.mul_not(ctx, is_gas_price, in_range);
        gate.select(ctx, field_idx, const_invalid, is_valid)
    };

    let true_idx = gate.select_by_indicator(ctx, [type_0, type_1, type_2], tx_type_indicator);
    let is_invalid = gate.is_equal(ctx, true_idx, const_invalid);
    gate.assert_is_const(ctx, &is_invalid, &F::ZERO);

    true_idx
}
