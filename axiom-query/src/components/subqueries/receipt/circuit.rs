use std::iter::zip;

use axiom_codec::{
    constants::FIELD_IDX_BITS,
    encoder::field_elements::SUBQUERY_OUTPUT_BYTES,
    special_values::{
        RECEIPT_ADDRESS_IDX, RECEIPT_BLOCK_NUMBER_FIELD_IDX, RECEIPT_DATA_IDX_OFFSET,
        RECEIPT_LOGS_BLOOM_IDX_OFFSET, RECEIPT_LOG_IDX_OFFSET, RECEIPT_TX_INDEX_FIELD_IDX,
        RECEIPT_TX_TYPE_FIELD_IDX,
    },
    HiLo,
};
use axiom_eth::{
    block_header::RECEIPT_ROOT_INDEX,
    halo2_base::{
        gates::{flex_gate::threads::parallelize_core, GateInstructions, RangeInstructions},
        safe_types::{SafeBool, SafeByte, SafeTypeChip, VarLenBytesVec},
        utils::bit_length,
        AssignedValue, Context,
        QuantumCell::Constant,
    },
    halo2_proofs::plonk::ConstraintSystem,
    keccak::{types::ComponentTypeKeccak, KeccakChip},
    mpt::MPTChip,
    receipt::{
        EthReceiptChip, EthReceiptChipParams, EthReceiptLogFieldWitness, EthReceiptLogWitness,
        EthReceiptWitness, RECEIPT_NUM_FIELDS,
    },
    rlc::circuit::builder::RlcCircuitBuilder,
    rlc::circuit::builder::RlcContextPair,
    rlp::RlpChip,
    utils::{
        build_utils::aggregation::CircuitMetadata,
        circuit_utils::{
            bytes::{pack_bytes_to_hilo, select_hi_lo_by_indicator, unsafe_mpt_root_to_hi_lo},
            extract_array_chunk_and_constrain_trailing_zeros, is_equal_usize, is_gte_usize,
            is_lt_usize, min_with_usize, unsafe_constrain_trailing_zeros,
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
        constrain_vec_equal, is_zero_vec, unsafe_bytes_to_assigned,
    },
};
use itertools::{zip_eq, Itertools};
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::{
        block_header::{
            circuit::handle_logs_bloom,
            types::{ComponentTypeHeaderSubquery, FieldHeaderSubqueryCall},
        },
        common::{extract_logical_results, extract_virtual_table},
    },
    utils::codec::{
        AssignedHeaderSubquery, AssignedReceiptSubquery, AssignedReceiptSubqueryResult,
    },
    Field,
};

use super::{
    types::{CircuitInputReceiptShard, CircuitInputReceiptSubquery, ComponentTypeReceiptSubquery},
    DUMMY_LOG,
};

/// The fieldIdx for cumulativeGas
const CUMULATIVE_GAS_FIELD_IDX: usize = 2;

pub struct CoreBuilderReceiptSubquery<F: Field> {
    input: Option<CircuitInputReceiptShard<F>>,
    params: CoreParamsReceiptSubquery,
    payload: Option<(KeccakChip<F>, Vec<PayloadReceiptSubquery<F>>)>,
}

/// Specify the output format of ReceiptSubquery component.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsReceiptSubquery {
    pub chip_params: EthReceiptChipParams,
    /// The maximum number of subqueries of this type allowed in a single circuit.
    pub capacity: usize,
    /// The maximum depth of the receipt MPT trie supported by this circuit.
    /// The depth is defined as the maximum length of a Merkle proof, where the proof always ends in a terminal node (if the proof ends in a branch, we extract the leaf and add it as a separate node).
    ///
    /// In practice this can always be set to 6, because
    /// transaction index is within u16, so rlp(txIndex) is at most 3 bytes => 6 nibbles.
    pub max_trie_depth: usize,
}
impl CoreBuilderParams for CoreParamsReceiptSubquery {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

type CKeccak<F> = ComponentTypeKeccak<F>;
type CHeader<F> = ComponentTypeHeaderSubquery<F>;
/// Used for loading receipt subquery promise results.
pub type PromiseLoaderReceiptSubquery<F> =
    PromiseBuilderCombo<F, PromiseLoader<F, CKeccak<F>>, PromiseLoader<F, CHeader<F>>>;
pub type ComponentCircuitReceiptSubquery<F> =
    ComponentCircuitImpl<F, CoreBuilderReceiptSubquery<F>, PromiseLoaderReceiptSubquery<F>>;

impl<F: Field> CircuitMetadata for CoreBuilderReceiptSubquery<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        unreachable!()
    }
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderReceiptSubquery<F> {
    type Params = CoreParamsReceiptSubquery;

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

impl<F: Field> CoreBuilder<F> for CoreBuilderReceiptSubquery<F> {
    type CompType = ComponentTypeReceiptSubquery<F>;
    type PublicInstanceValue = LogicalEmpty<F>;
    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;
    type CoreInput = CircuitInputReceiptShard<F>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        self.input = Some(input);
        Ok(())
    }
    /// Includes computing the component commitment to the logical output (the subquery results).
    /// **In addition** performs _promise calls_ to the Header Component to verify
    /// all `(block_number, receipts_root)` pairs as additional "enriched" header subqueries.
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
        let chip = EthReceiptChip::new(&mpt, self.params.chip_params);
        let base_builder = &mut builder.base;
        // actual logic
        let payload =
            parallelize_core(base_builder.pool(0), input.requests.clone(), |ctx, subquery| {
                handle_single_receipt_subquery_phase0(ctx, &chip, &subquery)
            });

        let vt = extract_virtual_table(payload.iter().map(|p| p.output));
        let lr: Vec<LogicalResult<F, Self::CompType>> =
            extract_logical_results(payload.iter().map(|p| p.output));

        let ctx = base_builder.main(0);
        // promise calls to header component:
        // - for each block number in a subquery, we must make a promise call to check the transaction root of that block
        let header_rc_root_idx = ctx.load_constant(F::from(RECEIPT_ROOT_INDEX as u64));
        for p in payload.iter() {
            let block_number = p.output.subquery.block_number;
            let rc_root = p.rc_root;
            let header_subquery =
                AssignedHeaderSubquery { block_number, field_idx: header_rc_root_idx };
            let promise_rc_root = promise_caller
                .call::<FieldHeaderSubqueryCall<F>, ComponentTypeHeaderSubquery<F>>(
                    ctx,
                    FieldHeaderSubqueryCall(header_subquery),
                )
                .unwrap();
            constrain_vec_equal(ctx, &rc_root.hi_lo(), &promise_rc_root.hi_lo());
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
        let chip = EthReceiptChip::new(&mpt, self.params.chip_params);

        // actual logic
        builder.parallelize_phase1(payload, |(ctx_gate, ctx_rlc), payload| {
            handle_single_receipt_subquery_phase1((ctx_gate, ctx_rlc), &chip, payload)
        });
    }
}

pub struct PayloadReceiptSubquery<F: Field> {
    pub rc_witness: EthReceiptWitness<F>,
    pub parsed_log_witness: EthReceiptLogFieldWitness<F>,
    pub rc_root: HiLo<AssignedValue<F>>,
    pub output: AssignedReceiptSubqueryResult<F>,
}

/// Assigns `subquery` to virtual cells and then handles the subquery to get result.
/// **Assumes** that the receiptsRoot is verified. Returns the assigned private witnesses of
/// `(block_number, receiptsRoot)`, to be looked up against Header Component promise.
pub fn handle_single_receipt_subquery_phase0<F: Field>(
    ctx: &mut Context<F>,
    chip: &EthReceiptChip<F>,
    subquery: &CircuitInputReceiptSubquery,
) -> PayloadReceiptSubquery<F> {
    assert_eq!(chip.params.topic_num_bounds, (0, 4), "Always support all topics");
    let gate = chip.gate();
    let range = chip.range();
    // assign rc proof
    let rc_proof = subquery.proof.clone().assign(ctx);
    // convert receiptsRoot from bytes to HiLo for later. `parse_receipt_proof` will constrain these witnesses to be bytes
    let rc_root = unsafe_mpt_root_to_hi_lo(ctx, gate, &rc_proof.proof);
    // Check the receipt MPT proof
    let rc_witness = chip.parse_receipt_proof_phase0(ctx, rc_proof);
    gate.assert_is_const(ctx, &rc_witness.mpt_witness().slot_is_empty, &F::ZERO); // ensure slot is not empty

    let field_or_log_idx = ctx.load_witness(F::from(subquery.field_or_log_idx as u64));
    range.range_check(ctx, field_or_log_idx, FIELD_IDX_BITS);
    let log_threshold = Constant(F::from(RECEIPT_LOG_IDX_OFFSET as u64));
    // if `field_idx` < `RECEIPT_NUM_FIELDS`, then it is an actual tx rlp list item. Note even though `field_idx` has both postState and status, we **do not** allow `field_idx = 4` for logs. That is what `is_log_idx` is for.
    let is_idx_in_list =
        is_lt_usize(ctx, range, field_or_log_idx, RECEIPT_NUM_FIELDS, FIELD_IDX_BITS);
    // The cumulativeGas field is always in a receipt, regardless of EIP-658, whereas we only allow fieldIdx = 0 (status) if the block is after EIP-658 or allow fieldIdx = 1 (postState) if the block is before EIP-658
    let field_idx = gate.select(
        ctx,
        field_or_log_idx,
        Constant(F::from(CUMULATIVE_GAS_FIELD_IDX as u64)),
        is_idx_in_list,
    );
    // if `field_idx` >= `RECEIPT_LOG_IDX_OFFSET`, then we want a log
    // must be log_idx if field_or_log_idx >= RECEIPT_LOG_IDX_OFFSET
    let is_log_idx =
        is_gte_usize(ctx, range, field_or_log_idx, RECEIPT_LOG_IDX_OFFSET, FIELD_IDX_BITS);
    // log_idx = field_or_log_idx - RECEIPT_LOG_IDX_OFFSET, wrapping sub
    let mut log_idx = gate.sub(ctx, field_or_log_idx, log_threshold);
    log_idx = gate.mul(ctx, log_idx, is_log_idx);
    let num_logs = rc_witness.logs.list_len.expect("logs are var len");
    let is_valid_log_idx = range.is_less_than(ctx, log_idx, num_logs, FIELD_IDX_BITS);
    let is_log_idx = SafeTypeChip::unsafe_to_bool(gate.and(ctx, is_log_idx, is_valid_log_idx));
    let log_idx = gate.mul(ctx, log_idx, is_log_idx);

    let tx_type = rc_witness.receipt_type;

    let rc_field_bytes =
        extract_truncated_field(ctx, range, &rc_witness, field_idx, SUBQUERY_OUTPUT_BYTES);

    let logs_bloom_bytes = &rc_witness.value().field_witness[2].field_cells;
    let (logs_bloom_value, is_logs_bloom_idx) = handle_logs_bloom(
        ctx,
        range,
        logs_bloom_bytes,
        field_or_log_idx,
        RECEIPT_LOGS_BLOOM_IDX_OFFSET,
    );

    // === begin process logs ===
    // tda = topic_or_data_or_address; too much to type
    let tda_idx = ctx.load_witness(F::from(subquery.topic_or_data_or_address_idx as u64));
    range.range_check(ctx, tda_idx, FIELD_IDX_BITS);
    let is_topic = is_lt_usize(ctx, range, tda_idx, 4, FIELD_IDX_BITS);
    let mut is_topic = gate.and(ctx, is_topic, is_log_idx);
    let data_threshold = Constant(F::from(RECEIPT_DATA_IDX_OFFSET as u64));
    let is_data_idx = is_gte_usize(ctx, range, tda_idx, RECEIPT_DATA_IDX_OFFSET, FIELD_IDX_BITS);
    let mut is_data_idx = gate.and(ctx, is_data_idx, is_log_idx);
    let topic_idx = gate.mul(ctx, tda_idx, is_topic);
    let data_idx = gate.sub(ctx, tda_idx, data_threshold);
    let data_idx = gate.mul(ctx, data_idx, is_data_idx);

    let log = chip.extract_receipt_log(ctx, &rc_witness, log_idx);
    let log_witness = conditional_parse_log_phase0(ctx, chip, log, is_log_idx);
    // Get 32 bytes from data
    let (data_bytes, is_valid_data) =
        extract_data_section(ctx, range, &log_witness, data_idx, SUBQUERY_OUTPUT_BYTES);
    is_data_idx = gate.and(ctx, is_data_idx, is_valid_data);
    // Get the address
    let addr = log_witness.address().to_vec();
    // Select the topic
    let topics_bytes = log_witness.topics_bytes();
    assert_eq!(topics_bytes.len(), 4);
    let topic_indicator = gate.idx_to_indicator(ctx, topic_idx, 4);
    let topic = gate.select_array_by_indicator(ctx, &topics_bytes, &topic_indicator);
    let is_valid_topic =
        range.is_less_than(ctx, topic_idx, log_witness.num_topics(), FIELD_IDX_BITS);
    is_topic = gate.and(ctx, is_topic, is_valid_topic);
    // ---- event schema ----
    // if event_schema != bytes32(0) and `is_log_idx`, then we constrain `topic[0] == event_schema`
    let event_schema = unsafe_bytes_to_assigned(ctx, subquery.event_schema.as_bytes());
    let no_constrain_event = is_zero_vec(ctx, gate, &event_schema);
    let event_diff =
        zip_eq(&topics_bytes[0], &event_schema).map(|(&a, &b)| gate.sub(ctx, a, b)).collect_vec();
    let mut event_eq = is_zero_vec(ctx, gate, &event_diff);
    event_eq = gate.and(ctx, event_eq, is_log_idx);
    let valid_event = gate.or(ctx, no_constrain_event, event_eq);
    gate.assert_is_const(ctx, &valid_event, &F::ONE);
    // ==== end process logs ====

    let [is_tx_type, is_block_num, is_tx_idx] =
        [RECEIPT_TX_TYPE_FIELD_IDX, RECEIPT_BLOCK_NUMBER_FIELD_IDX, RECEIPT_TX_INDEX_FIELD_IDX]
            .map(|x| is_equal_usize(ctx, gate, field_or_log_idx, x));
    let is_addr = is_equal_usize(ctx, gate, tda_idx, RECEIPT_ADDRESS_IDX);
    let is_addr = gate.and(ctx, is_addr, is_log_idx);

    let safe = SafeTypeChip::new(range);
    let value_indicator = vec![
        is_idx_in_list.into(),
        is_tx_type.into(),
        is_block_num.into(),
        is_tx_idx.into(),
        is_logs_bloom_idx.into(),
        is_topic,
        is_addr,
        is_data_idx,
    ];
    // it must be exactly one of the above cases
    let idx_check = gate.sum(ctx, value_indicator.clone());
    gate.assert_is_const(ctx, &idx_check, &F::ONE);

    let block_number = ctx.load_witness(F::from(subquery.block_number));
    let tx_idx = rc_witness.tx_idx;
    let field_hilo = prep_field(ctx, gate, rc_field_bytes, field_idx);
    let const_zero = ctx.load_zero();
    let from_lo = |lo| HiLo::from_hi_lo([const_zero, lo]);

    // unsafe because rlp has already constrained these to be bytes
    let topic = SafeTypeChip::unsafe_to_fix_len_bytes_vec(topic, 32);
    let addr = SafeTypeChip::unsafe_to_fix_len_bytes_vec(addr, 20);
    let topic_hilo = pack_bytes_to_hilo(ctx, gate, topic.bytes());
    let addr_hilo = pack_bytes_to_hilo(ctx, gate, addr.bytes());
    let data_hilo = pack_bytes_to_hilo(ctx, gate, &data_bytes);
    let hilos = vec![
        field_hilo,
        from_lo(tx_type),
        from_lo(block_number),
        from_lo(tx_idx),
        logs_bloom_value,
        topic_hilo,
        addr_hilo,
        data_hilo,
    ];
    let value = select_hi_lo_by_indicator(ctx, gate, &hilos, value_indicator);
    // dbg!(value.hi_lo().map(|v| *v.value()));
    let event_schema = safe.raw_to_fix_len_bytes_vec(ctx, event_schema, 32);
    let event_schema = pack_bytes_to_hilo(ctx, gate, event_schema.bytes());
    PayloadReceiptSubquery {
        rc_witness,
        rc_root,
        parsed_log_witness: log_witness,
        output: AssignedReceiptSubqueryResult {
            subquery: AssignedReceiptSubquery {
                block_number,
                tx_idx,
                field_or_log_idx,
                topic_or_data_or_address_idx: tda_idx,
                event_schema,
            },
            value,
        },
    }
}

pub fn handle_single_receipt_subquery_phase1<F: Field>(
    (ctx_gate, ctx_rlc): RlcContextPair<F>,
    chip: &EthReceiptChip<F>,
    payload: PayloadReceiptSubquery<F>,
) {
    chip.parse_receipt_proof_phase1((ctx_gate, ctx_rlc), payload.rc_witness);
    conditional_parse_log_phase1((ctx_gate, ctx_rlc), chip, payload.parsed_log_witness);
}

/// Extracts the field at `field_idx` from the given rlp list decomposition of a transaction.
/// The field is truncated to the first `truncated_byte_len` bytes.
///
/// We do not use `EthReceiptChip::extract_field` because without the truncation the
/// select operation can be very expensive if the `data` field is very long.
///
/// We **ignore** `field_idx = 4` (logs) because it is handled separately.
pub fn extract_truncated_field<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    witness: &EthReceiptWitness<F>,
    field_idx: AssignedValue<F>,
    truncated_byte_len: usize,
) -> VarLenBytesVec<F> {
    let gate = range.gate();
    let rc_values = &witness.value().field_witness;
    assert_eq!(rc_values.len(), RECEIPT_NUM_FIELDS);
    let rc_values = &rc_values[..RECEIPT_NUM_FIELDS - 1];
    // | ReceiptField           | `fieldIdx` |
    // |------------------------|-------|
    // | Status                 | 0     |
    // | PostState              | 1     |
    // | CumulativeGas          | 2     |
    // | LogsBloom              | 3     |
    // | Logs                   | 4     |
    // while the actual list index is:
    //
    // | `listIdx` | State Field    | Type      | Bytes | RLP Size (Bytes) | RLP Size (Bits) |
    // | --------- | -------------- | --------- | -------- | -------- | -------- |
    // | 0         | PostState      | bytes32   | 32     | 33 | 264 |
    // | 0         | Status         | uint64    | $\leq 1$     | $\leq 33$ | $\leq 264$ |
    // | 1         | Cumulative Gas | uint256   | $\leq 32$     | $\leq 33$ | $\leq 264$ |
    // | 2         | Log Blooms     | Bytes     | 256     | 259 | 2072 |
    // | 3         | Logs           | List of Logs | variable | variable | variable |
    //
    // Before EIP-658, receipts hold the PostState hash (the intermediate state root hash) instead of the Status.
    let get_status = gate.is_zero(ctx, field_idx);
    let offset = gate.not(ctx, get_status);
    let list_idx = gate.sub(ctx, field_idx, offset);
    let indicator = gate.idx_to_indicator(ctx, list_idx, RECEIPT_NUM_FIELDS - 1);
    let const_zero = ctx.load_zero();
    let mut field_bytes = (0..truncated_byte_len)
        .map(|i| {
            let entries = rc_values.iter().map(|w| *w.field_cells.get(i).unwrap_or(&const_zero));
            gate.select_by_indicator(ctx, entries, indicator.clone())
        })
        .collect_vec();
    let lens = rc_values.iter().map(|w| w.field_len);
    let mut len = gate.select_by_indicator(ctx, lens, indicator);
    // len = min(len, truncated_byte_len)
    let max_bytes = rc_values.iter().map(|w| w.field_cells.len()).max().unwrap();
    let max_bits = bit_length(max_bytes as u64);
    len = min_with_usize(ctx, range, len, truncated_byte_len, max_bits);

    unsafe_constrain_trailing_zeros(ctx, gate, &mut field_bytes, len);

    // constrain that postState is 32 bytes and status is less than 32 bytes
    let is_post_state_or_status = gate.is_zero(ctx, list_idx);
    let is_small = range.is_less_than_safe(ctx, len, 32);
    // if is_post_state_or_status, then is_small and get_status must match
    let diff = gate.sub(ctx, is_small, get_status);
    let status_check = gate.mul(ctx, is_post_state_or_status, diff);
    ctx.constrain_equal(&status_check, &const_zero);

    SafeTypeChip::unsafe_to_var_len_bytes_vec(field_bytes, len, truncated_byte_len)
}

fn prep_field<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    field_bytes: VarLenBytesVec<F>,
    field_idx: AssignedValue<F>,
) -> HiLo<AssignedValue<F>> {
    let left_pad_indicator = [true, false, true, false, false].map(F::from).map(Constant);
    let field_fixed = field_bytes.left_pad_to_fixed(ctx, gate);
    let left_pad = gate.select_from_idx(ctx, left_pad_indicator, field_idx);
    let value = zip(field_bytes.bytes(), field_fixed.bytes())
        .map(|(var, fixed)| gate.select(ctx, *fixed, *var, left_pad))
        .collect_vec();
    let value = SafeTypeChip::unsafe_to_fix_len_bytes_vec(value, SUBQUERY_OUTPUT_BYTES);
    pack_bytes_to_hilo(ctx, gate, value.bytes())
}

/// Extracts a chunk of `log_data[data_idx * chunk_size.. (data_idx + 1) * chunk_size]`
/// and constrains trailing zeros.
/// Returns a flag indicating whether `data_idx * chunk_size < data_len`.
///
/// Note: select operation can be very expensive if the `data` field is very long.
pub fn extract_data_section<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    witness: &EthReceiptLogFieldWitness<F>,
    data_idx: AssignedValue<F>,
    chunk_size: usize,
) -> (Vec<SafeByte<F>>, SafeBool<F>) {
    let (chunk, is_valid) = extract_array_chunk_and_constrain_trailing_zeros(
        ctx,
        range,
        witness.data_bytes(),
        witness.data_len(),
        data_idx,
        chunk_size,
        FIELD_IDX_BITS,
    );
    let chunk = chunk.into_iter().map(SafeTypeChip::unsafe_to_byte).collect();
    (chunk, is_valid)
}

/// The `witness` might not have a valid log.
/// When `parse_log_flag` is false, we parse a dummy log.
///
/// # Assumptions
/// - When `parse_log_flag` is true, `witness` has a valid log.
pub fn conditional_parse_log_phase0<F: Field>(
    ctx: &mut Context<F>,
    chip: &EthReceiptChip<F>,
    mut witness: EthReceiptLogWitness<F>,
    parse_log_flag: SafeBool<F>,
) -> EthReceiptLogFieldWitness<F> {
    let gate = chip.gate();
    let log = &mut witness.log_bytes;
    // we zip here because the RLP will parse based on the prefix so it should not matter what dummy values are beyond `DUMMY_LOG.len()`
    for (byte, dummy_byte) in log.iter_mut().zip(DUMMY_LOG) {
        let dummy_byte = F::from(dummy_byte as u64);
        *byte = gate.select(ctx, *byte, Constant(dummy_byte), parse_log_flag);
    }
    parse_log_phase0(ctx, chip, witness)
}

pub fn conditional_parse_log_phase1<F: Field>(
    (ctx_gate, ctx_rlc): RlcContextPair<F>,
    chip: &EthReceiptChip<F>,
    witness: EthReceiptLogFieldWitness<F>,
) {
    parse_log_phase1((ctx_gate, ctx_rlc), chip, witness);
}

/// ### Log Fields
///
/// | State Field           | Type          | Bytes     | RLP Size (Bytes) | RLP Size (Bits) |
/// | --------              | --------      | --------  | -------- | -------- |
/// | Address               | address hash  | 20        | 21 | 168 |
/// | List of 0 to 4 Topics | bytes32       | 32        | 33 | 264 |
/// | data                  | Bytes         | variable  | variable | variable |
pub fn parse_log_phase0<F: Field>(
    ctx_gate: &mut Context<F>,
    chip: &EthReceiptChip<F>,
    witness: EthReceiptLogWitness<F>,
) -> EthReceiptLogFieldWitness<F> {
    let (_, max_topics) = chip.params.topic_num_bounds; // in practice this will always be 4
    let max_data_byte_len = chip.params.max_data_byte_len;
    let field_lengths = [20, max_topics * 33 + 3, max_data_byte_len];
    let log_list =
        chip.rlp().decompose_rlp_array_phase0(ctx_gate, witness.log_bytes, &field_lengths, false);
    let topics = log_list.field_witness[1].clone();
    let topics_list = chip.rlp().decompose_rlp_array_phase0(
        ctx_gate,
        topics.encoded_item,
        &vec![32; max_topics],
        true,
    );
    EthReceiptLogFieldWitness { log_list, topics_list }
}

pub fn parse_log_phase1<F: Field>(
    (ctx_gate, ctx_rlc): RlcContextPair<F>,
    chip: &EthReceiptChip<F>,
    witness: EthReceiptLogFieldWitness<F>,
) {
    chip.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.log_list, false);
    chip.rlp().decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.topics_list, true);
}
