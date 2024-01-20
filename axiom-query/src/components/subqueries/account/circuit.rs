use std::iter::zip;

use axiom_eth::{
    block_header::STATE_ROOT_INDEX,
    halo2_base::{
        gates::{flex_gate::threads::parallelize_core, GateInstructions, RangeInstructions},
        safe_types::SafeTypeChip,
        AssignedValue, Context,
        QuantumCell::Constant,
    },
    halo2_proofs::plonk::ConstraintSystem,
    keccak::{types::ComponentTypeKeccak, KeccakChip},
    mpt::MPTChip,
    rlc::circuit::builder::RlcCircuitBuilder,
    rlc::circuit::builder::RlcContextPair,
    rlp::RlpChip,
    storage::{
        EthAccountWitness, EthStorageChip, ACCOUNT_STATE_FIELDS_MAX_BYTES,
        ACCOUNT_STATE_FIELD_IS_VAR_LEN, NUM_ACCOUNT_STATE_FIELDS,
    },
    utils::{
        build_utils::aggregation::CircuitMetadata,
        bytes_be_to_uint,
        circuit_utils::bytes::{pack_bytes_to_hilo, unsafe_mpt_root_to_hi_lo},
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
        constrain_vec_equal, encode_h256_to_hilo,
        hilo::HiLo,
        unsafe_bytes_to_assigned,
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::{
        block_header::types::{ComponentTypeHeaderSubquery, FieldHeaderSubqueryCall},
        common::{extract_logical_results, extract_virtual_table},
    },
    utils::codec::{
        AssignedAccountSubquery, AssignedAccountSubqueryResult, AssignedHeaderSubquery,
    },
    Field,
};

use super::{
    types::{CircuitInputAccountShard, CircuitInputAccountSubquery, ComponentTypeAccountSubquery},
    KECCAK_RLP_EMPTY_STRING, STORAGE_ROOT_INDEX,
};

pub struct CoreBuilderAccountSubquery<F: Field> {
    input: Option<CircuitInputAccountShard<F>>,
    params: CoreParamsAccountSubquery,
    payload: Option<(KeccakChip<F>, Vec<PayloadAccountSubquery<F>>)>,
}

/// Specify the output format of AccountSubquery component.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsAccountSubquery {
    /// The maximum number of subqueries of this type allowed in a single circuit.
    pub capacity: usize,
    /// The maximum depth of the state MPT trie supported by this circuit.
    /// The depth is defined as the maximum length of an account proof, where the account proof always ends in a terminal leaf node.
    ///
    /// In production this will be set to 14 based on the MPT analysis from https://hackmd.io/@axiom/BJBledudT
    pub max_trie_depth: usize,
}
impl CoreBuilderParams for CoreParamsAccountSubquery {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

type CKeccak<F> = ComponentTypeKeccak<F>;
type CHeader<F> = ComponentTypeHeaderSubquery<F>;
pub type PromiseLoaderAccountSubquery<F> =
    PromiseBuilderCombo<F, PromiseLoader<F, CKeccak<F>>, PromiseLoader<F, CHeader<F>>>;
pub type ComponentCircuitAccountSubquery<F> =
    ComponentCircuitImpl<F, CoreBuilderAccountSubquery<F>, PromiseLoaderAccountSubquery<F>>;

impl<F: Field> CircuitMetadata for CoreBuilderAccountSubquery<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        unreachable!()
    }
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderAccountSubquery<F> {
    type Params = CoreParamsAccountSubquery;
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

impl<F: Field> CoreBuilder<F> for CoreBuilderAccountSubquery<F> {
    type CompType = ComponentTypeAccountSubquery<F>;
    type PublicInstanceValue = LogicalEmpty<F>;
    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;
    type CoreInput = CircuitInputAccountShard<F>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        for r in &input.requests {
            if r.proof.acct_pf.max_depth != self.params.max_trie_depth {
                anyhow::bail!("AccountSubquery: request MPT max depth {} does not match configured max depth {}", r.proof.acct_pf.max_depth, self.params.max_trie_depth);
            }
        }
        self.input = Some(input);
        Ok(())
    }
    /// Includes computing the component commitment to the logical output (the subquery results).
    /// **In addition** performs _promise calls_ to the Header Component to verify
    /// all `(block_number, state_root)` pairs as additional "enriched" header subqueries.
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
        let chip = EthStorageChip::new(&mpt, None);
        let base_builder = &mut builder.base;
        // actual logic
        let payload =
            parallelize_core(base_builder.pool(0), input.requests.clone(), |ctx, subquery| {
                handle_single_account_subquery_phase0(ctx, &chip, &subquery)
            });

        let vt = extract_virtual_table(payload.iter().map(|p| p.output));
        let lr: Vec<LogicalResult<F, Self::CompType>> =
            extract_logical_results(payload.iter().map(|p| p.output));

        let ctx = base_builder.main(0);
        // promise calls to header component:
        // - for each block number in a subquery, we must make a promise call to check the state root of that block
        let header_state_root_idx = ctx.load_constant(F::from(STATE_ROOT_INDEX as u64));
        for p in payload.iter() {
            let block_number = p.output.subquery.block_number;
            let state_root = p.state_root;
            let header_subquery =
                AssignedHeaderSubquery { block_number, field_idx: header_state_root_idx };
            let promise_state_root = promise_caller
                .call::<FieldHeaderSubqueryCall<F>, ComponentTypeHeaderSubquery<F>>(
                    ctx,
                    FieldHeaderSubqueryCall(header_subquery),
                )
                .unwrap();
            constrain_vec_equal(ctx, &state_root.hi_lo(), &promise_state_root.hi_lo());
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
        let chip = EthStorageChip::new(&mpt, None);

        // actual logic
        builder.parallelize_phase1(payload, |(ctx_gate, ctx_rlc), payload| {
            handle_single_account_subquery_phase1((ctx_gate, ctx_rlc), &chip, payload)
        });
    }
}

pub struct PayloadAccountSubquery<F: Field> {
    pub account_witness: EthAccountWitness<F>,
    pub state_root: HiLo<AssignedValue<F>>,
    pub output: AssignedAccountSubqueryResult<F>,
}

/// Assigns `subquery` to virtual cells and then handles the subquery to get result.
/// **Assumes** that the stateRoot is verified. Returns the assigned private witnesses of
/// `(block_number, state_root)`, to be looked up against Header Component promise.
pub fn handle_single_account_subquery_phase0<F: Field>(
    ctx: &mut Context<F>,
    chip: &EthStorageChip<F>,
    subquery: &CircuitInputAccountSubquery,
) -> PayloadAccountSubquery<F> {
    let gate = chip.gate();
    let range = chip.range();
    let safe = SafeTypeChip::new(range);
    // assign address as SafeBytes20 and also convert to single field element
    let unsafe_address = unsafe_bytes_to_assigned(ctx, subquery.proof.addr.as_bytes());
    let address = safe.raw_bytes_to(ctx, unsafe_address);
    // transmute SafeBytes20 to FixLenBytesVec
    let addr = SafeTypeChip::unsafe_to_fix_len_bytes_vec(address.value().to_vec(), 20);
    // convert bytes (160 bits) to single field element
    let addr = bytes_be_to_uint(ctx, gate, addr.bytes(), 20);
    // assign MPT proof
    let mpt_proof = subquery.proof.acct_pf.clone().assign(ctx);
    // convert state root to HiLo form to save for later. `parse_account_proof` will constrain these witnesses to be bytes
    let state_root = unsafe_mpt_root_to_hi_lo(ctx, gate, &mpt_proof);
    // Check the account MPT proof
    let account_witness = chip.parse_account_proof_phase0(ctx, address, mpt_proof);
    // get the value for subquery
    let field_idx = ctx.load_witness(F::from(subquery.field_idx as u64));
    range.check_less_than_safe(ctx, field_idx, NUM_ACCOUNT_STATE_FIELDS as u64);

    // Left pad value types to 32 bytes and convert to HiLo
    let mut account_fixed = zip(ACCOUNT_STATE_FIELDS_MAX_BYTES, ACCOUNT_STATE_FIELD_IS_VAR_LEN)
        .zip(&account_witness.array_witness().field_witness)
        .map(|((max_bytes, is_var_len), w)| {
            let inputs = w.field_cells.clone();
            // if var len, then its either nonce or balance, which are value types
            let fixed_bytes = if is_var_len {
                let len = w.field_len;
                let var_len_bytes =
                    SafeTypeChip::unsafe_to_var_len_bytes_vec(inputs, len, max_bytes);
                assert!(var_len_bytes.max_len() <= 32);
                var_len_bytes.left_pad_to_fixed(ctx, gate)
            } else {
                let len = inputs.len();
                SafeTypeChip::unsafe_to_fix_len_bytes_vec(inputs, len)
            };
            let fixed_bytes = fixed_bytes.into_bytes();
            // known to be <=32 bytes
            pack_bytes_to_hilo(ctx, gate, &fixed_bytes).hi_lo()
        })
        .collect_vec();

    let account_is_empty = account_witness.mpt_witness().slot_is_empty;
    // If account does not exist, then return:
    // - nonce = 0
    // - balance = 0
    // - storageRoot = null root hash = keccak(rlp("")) = keccak(0x80) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
    // - codeHash = 0 (see Test Case 2 of https://eips.ethereum.org/EIPS/eip-1052)
    for (i, account_field) in account_fixed.iter_mut().enumerate() {
        if i == STORAGE_ROOT_INDEX {
            let null_root = encode_h256_to_hilo(&KECCAK_RLP_EMPTY_STRING).hi_lo();
            for (limb, null_limb) in account_field.iter_mut().zip(null_root) {
                *limb = gate.select(ctx, Constant(null_limb), *limb, account_is_empty);
            }
        } else {
            for limb in account_field.iter_mut() {
                *limb = gate.mul_not(ctx, account_is_empty, *limb);
            }
        }
    }

    let indicator = gate.idx_to_indicator(ctx, field_idx, account_fixed.len());
    let value = gate.select_array_by_indicator(ctx, &account_fixed, &indicator);
    let value = HiLo::from_hi_lo(value.try_into().unwrap());

    let block_number = ctx.load_witness(F::from(subquery.block_number));

    PayloadAccountSubquery {
        account_witness,
        state_root,
        output: AssignedAccountSubqueryResult {
            subquery: AssignedAccountSubquery { block_number, addr, field_idx },
            value,
        },
    }
}

pub fn handle_single_account_subquery_phase1<F: Field>(
    ctx: RlcContextPair<F>,
    chip: &EthStorageChip<F>,
    payload: PayloadAccountSubquery<F>,
) {
    chip.parse_account_proof_phase1(ctx, payload.account_witness);
}
