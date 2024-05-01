use std::{marker::PhantomData, sync::RwLock};

use anyhow::anyhow;

use ethers_core::{
    types::{Bytes, H256},
    utils::keccak256,
};
use halo2_base::{
    gates::{GateInstructions, RangeChip},
    poseidon::hasher::PoseidonCompactChunkInput,
    safe_types::{SafeBytes32, SafeTypeChip},
    utils::ScalarField,
    AssignedValue, Context,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use type_map::concurrent::TypeMap;
use zkevm_hashes::keccak::{
    component::{encode::pack_native_input, output::KeccakCircuitOutput, param::POSEIDON_RATE},
    vanilla::keccak_packed_multi::get_num_keccak_f,
};

use crate::{
    rlc::chip::RlcChip,
    utils::{
        component::{
            types::{FixLenLogical, Flatten},
            ComponentType, ComponentTypeId, LogicalInputValue, LogicalResult,
        },
        hilo::HiLo,
        AssignedH256,
    },
    Field,
};

use super::promise::KeccakComponentCommiter;

#[derive(Clone, Debug)]
pub struct KeccakFixedLenQuery<F: ScalarField> {
    /// Input in bytes
    pub input_assigned: Vec<AssignedValue<F>>,
    /// The hash digest, in bytes
    // For backwards compatibility we always compute this; we can consider computing it on-demand in the future
    pub output_bytes: SafeBytes32<F>,
    /// The hash digest, hi 128 bits (range checked by lookup table)
    pub output_hi: AssignedValue<F>,
    /// The hash digest, lo 128 bits (range checked by lookup table)
    pub output_lo: AssignedValue<F>,
}

impl<F: ScalarField> KeccakFixedLenQuery<F> {
    pub fn hi_lo(&self) -> AssignedH256<F> {
        [self.output_hi, self.output_lo]
    }
}

#[derive(Clone, Debug)]
pub struct KeccakVarLenQuery<F: ScalarField> {
    pub min_bytes: usize,
    // pub max_bytes: usize, // equal to input_assigned.len()
    // pub num_bytes: usize,
    /// Actual length of input
    pub length: AssignedValue<F>,
    pub input_assigned: Vec<AssignedValue<F>>,
    /// The hash digest, in bytes
    // For backwards compatibility we always compute this; we can consider computing it on-demand in the future
    pub output_bytes: SafeBytes32<F>,
    /// The hash digest, hi 128 bits (range checked by lookup table)
    pub output_hi: AssignedValue<F>,
    /// The hash digest, lo 128 bits (range checked by lookup table)
    pub output_lo: AssignedValue<F>,
}

impl<F: ScalarField> KeccakVarLenQuery<F> {
    pub fn hi_lo(&self) -> AssignedH256<F> {
        [self.output_hi, self.output_lo]
    }
}

/// The core logical input to the keccak component circuit.
pub type CoreInputKeccak = Vec<Vec<u8>>;

#[derive(Clone, Debug, Default, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct OutputKeccakShard {
    /// The (assumed to be deduplicated) list of requests, in the form of variable
    /// length byte arrays to be hashed. Optionally include the calculated hash.
    pub responses: Vec<(Bytes, Option<H256>)>,
    /// To prevent inconsistencies, also specify the capacity of the keccak circuit
    pub capacity: usize,
}

impl OutputKeccakShard {
    /// Create a dummy OutputKeccakShard with the given capacity.
    pub fn create_dummy(capacity: usize) -> Self {
        Self { responses: vec![], capacity }
    }
    pub fn into_logical_results<F: Field>(self) -> Vec<LogicalResult<F, ComponentTypeKeccak<F>>> {
        let mut total_capacity = 0;
        let mut promise_results = self
            .responses
            .into_iter()
            .map(|(input, output)| {
                let input = KeccakLogicalInput::new(input.to_vec());
                total_capacity += get_num_keccak_f(input.bytes.len());
                let v_output =
                    if let Some(hash) = output { hash.into() } else { input.compute_output::<F>() };
                LogicalResult::<F, ComponentTypeKeccak<F>>::new(input, v_output)
            })
            .collect_vec();
        assert!(total_capacity <= self.capacity);
        if total_capacity < self.capacity {
            let target_len = self.capacity - total_capacity + promise_results.len();
            let dummy = dummy_circuit_output::<F>();
            promise_results.resize(
                target_len,
                LogicalResult::new(
                    KeccakLogicalInput::new(vec![]),
                    KeccakVirtualOutput::<F> {
                        hash: HiLo::from_hi_lo([dummy.hash_hi, dummy.hash_lo]),
                    },
                ),
            );
        }
        promise_results
    }
}

/// KeccakLogicalInput is the logical input of Keccak Component.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeccakLogicalInput {
    pub bytes: Vec<u8>,
}
impl KeccakLogicalInput {
    // Create KeccakLogicalInput
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    pub fn compute_output<F: Field>(&self) -> KeccakVirtualOutput<F> {
        let hash = H256(keccak256(&self.bytes));
        hash.into()
    }
}

impl<F: Field> LogicalInputValue<F> for KeccakLogicalInput {
    fn get_capacity(&self) -> usize {
        get_num_keccak_f(self.bytes.len())
    }
}

pub(crate) const NUM_WITNESS_PER_KECCAK_F: usize = 6;
const KECCAK_VIRTUAL_INPUT_FIELD_SIZE: [usize; NUM_WITNESS_PER_KECCAK_F + 1] = [
    192, 192, 192, 192, 192, 192, // packed_input
    1,   // is_final
];
const KECCAK_VIRTUAL_OUTPUT_FIELD_SIZE: [usize; 2] = [128, 128];

/// Virtual input of Keccak Component.
/// TODO: this cannot work if F::capacity < 192.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct KeccakVirtualInput<T: Clone> {
    // 1 length + 17 64-byte words, every 3 are compressed into 1 witness.
    // spec: https://github.com/axiom-crypto/halo2-lib/blob/9e6c9a16196e7e2ce58ccb6ffc31984fc0ba69d9/hashes/zkevm/src/keccak/component/encode.rs#L25
    pub packed_input: [T; NUM_WITNESS_PER_KECCAK_F],
    // Whether this is the last chunk of the input.
    // TODO: this is hacky because it can be derived from packed_input but it's not really committed.
    pub is_final: T,
}

impl<T: Clone> KeccakVirtualInput<T> {
    pub fn new(packed_input: [T; NUM_WITNESS_PER_KECCAK_F], is_final: T) -> Self {
        Self { packed_input, is_final }
    }
}

impl<T: Copy> TryFrom<Flatten<T>> for KeccakVirtualInput<T> {
    type Error = anyhow::Error;

    fn try_from(value: Flatten<T>) -> std::result::Result<Self, Self::Error> {
        if value.field_size != KECCAK_VIRTUAL_INPUT_FIELD_SIZE {
            return Err(anyhow::anyhow!("invalid field size"));
        }
        if value.field_size.len() != value.fields.len() {
            return Err(anyhow::anyhow!("field length doesn't match"));
        }

        Ok(Self {
            packed_input: value.fields[0..NUM_WITNESS_PER_KECCAK_F]
                .try_into()
                .map_err(|_| anyhow!("failed to convert flatten to KeccakVirtualInput"))?,
            is_final: value.fields[NUM_WITNESS_PER_KECCAK_F],
        })
    }
}
impl<T: Copy> From<KeccakVirtualInput<T>> for Flatten<T> {
    fn from(val: KeccakVirtualInput<T>) -> Self {
        Self {
            fields: [val.packed_input.as_slice(), [val.is_final].as_slice()].concat(),
            field_size: &KECCAK_VIRTUAL_INPUT_FIELD_SIZE,
        }
    }
}
impl<T: Copy> FixLenLogical<T> for KeccakVirtualInput<T> {
    fn get_field_size() -> &'static [usize] {
        &KECCAK_VIRTUAL_INPUT_FIELD_SIZE
    }
}

impl<F: Field> From<KeccakVirtualInput<AssignedValue<F>>>
    for PoseidonCompactChunkInput<F, POSEIDON_RATE>
{
    fn from(val: KeccakVirtualInput<AssignedValue<F>>) -> Self {
        let KeccakVirtualInput::<AssignedValue<F>> { packed_input, is_final } = val;
        assert!(packed_input.len() % POSEIDON_RATE == 0);
        let inputs: Vec<[AssignedValue<F>; POSEIDON_RATE]> = packed_input
            .into_iter()
            .chunks(POSEIDON_RATE)
            .into_iter()
            .map(|c| c.collect_vec().try_into().unwrap())
            .collect_vec();
        let is_final = SafeTypeChip::unsafe_to_bool(is_final);
        Self::new(inputs, is_final)
    }
}

/// Virtual input of Keccak Component.
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct KeccakVirtualOutput<T: Clone> {
    /// Keccak hash result
    pub hash: HiLo<T>,
}

impl<T: Clone> KeccakVirtualOutput<T> {
    pub fn new(hash: HiLo<T>) -> Self {
        Self { hash }
    }
}

impl<T: Copy> TryFrom<Flatten<T>> for KeccakVirtualOutput<T> {
    type Error = anyhow::Error;

    fn try_from(value: Flatten<T>) -> std::result::Result<Self, Self::Error> {
        if value.field_size != KECCAK_VIRTUAL_OUTPUT_FIELD_SIZE {
            return Err(anyhow::anyhow!("invalid field size"));
        }
        if value.field_size.len() != value.fields.len() {
            return Err(anyhow::anyhow!("field length doesn't match"));
        }

        Ok(Self {
            hash: HiLo::from_hi_lo(
                value
                    .fields
                    .try_into()
                    .map_err(|_| anyhow!("failed to convert flatten to KeccakVirtualOutput"))?,
            ),
        })
    }
}
impl<T: Copy> From<KeccakVirtualOutput<T>> for Flatten<T> {
    fn from(val: KeccakVirtualOutput<T>) -> Self {
        Self { fields: val.hash.hi_lo().to_vec(), field_size: &KECCAK_VIRTUAL_OUTPUT_FIELD_SIZE }
    }
}
impl<T: Copy> FixLenLogical<T> for KeccakVirtualOutput<T> {
    fn get_field_size() -> &'static [usize] {
        &KECCAK_VIRTUAL_OUTPUT_FIELD_SIZE
    }
}
impl<F: Field> From<H256> for KeccakVirtualOutput<F> {
    fn from(hash: H256) -> Self {
        let hash_hi = u128::from_be_bytes(hash[..16].try_into().unwrap());
        let hash_lo = u128::from_be_bytes(hash[16..].try_into().unwrap());
        Self { hash: HiLo::from_hi_lo([F::from_u128(hash_hi), F::from_u128(hash_lo)]) }
    }
}

#[derive(Debug, Clone)]
pub struct ComponentTypeKeccak<F: Field>(PhantomData<F>);

impl<F: Field> ComponentType<F> for ComponentTypeKeccak<F> {
    type InputValue = KeccakVirtualInput<F>;
    type InputWitness = KeccakVirtualInput<AssignedValue<F>>;
    type OutputValue = KeccakVirtualOutput<F>;
    type OutputWitness = KeccakVirtualOutput<AssignedValue<F>>;
    type LogicalInput = KeccakLogicalInput;
    type Commiter = KeccakComponentCommiter<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-eth:ComponentTypeKeccak".to_string()
    }

    fn logical_result_to_virtual_rows_impl(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        let virtual_inputs = Self::logical_input_to_virtual_rows_impl(&ins.input);
        let len = virtual_inputs.len();
        let mut virtual_outputs = Vec::with_capacity(len);
        let dummy = dummy_circuit_output();
        virtual_outputs.resize(
            len - 1,
            Self::OutputValue { hash: HiLo::from_hi_lo([dummy.hash_hi, dummy.hash_lo]) },
        );
        virtual_outputs.push(ins.output.clone());
        virtual_inputs.into_iter().zip_eq(virtual_outputs).collect_vec()
    }
    fn logical_input_to_virtual_rows_impl(li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        let mut packed_inputs = pack_native_input::<F>(&li.bytes);
        let len = packed_inputs.len();
        for (i, packed_input) in packed_inputs.iter_mut().enumerate() {
            let is_final = if i + 1 == len { F::ONE } else { F::ZERO };
            packed_input.push(is_final);
        }
        packed_inputs
            .into_iter()
            .map(|p| KeccakVirtualInput::try_from_raw(p).unwrap())
            .collect_vec()
    }
    fn rlc_virtual_rows(
        (gate_ctx, rlc_ctx): (&mut Context<F>, &mut Context<F>),
        range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
        virtual_rows: &[(Self::InputWitness, Self::OutputWitness)],
    ) -> Vec<AssignedValue<F>> {
        let gate = &range_chip.gate;
        let one = gate_ctx.load_constant(F::ONE);
        let zero = gate_ctx.load_zero();
        let empty_input_rlc = rlc_chip.rlc_pow_fixed(gate_ctx, gate, NUM_WITNESS_PER_KECCAK_F - 1);
        // = rlc_chip.compute_rlc_fixed_len(rlc_ctx, [one, zero, zero, zero, zero, zero]).rlc_val;
        // empty_input_rlc[0] = empty_input_len + 1 = 1. empty_input corresponds to input = []

        let chunk_multiplier =
            rlc_chip.rlc_pow_fixed(gate_ctx, &range_chip.gate, NUM_WITNESS_PER_KECCAK_F);
        let output_multiplier = rlc_chip.rlc_pow_fixed(
            gate_ctx,
            &range_chip.gate,
            Self::OutputWitness::get_num_fields(),
        );

        // If last chunk is a final chunk.
        let mut last_is_final = one;
        // RLC of the current logical input.
        let mut curr_rlc = zero;
        let mut virtual_row_rlcs = Vec::with_capacity(virtual_rows.len());
        for (input, output) in virtual_rows {
            let mut input_to_rlc = input.packed_input;
            // +1 to length when calculating RLC in order to make sure 0 is not a valid RLC for any input. Therefore the lookup
            // table column doesn't need a selector.
            input_to_rlc[0] = range_chip.gate.add(gate_ctx, input_to_rlc[0], last_is_final);

            let chunk_rlc = rlc_chip.compute_rlc_fixed_len(rlc_ctx, input_to_rlc).rlc_val;
            curr_rlc = range_chip.gate.mul_add(gate_ctx, curr_rlc, chunk_multiplier, chunk_rlc);

            let input_rlc =
                range_chip.gate.select(gate_ctx, curr_rlc, empty_input_rlc, input.is_final);
            let output_rlc = rlc_chip.compute_rlc_fixed_len(rlc_ctx, output.hash.hi_lo()).rlc_val;
            let virtual_row_rlc =
                range_chip.gate.mul_add(gate_ctx, input_rlc, output_multiplier, output_rlc);
            virtual_row_rlcs.push(virtual_row_rlc);

            curr_rlc = range_chip.gate.select(gate_ctx, zero, curr_rlc, input.is_final);

            last_is_final = input.is_final;
        }
        virtual_row_rlcs
    }
}

lazy_static! {
    /// We cache the dummy circuit output to avoid re-computing it.
    /// The recomputation involves creating an optimized Poseidon spec, which is
    /// time intensive.
    static ref CACHED_DUMMY_CIRCUIT_OUTPUT: RwLock<TypeMap> = RwLock::new(TypeMap::new());
}

/// The default dummy_circuit_output needs to do Poseidon. Poseidon generic over F
/// requires re-computing the optimized Poseidon spec, which is computationally
/// intensive. Since we call dummy_circuit_output very often, we cache the result
/// as a performance optimization.
fn dummy_circuit_output<F: crate::RawField>() -> KeccakCircuitOutput<F> {
    use zkevm_hashes::keccak::component::output::dummy_circuit_output;

    let cached_output =
        CACHED_DUMMY_CIRCUIT_OUTPUT.read().unwrap().get::<KeccakCircuitOutput<F>>().cloned();
    if let Some(cached_output) = cached_output {
        return cached_output;
    }
    let output = dummy_circuit_output::<F>();
    CACHED_DUMMY_CIRCUIT_OUTPUT.write().unwrap().insert(output);
    output
}
