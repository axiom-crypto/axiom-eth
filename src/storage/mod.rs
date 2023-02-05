use crate::{
    block_header::{
        EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness,
        GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    mpt::{AssignedBytes, MPTFixedKeyInput, MPTFixedKeyProof, MPTFixedKeyProofWitness},
    rlp::{rlc::RlcTrace, RlpArrayTraceWitness, RlpFieldTraceWitness},
    util::{
        bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, encode_addr_to_field,
        encode_h256_to_field, encode_u256_to_field, uint_to_bytes_be, AssignedH256,
        EthConfigParams,
    },
    EthChip, EthConfig, Field, Network,
};
#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use ethers_core::types::{Address, Block, H256, U256};
#[cfg(feature = "providers")]
use ethers_providers::{Http, Provider};
use halo2_base::{gates::GateInstructions, AssignedValue, Context, ContextParams, SKIP_FIRST_PASS};
use itertools::Itertools;
use snark_verifier_sdk::CircuitExt;
use std::marker::PhantomData;

#[cfg(all(test, feature = "providers"))]
mod tests;

#[derive(Clone, Debug)]
pub struct EthAccountTrace<'v, F: Field> {
    pub nonce_trace: RlcTrace<'v, F>,
    pub balance_trace: RlcTrace<'v, F>,
    pub storage_root_trace: RlcTrace<'v, F>,
    pub code_hash_trace: RlcTrace<'v, F>,
}

#[derive(Clone, Debug)]
pub struct EthAccountTraceWitness<'v, F: Field> {
    array_witness: RlpArrayTraceWitness<'v, F>,
    mpt_witness: MPTFixedKeyProofWitness<'v, F>,
}

#[derive(Clone, Debug)]
pub struct EthStorageTrace<'v, F: Field> {
    pub value_bytes: AssignedBytes<'v, F>,
}

#[derive(Clone, Debug)]
pub struct EthStorageTraceWitness<'v, F: Field> {
    value_witness: RlpFieldTraceWitness<'v, F>,
    mpt_witness: MPTFixedKeyProofWitness<'v, F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTrace<'v, F: Field> {
    pub block_trace: EthBlockHeaderTrace<'v, F>,
    pub acct_trace: EthAccountTrace<'v, F>,
    pub storage_trace: Vec<EthStorageTrace<'v, F>>,
    pub digest: EIP1186ResponseDigest<'v, F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTraceWitness<'v, F: Field> {
    block_witness: EthBlockHeaderTraceWitness<'v, F>,
    acct_witness: EthAccountTraceWitness<'v, F>,
    storage_witness: Vec<EthStorageTraceWitness<'v, F>>,
    digest: EIP1186ResponseDigest<'v, F>,
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<'v, F: Field> {
    pub block_hash: AssignedH256<'v, F>,
    pub block_number: AssignedValue<'v, F>,
    pub address: AssignedValue<'v, F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<(AssignedH256<'v, F>, AssignedH256<'v, F>)>,
}

pub trait EthStorageChip<'v, F: Field> {
    fn parse_account_proof_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        state_root_bytes: &[AssignedValue<'v, F>],
        addr: AssignedBytes<'v, F>,
        proof: MPTFixedKeyProof<'v, F>,
    ) -> EthAccountTraceWitness<'v, F>;

    fn parse_account_proof_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: EthAccountTraceWitness<'v, F>,
    ) -> EthAccountTrace<'v, F>;

    fn parse_storage_proof_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        storage_root_bytes: &[AssignedValue<'v, F>],
        slot_bytes: AssignedBytes<'v, F>,
        proof: MPTFixedKeyProof<'v, F>,
    ) -> EthStorageTraceWitness<'v, F>;

    fn parse_storage_proof_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: EthStorageTraceWitness<'v, F>,
    ) -> EthStorageTrace<'v, F>;

    fn parse_eip1186_proofs_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        state_root_bytes: &[AssignedValue<'v, F>],
        addr: AssignedBytes<'v, F>,
        acct_pf: MPTFixedKeyProof<'v, F>,
        storage_pfs: Vec<(AssignedBytes<'v, F>, MPTFixedKeyProof<'v, F>)>, // (slot_bytes, storage_proof)
    ) -> (EthAccountTraceWitness<'v, F>, Vec<EthStorageTraceWitness<'v, F>>);

    fn parse_eip1186_proofs_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: (EthAccountTraceWitness<'v, F>, Vec<EthStorageTraceWitness<'v, F>>),
    ) -> (EthAccountTrace<'v, F>, Vec<EthStorageTrace<'v, F>>);

    // slot and block_hash are big-endian 16-byte
    // inputs have H256 represented in (hi,lo) format as two u128s
    // block number and slot values can be derived from the final trace output
    fn parse_eip1186_proofs_from_block_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        input: EthBlockStorageInputAssigned<'v, F>,
        network: Network,
    ) -> EthBlockAccountStorageTraceWitness<'v, F>
    where
        Self: EthBlockHeaderChip<'v, F>;

    fn parse_eip1186_proofs_from_block_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: EthBlockAccountStorageTraceWitness<'v, F>,
    ) -> EthBlockAccountStorageTrace<'v, F>
    where
        Self: EthBlockHeaderChip<'v, F>;
}

impl<'v, F: Field> EthStorageChip<'v, F> for EthChip<'v, F> {
    fn parse_account_proof_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        state_root_bytes: &[AssignedValue<'v, F>],
        addr: AssignedBytes<'v, F>,
        proof: MPTFixedKeyProof<'v, F>,
    ) -> EthAccountTraceWitness<'v, F> {
        assert_eq!(32, proof.key_byte_len);

        // check key is keccak(addr)
        assert_eq!(addr.len(), 20);
        let hash_query_idx = self.mpt.keccak.keccak_fixed_len(ctx, self.mpt.rlp.gate(), addr, None);
        let hash_bytes = &self.keccak().fixed_len_queries[hash_query_idx].output_assigned;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }

        // check MPT root is state root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(state_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse value RLP([nonce, balance, storage_root, code_hash])
        let array_witness = self.mpt.rlp.decompose_rlp_array_phase0(
            ctx,
            proof.value_bytes.clone(),
            &[33, 13, 33, 33],
            false,
        );
        // Check MPT inclusion for:
        // keccak(addr) => RLP([nonce, balance, storage_root, code_hash])
        let max_depth = proof.max_depth;
        let mpt_witness =
            self.mpt.parse_mpt_inclusion_fixed_key_phase0(ctx, proof, 32, 114, max_depth);

        EthAccountTraceWitness { array_witness, mpt_witness }
    }

    fn parse_account_proof_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: EthAccountTraceWitness<'v, F>,
    ) -> EthAccountTrace<'v, F> {
        self.mpt.parse_mpt_inclusion_fixed_key_phase1(ctx, witness.mpt_witness);
        let array_trace: [_; 4] = self
            .mpt
            .rlp
            .decompose_rlp_array_phase1(ctx, witness.array_witness, false)
            .field_trace
            .try_into()
            .unwrap();
        let [nonce_trace, balance_trace, storage_root_trace, code_hash_trace] =
            array_trace.map(|trace| trace.field_trace);
        EthAccountTrace { nonce_trace, balance_trace, storage_root_trace, code_hash_trace }
    }

    fn parse_storage_proof_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        storage_root_bytes: &[AssignedValue<'v, F>],
        slot: AssignedBytes<'v, F>,
        proof: MPTFixedKeyProof<'v, F>,
    ) -> EthStorageTraceWitness<'v, F> {
        assert_eq!(32, proof.key_byte_len);

        // check key is keccak(slot)
        let hash_query_idx = self.mpt.keccak.keccak_fixed_len(ctx, self.mpt.rlp.gate(), slot, None);
        let hash_bytes = &self.keccak().fixed_len_queries[hash_query_idx].output_assigned;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }
        // check MPT root is storage_root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(storage_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse slot value
        let value_witness =
            self.mpt.rlp.decompose_rlp_field_phase0(ctx, proof.value_bytes.clone(), 32);
        // check MPT inclusion
        let max_depth = proof.max_depth;
        let mpt_witness =
            self.mpt.parse_mpt_inclusion_fixed_key_phase0(ctx, proof, 32, 33, max_depth);

        EthStorageTraceWitness { value_witness, mpt_witness }
    }

    fn parse_storage_proof_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: EthStorageTraceWitness<'v, F>,
    ) -> EthStorageTrace<'v, F> {
        self.mpt.parse_mpt_inclusion_fixed_key_phase1(ctx, witness.mpt_witness);
        let value_trace = self.mpt.rlp.decompose_rlp_field_phase1(ctx, witness.value_witness);
        let value_bytes = value_trace.field_trace.values;
        debug_assert_eq!(value_bytes.len(), 32);
        EthStorageTrace { value_bytes }
    }

    fn parse_eip1186_proofs_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        state_root: &[AssignedValue<'v, F>],
        addr: AssignedBytes<'v, F>,
        acct_pf: MPTFixedKeyProof<'v, F>,
        storage_pfs: Vec<(AssignedBytes<'v, F>, MPTFixedKeyProof<'v, F>)>, // (slot_bytes, storage_proof)
    ) -> (EthAccountTraceWitness<'v, F>, Vec<EthStorageTraceWitness<'v, F>>) {
        let acct_trace = self.parse_account_proof_phase0(ctx, state_root, addr, acct_pf);
        let storage_root = &acct_trace.array_witness.field_witness[2].field_cells;

        let storage_trace = storage_pfs
            .into_iter()
            .map(|(slot, storage_pf)| {
                self.parse_storage_proof_phase0(ctx, storage_root, slot, storage_pf)
            })
            .collect();

        (acct_trace, storage_trace)
    }

    fn parse_eip1186_proofs_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        (acct_witness, storage_witness): (
            EthAccountTraceWitness<'v, F>,
            Vec<EthStorageTraceWitness<'v, F>>,
        ),
    ) -> (EthAccountTrace<'v, F>, Vec<EthStorageTrace<'v, F>>) {
        let acct_trace = self.parse_account_proof_phase1(ctx, acct_witness);
        let storage_trace = storage_witness
            .into_iter()
            .map(|storage_witness| self.parse_storage_proof_phase1(ctx, storage_witness))
            .collect();
        (acct_trace, storage_trace)
    }

    fn parse_eip1186_proofs_from_block_phase0(
        &mut self,
        ctx: &mut Context<'v, F>,
        input: EthBlockStorageInputAssigned<'v, F>,
        network: Network,
    ) -> EthBlockAccountStorageTraceWitness<'v, F>
    where
        Self: EthBlockHeaderChip<'v, F>,
    {
        // check block_hash
        // TODO: more optimal to compute the `block_hash` via keccak below and then just constrain the bytes match this (hi,lo) representation
        let block_hash = input.block_hash;
        let address = input.storage.address;
        let block_hash_bytes0 =
            block_hash.iter().map(|u128| uint_to_bytes_be(ctx, self.range(), u128, 16)).concat();
        let mut block_header = input.block_header;
        let max_len = match network {
            Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
        };
        block_header.resize(max_len, 0);
        let block_witness = self.decompose_block_header_phase0(ctx, &block_header, network);

        let state_root = &block_witness.rlp_witness.field_witness[3].field_cells;
        let block_hash_bytes1 =
            &self.keccak().var_len_queries[block_witness.block_hash_query_idx].output_assigned;
        for (byte0, byte1) in block_hash_bytes0.iter().zip(block_hash_bytes1.iter()) {
            ctx.constrain_equal(byte0, byte1);
        }

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.rlp_witness.field_witness[8].field_cells;
        let block_num_len = &block_witness.rlp_witness.field_witness[8].field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 4);
        let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, 4);

        // verify account + storage proof
        let addr_bytes = uint_to_bytes_be(ctx, self.range(), &address, 20);
        let acct_witness = self.parse_account_proof_phase0(
            ctx,
            state_root,
            addr_bytes.clone(),
            input.storage.acct_pf,
        );
        let storage_root = &acct_witness.array_witness.field_witness[2].field_cells;

        let mut slots_values = Vec::with_capacity(input.storage.storage_pfs.len());
        let storage_witness = input
            .storage
            .storage_pfs
            .into_iter()
            .map(|(slot, storage_pf)| {
                let slot_bytes =
                    slot.iter().map(|u128| uint_to_bytes_be(ctx, self.range(), u128, 16)).concat();
                let witness =
                    self.parse_storage_proof_phase0(ctx, storage_root, slot_bytes, storage_pf);
                // get value as U256 from RLP decoding, convert to H256, then to hi-lo
                let value_bytes = &witness.value_witness.witness.field_cells;
                let value_len = &witness.value_witness.witness.field_len;
                let value_bytes =
                    bytes_be_var_to_fixed(ctx, self.gate(), value_bytes, value_len, 32);
                let value: [_; 2] =
                    bytes_be_to_u128(ctx, self.gate(), &value_bytes).try_into().unwrap();
                slots_values.push((slot, value));

                witness
            })
            .collect();
        EthBlockAccountStorageTraceWitness {
            block_witness,
            acct_witness,
            storage_witness,
            digest: EIP1186ResponseDigest { block_hash, block_number, address, slots_values },
        }
    }

    fn parse_eip1186_proofs_from_block_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        witness: EthBlockAccountStorageTraceWitness<'v, F>,
    ) -> EthBlockAccountStorageTrace<'v, F>
    where
        Self: EthBlockHeaderChip<'v, F>,
    {
        let block_trace = self.decompose_block_header_phase1(ctx, witness.block_witness);
        let (acct_trace, storage_trace) =
            self.parse_eip1186_proofs_phase1(ctx, (witness.acct_witness, witness.storage_witness));
        EthBlockAccountStorageTrace {
            block_trace,
            acct_trace,
            storage_trace,
            digest: witness.digest,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthStorageInput {
    pub addr: Address,
    pub acct_pf: MPTFixedKeyInput,
    pub storage_pfs: Vec<(H256, U256, MPTFixedKeyInput)>, // (slot, value, proof)
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageInput {
    pub block: Block<H256>,
    pub block_number: u32,
    pub block_hash: H256,
    pub block_header: Vec<u8>,
    pub storage: EthStorageInput,
}

impl EthStorageInput {
    pub fn assign<'v, F: Field>(
        &self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
    ) -> EthStorageInputAssigned<'v, F> {
        let address = encode_addr_to_field(&self.addr);
        let address = gate.load_witness(ctx, Value::known(address));
        let acct_pf = self.acct_pf.assign(ctx, gate);
        let storage_pfs = self
            .storage_pfs
            .iter()
            .map(|(slot, _, pf)| {
                let slot = encode_h256_to_field(slot);
                let slot = slot.map(|slot| gate.load_witness(ctx, Value::known(slot)));
                let pf = pf.assign(ctx, gate);
                (slot, pf)
            })
            .collect();
        EthStorageInputAssigned { address, acct_pf, storage_pfs }
    }
}

impl EthBlockStorageInput {
    pub fn assign<'v, F: Field>(
        &self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
    ) -> EthBlockStorageInputAssigned<'v, F> {
        let block_hash = encode_h256_to_field(&self.block_hash);
        let block_hash =
            block_hash.map(|block_hash| gate.load_witness(ctx, Value::known(block_hash)));
        let storage = self.storage.assign(ctx, gate);
        EthBlockStorageInputAssigned {
            block_hash,
            block_header: self.block_header.clone(),
            storage,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthStorageInputAssigned<'v, F: Field> {
    pub address: AssignedValue<'v, F>, // U160
    pub acct_pf: MPTFixedKeyProof<'v, F>,
    pub storage_pfs: Vec<(AssignedH256<'v, F>, MPTFixedKeyProof<'v, F>)>, // (slot, proof) where slot is H256 as (u128, u128)
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageInputAssigned<'v, F: Field> {
    pub block_hash: AssignedH256<'v, F>, // H256 as (u128, u128)
    pub block_header: Vec<u8>,
    pub storage: EthStorageInputAssigned<'v, F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageCircuit<F> {
    pub inputs: EthBlockStorageInput,
    network: Network,
    _marker: PhantomData<F>,
}

impl<F: Field> EthBlockStorageCircuit<F> {
    #[cfg(feature = "providers")]
    pub fn from_provider(
        provider: &Provider<Http>,
        block_number: u32,
        address: Address,
        slots: Vec<H256>,
        acct_pf_max_depth: usize,
        storage_pf_max_depth: usize,
        network: Network,
    ) -> Self {
        use crate::providers::get_block_storage_input;

        let inputs = get_block_storage_input(
            provider,
            block_number,
            address,
            slots,
            acct_pf_max_depth,
            storage_pf_max_depth,
        );
        Self { inputs, network, _marker: PhantomData }
    }

    // blockHash, blockNumber, address, (slot, value)s
    // with H256 encoded as hi-lo (u128, u128)
    pub fn instance(&self) -> Vec<F> {
        let EthBlockStorageInput { block_number, block_hash, storage, .. } = &self.inputs;
        let EthStorageInput { addr, storage_pfs, .. } = storage;
        let mut instance = Vec::with_capacity(4 + 4 * storage_pfs.len());
        instance.extend(encode_h256_to_field::<F>(block_hash));
        instance.push(F::from(*block_number as u64));
        instance.push(encode_addr_to_field(addr));
        for (slot, value, _) in storage_pfs {
            instance.extend(encode_h256_to_field::<F>(slot));
            instance.extend(encode_u256_to_field::<F>(value));
        }
        instance
    }
}

impl<F: Field> Circuit<F> for EthBlockStorageCircuit<F> {
    type Config = EthConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = EthConfigParams::get_storage();
        EthConfig::configure(meta, params, 0)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        #[cfg(feature = "display")]
        let witness_gen = start_timer!(|| "synthesize");

        let gamma = layouter.get_challenge(config.rlc().gamma);
        config.range().load_lookup_table(&mut layouter).expect("load range lookup table");
        config.keccak().load_aux_tables(&mut layouter).expect("load keccak lookup tables");

        let mut first_pass = SKIP_FIRST_PASS;
        let mut instance = vec![];
        layouter
            .assign_region(
                || "eth_getProof verify from blockHash",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let mut chip = EthChip::new(config.clone(), gamma);
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: chip.gate().max_rows,
                            num_context_ids: 2,
                            fixed_columns: chip.gate().constants.clone(),
                        },
                    );
                    let ctx = &mut aux;

                    // ================= FIRST PHASE ================
                    let input = self.inputs.assign(ctx, chip.gate());
                    let witness =
                        chip.parse_eip1186_proofs_from_block_phase0(ctx, input, self.network);
                    chip.assign_phase0(ctx);
                    ctx.next_phase();

                    // ================= SECOND PHASE ================
                    chip.get_challenge(ctx);
                    chip.keccak_assign_phase1(ctx);

                    let trace = chip.parse_eip1186_proofs_from_block_phase1(ctx, witness);
                    let EIP1186ResponseDigest { block_hash, block_number, address, slots_values } =
                        trace.digest;
                    chip.range().finalize(ctx);

                    instance.extend(
                        block_hash
                            .iter()
                            .chain([block_number, address].iter())
                            .chain(
                                slots_values
                                    .iter()
                                    .flat_map(|(slot, value)| slot.iter().chain(value.iter())),
                            )
                            .map(|acell| *acell.cell()),
                    );

                    #[cfg(feature = "display")]
                    ctx.print_stats(&["Range", "RLC"]);
                    Ok(())
                },
            )
            .unwrap();
        for (i, cell) in instance.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instance, i);
        }
        #[cfg(feature = "display")]
        end_timer!(witness_gen);
        Ok(())
    }
}

impl<F: Field> CircuitExt<F> for EthBlockStorageCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![4 + 4 * self.inputs.storage.storage_pfs.len()]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instance()]
    }
}
