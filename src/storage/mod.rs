use crate::{
    block_header::{
        EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness,
        GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    mpt::{AssignedBytes, MPTFixedKeyInput, MPTFixedKeyProof, MPTFixedKeyProofWitness},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::{RlcContextPair, RlcTrace, FIRST_PHASE, RLC_PHASE},
        RlpArrayTraceWitness, RlpChip, RlpFieldTraceWitness, RlpFieldWitness,
    },
    util::{
        bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, encode_addr_to_field,
        encode_h256_to_field, encode_u256_to_field, uint_to_bytes_be, AssignedH256,
        EthConfigParams,
    },
    EthChip, EthCircuitBuilder, Field, Network, ETH_LOOKUP_BITS,
};
use ethers_core::types::{Address, Block, H256, U256};
#[cfg(feature = "providers")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{builder::GateThreadBuilder, RangeChip},
    utils::bit_length,
    AssignedValue, Context,
};
use itertools::Itertools;
use rayon::prelude::*;
use std::{cell::RefCell, env::var, marker::PhantomData};

#[cfg(all(test, feature = "providers"))]
mod tests;

#[derive(Clone, Debug)]
pub struct EthAccountTrace<F: Field> {
    pub nonce_trace: RlcTrace<F>,
    pub balance_trace: RlcTrace<F>,
    pub storage_root_trace: RlcTrace<F>,
    pub code_hash_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthAccountTraceWitness<F: Field> {
    array_witness: RlpArrayTraceWitness<F>,
    mpt_witness: MPTFixedKeyProofWitness<F>,
}

impl<F: Field> EthAccountTraceWitness<F> {
    pub fn get(&self, acct_field: &str) -> &RlpFieldWitness<F> {
        match acct_field {
            "nonce" => &self.array_witness.field_witness[0],
            "balance" => &self.array_witness.field_witness[1],
            "storage_root" | "storageRoot" => &self.array_witness.field_witness[2],
            "code_hash" | "codeHash" => &self.array_witness.field_witness[3],
            _ => panic!("invalid account field"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthStorageTrace<F: Field> {
    pub value_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthStorageTraceWitness<F: Field> {
    value_witness: RlpFieldTraceWitness<F>,
    mpt_witness: MPTFixedKeyProofWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub acct_trace: EthAccountTrace<F>,
    pub storage_trace: Vec<EthStorageTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTraceWitness<F: Field> {
    block_witness: EthBlockHeaderTraceWitness<F>,
    acct_witness: EthAccountTraceWitness<F>,
    storage_witness: Vec<EthStorageTraceWitness<F>>,
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub address: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<(AssignedH256<F>, AssignedH256<F>)>,
}

pub trait EthStorageChip<F: Field> {
    fn parse_account_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        state_root_bytes: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthAccountTraceWitness<F>;

    fn parse_account_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthAccountTraceWitness<F>,
    ) -> EthAccountTrace<F>;

    fn parse_storage_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        storage_root_bytes: &[AssignedValue<F>],
        slot_bytes: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthStorageTraceWitness<F>;

    fn parse_storage_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthStorageTraceWitness<F>,
    ) -> EthStorageTrace<F>;

    fn parse_eip1186_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        state_root_bytes: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        acct_pf: MPTFixedKeyProof<F>,
        storage_pfs: Vec<(AssignedBytes<F>, MPTFixedKeyProof<F>)>, // (slot_bytes, storage_proof)
    ) -> (EthAccountTraceWitness<F>, Vec<EthStorageTraceWitness<F>>);

    fn parse_eip1186_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: (EthAccountTraceWitness<F>, Vec<EthStorageTraceWitness<F>>),
    ) -> (EthAccountTrace<F>, Vec<EthStorageTrace<F>>);

    // slot and block_hash are big-endian 16-byte
    // inputs have H256 represented in (hi,lo) format as two u128s
    // block number and slot values can be derived from the final trace output
    fn parse_eip1186_proofs_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockStorageInputAssigned<F>,
        network: Network,
    ) -> (EthBlockAccountStorageTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proofs_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockAccountStorageTraceWitness<F>,
    ) -> EthBlockAccountStorageTrace<F>
    where
        Self: EthBlockHeaderChip<F>;
}

impl<'chip, F: Field> EthStorageChip<F> for EthChip<'chip, F> {
    fn parse_account_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        state_root_bytes: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthAccountTraceWitness<F> {
        assert_eq!(32, proof.key_byte_len);

        // check key is keccak(addr)
        assert_eq!(addr.len(), 20);
        let hash_query_idx = keccak.keccak_fixed_len(ctx, self.gate(), addr, None);
        let hash_bytes = &keccak.fixed_len_queries[hash_query_idx].output_assigned;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }

        // check MPT root is state root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(state_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse value RLP([nonce, balance, storage_root, code_hash])
        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            proof.value_bytes.clone(),
            &[33, 13, 33, 33],
            false,
        );
        // Check MPT inclusion for:
        // keccak(addr) => RLP([nonce, balance, storage_root, code_hash])
        let max_depth = proof.max_depth;
        let mpt_witness =
            self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, proof, 32, 114, max_depth);

        EthAccountTraceWitness { array_witness, mpt_witness }
    }

    fn parse_account_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthAccountTraceWitness<F>,
    ) -> EthAccountTrace<F> {
        self.parse_mpt_inclusion_fixed_key_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        let array_trace: [_; 4] = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.array_witness, false)
            .field_trace
            .try_into()
            .unwrap();
        let [nonce_trace, balance_trace, storage_root_trace, code_hash_trace] =
            array_trace.map(|trace| trace.field_trace);
        EthAccountTrace { nonce_trace, balance_trace, storage_root_trace, code_hash_trace }
    }

    fn parse_storage_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        storage_root_bytes: &[AssignedValue<F>],
        slot: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthStorageTraceWitness<F> {
        assert_eq!(32, proof.key_byte_len);

        // check key is keccak(slot)
        let hash_query_idx = keccak.keccak_fixed_len(ctx, self.gate(), slot, None);
        let hash_bytes = &keccak.fixed_len_queries[hash_query_idx].output_assigned;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }
        // check MPT root is storage_root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(storage_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse slot value
        let value_witness =
            self.rlp().decompose_rlp_field_phase0(ctx, proof.value_bytes.clone(), 32);
        // check MPT inclusion
        let max_depth = proof.max_depth;
        let mpt_witness =
            self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, proof, 32, 33, max_depth);

        EthStorageTraceWitness { value_witness, mpt_witness }
    }

    fn parse_storage_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthStorageTraceWitness<F>,
    ) -> EthStorageTrace<F> {
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.parse_mpt_inclusion_fixed_key_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let value_trace =
            self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness.value_witness);
        let value_trace = value_trace.field_trace;
        debug_assert_eq!(value_trace.max_len, 32);
        EthStorageTrace { value_trace }
    }

    fn parse_eip1186_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        state_root: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        acct_pf: MPTFixedKeyProof<F>,
        storage_pfs: Vec<(AssignedBytes<F>, MPTFixedKeyProof<F>)>, // (slot_bytes, storage_proof)
    ) -> (EthAccountTraceWitness<F>, Vec<EthStorageTraceWitness<F>>) {
        // TODO: spawn separate thread for account proof; just need to get storage_root first somehow
        let ctx = thread_pool.main(FIRST_PHASE);
        let acct_trace = self.parse_account_proof_phase0(ctx, keccak, state_root, addr, acct_pf);
        // ctx dropped
        let storage_root = &acct_trace.get("storage_root").field_cells;

        // parallelize storage proofs
        let witness_gen_only = thread_pool.witness_gen_only();
        let ctx_ids = storage_pfs.iter().map(|_| thread_pool.get_new_thread_id()).collect_vec();
        let (mut storage_trace, ctx_keccaks): (Vec<_>, Vec<_>) = storage_pfs
            .into_par_iter()
            .zip(ctx_ids.into_par_iter())
            .map(|((slot, storage_pf), ctx_id)| {
                let mut ctx = Context::new(witness_gen_only, ctx_id);
                let mut keccak = KeccakChip::default();
                let trace = self.parse_storage_proof_phase0(
                    &mut ctx,
                    &mut keccak,
                    storage_root,
                    slot,
                    storage_pf,
                );
                (trace, (ctx, keccak))
            })
            .unzip();
        // join gate contexts and keccak queries; need to shift keccak query indices because of the join
        for (trace, (ctx, mut keccak_)) in storage_trace.iter_mut().zip(ctx_keccaks.into_iter()) {
            thread_pool.threads[FIRST_PHASE].push(ctx);
            keccak.fixed_len_queries.append(&mut keccak_.fixed_len_queries);
            trace.mpt_witness.shift_query_indices(keccak.var_len_queries.len());
            keccak.var_len_queries.append(&mut keccak_.var_len_queries);
        }

        (acct_trace, storage_trace)
    }

    fn parse_eip1186_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        (acct_witness, storage_witness): (
            EthAccountTraceWitness<F>,
            Vec<EthStorageTraceWitness<F>>,
        ),
    ) -> (EthAccountTrace<F>, Vec<EthStorageTrace<F>>) {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let acct_trace = self.parse_account_proof_phase1((ctx_gate, ctx_rlc), acct_witness);

        // pre-load rlc cache so later parallelization is deterministic
        let max_len = storage_witness
            .iter()
            .map(|w| (2 * w.mpt_witness.key_byte_len).max(w.value_witness.rlp_field.len()))
            .max()
            .unwrap_or(1);
        let cache_bits = bit_length(max_len as u64);
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), cache_bits);
        // parallelize
        let witness_gen_only = thread_pool.witness_gen_only();
        let ctx_ids = storage_witness
            .iter()
            .map(|_| (thread_pool.get_new_thread_id(), thread_pool.get_new_thread_id()))
            .collect_vec();
        let (storage_trace, ctxs): (Vec<_>, Vec<_>) = storage_witness
            .into_par_iter()
            .zip(ctx_ids.into_par_iter())
            .map(|(storage_witness, (gate_id, rlc_id))| {
                let mut ctx_gate = Context::new(witness_gen_only, gate_id);
                let mut ctx_rlc = Context::new(witness_gen_only, rlc_id);
                let trace =
                    self.parse_storage_proof_phase1((&mut ctx_gate, &mut ctx_rlc), storage_witness);
                (trace, (ctx_gate, ctx_rlc))
            })
            .unzip();
        let (mut ctxs_gate, mut ctxs_rlc): (Vec<_>, Vec<_>) = ctxs.into_iter().unzip();
        thread_pool.gate_builder.threads[RLC_PHASE].append(&mut ctxs_gate);
        thread_pool.threads_rlc.append(&mut ctxs_rlc);
        (acct_trace, storage_trace)
    }

    fn parse_eip1186_proofs_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockStorageInputAssigned<F>,
        network: Network,
    ) -> (EthBlockAccountStorageTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let ctx = thread_pool.main(FIRST_PHASE);
        let address = input.storage.address;
        let mut block_header = input.block_header;
        let max_len = match network {
            Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
        };
        block_header.resize(max_len, 0);
        let block_witness = self.decompose_block_header_phase0(ctx, keccak, &block_header, network);

        let state_root = &block_witness.get("state_root").field_cells;
        let block_hash_hi_lo = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.get("number").field_cells;
        let block_num_len = block_witness.get("number").field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 4);
        let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, 4);

        // verify account + storage proof
        let addr_bytes = uint_to_bytes_be(ctx, self.range(), &address, 20);
        let (slots, storage_pfs): (Vec<_>, Vec<_>) = input
            .storage
            .storage_pfs
            .into_iter()
            .map(|(slot, storage_pf)| {
                let slot_bytes =
                    slot.iter().map(|u128| uint_to_bytes_be(ctx, self.range(), u128, 16)).concat();
                (slot, (slot_bytes, storage_pf))
            })
            .unzip();
        // drop ctx
        let (acct_witness, storage_witness) = self.parse_eip1186_proofs_phase0(
            thread_pool,
            keccak,
            state_root,
            addr_bytes,
            input.storage.acct_pf,
            storage_pfs,
        );

        let ctx = thread_pool.main(FIRST_PHASE);
        let slots_values = slots
            .into_iter()
            .zip(storage_witness.iter())
            .map(|(slot, witness)| {
                // get value as U256 from RLP decoding, convert to H256, then to hi-lo
                let value_bytes = &witness.value_witness.witness.field_cells;
                let value_len = witness.value_witness.witness.field_len;
                let value_bytes =
                    bytes_be_var_to_fixed(ctx, self.gate(), value_bytes, value_len, 32);
                let value: [_; 2] =
                    bytes_be_to_u128(ctx, self.gate(), &value_bytes).try_into().unwrap();
                (slot, value)
            })
            .collect_vec();
        (
            EthBlockAccountStorageTraceWitness { block_witness, acct_witness, storage_witness },
            EIP1186ResponseDigest {
                block_hash: block_hash_hi_lo.try_into().unwrap(),
                block_number,
                address,
                slots_values,
            },
        )
    }

    fn parse_eip1186_proofs_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockAccountStorageTraceWitness<F>,
    ) -> EthBlockAccountStorageTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let block_trace =
            self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let (acct_trace, storage_trace) = self.parse_eip1186_proofs_phase1(
            thread_pool,
            (witness.acct_witness, witness.storage_witness),
        );
        EthBlockAccountStorageTrace { block_trace, acct_trace, storage_trace }
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
    pub block_hash: H256, // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub storage: EthStorageInput,
}

impl EthStorageInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthStorageInputAssigned<F> {
        let address = encode_addr_to_field(&self.addr);
        let address = ctx.load_witness(address);
        let acct_pf = self.acct_pf.assign(ctx);
        let storage_pfs = self
            .storage_pfs
            .into_iter()
            .map(|(slot, _, pf)| {
                let slot = encode_h256_to_field(&slot);
                let slot = slot.map(|slot| ctx.load_witness(slot));
                let pf = pf.assign(ctx);
                (slot, pf)
            })
            .collect();
        EthStorageInputAssigned { address, acct_pf, storage_pfs }
    }
}

impl EthBlockStorageInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthBlockStorageInputAssigned<F> {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let storage = self.storage.assign(ctx);
        EthBlockStorageInputAssigned { block_header: self.block_header, storage }
    }
}

#[derive(Clone, Debug)]
pub struct EthStorageInputAssigned<F: Field> {
    pub address: AssignedValue<F>, // U160
    pub acct_pf: MPTFixedKeyProof<F>,
    pub storage_pfs: Vec<(AssignedH256<F>, MPTFixedKeyProof<F>)>, // (slot, proof) where slot is H256 as (u128, u128)
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageInputAssigned<F: Field> {
    // block_hash: AssignedH256<F>, // H256 as (u128, u128)
    pub block_header: Vec<u8>,
    pub storage: EthStorageInputAssigned<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageCircuit<F> {
    pub inputs: EthBlockStorageInput, // public and private inputs
    pub network: Network,
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

    // MAYBE UNUSED
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

    pub fn create_circuit(
        self,
        mut builder: RlcThreadBuilder<F>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<F, impl FnSynthesize<F>> {
        let prover = builder.witness_gen_only();
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();
        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let input = self.inputs.assign(ctx);
        let (witness, digest) = chip.parse_eip1186_proofs_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            self.network,
        );
        let EIP1186ResponseDigest { block_hash, block_number, address, slots_values } = digest;
        let assigned_instances = block_hash
            .into_iter()
            .chain([block_number, address])
            .chain(
                slots_values
                    .into_iter()
                    .flat_map(|(slot, value)| slot.into_iter().chain(value.into_iter())),
            )
            .collect_vec();

        let circuit = EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<F>,
                  rlp: RlpChip<F>,
                  keccak_rlcs: (FixedLenRLCs<F>, VarLenRLCs<F>)| {
                // ======== SECOND PHASE ===========
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                let _trace = chip.parse_eip1186_proofs_from_block_phase1(builder, witness);
            },
        );
        if !prover {
            let config_params: EthConfigParams = serde_json::from_str(
                var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
            )
            .unwrap();
            circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
        }
        circuit
    }
}
