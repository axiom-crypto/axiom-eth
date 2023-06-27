use crate::{
    batch_query::response::{ByteArray, FixedByteArray},
    block_header::{
        EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness,
        GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
    },
    keccak::{
        parallelize_keccak_phase0, ContainsParallelizableKeccakQueries, FixedLenRLCs, FnSynthesize,
        KeccakChip, VarLenRLCs,
    },
    mpt::{AssignedBytes, MPTFixedKeyInput, MPTFixedKeyProof, MPTFixedKeyProofWitness},
    rlp::{
        builder::{parallelize_phase1, RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::{RlcContextPair, RlcTrace, FIRST_PHASE},
        RlpArrayTraceWitness, RlpChip, RlpFieldTraceWitness, RlpFieldWitness,
    },
    util::{
        bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, encode_addr_to_field,
        encode_h256_to_field, encode_u256_to_field, uint_to_bytes_be, AssignedH256,
    },
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, Network, ETH_LOOKUP_BITS,
};
use ethers_core::types::{Address, Block, H256, U256};
#[cfg(feature = "providers")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

#[cfg(all(test, feature = "providers"))]
mod tests;

/*
| Account State Field     | Max bytes   |
|-------------------------|-------------|
| nonce                   | ≤8          |
| balance                 | ≤12         |
| storageRoot             | 32          |
| codeHash                | 32          |

account nonce is uint64 by https://eips.ethereum.org/EIPS/eip-2681
*/
pub(crate) const NUM_ACCOUNT_STATE_FIELDS: usize = 4;
pub(crate) const ACCOUNT_STATE_FIELDS_MAX_BYTES: [usize; NUM_ACCOUNT_STATE_FIELDS] =
    [8, 12, 32, 32];
pub(crate) const ACCOUNT_STATE_FIELD_IS_VAR_LEN: [bool; NUM_ACCOUNT_STATE_FIELDS] =
    [true, true, false, false];
pub(crate) const ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN: usize = 90;
pub(crate) const STORAGE_PROOF_VALUE_MAX_BYTE_LEN: usize = 33;
/*
let max_branch_bytes = MAX_BRANCH_LENS.1;
let (_, max_ext_bytes) = max_ext_lens(32);
// max_len dominated by max branch rlp length = 533
let max_len = max(max_ext_bytes, max_branch_bytes, 2 * 32, {ACCOUNT,STORAGE}_PROOF_VALUE_MAX_BYTE_LEN);
let cache_bits = bit_length(max_len)
*/
const CACHE_BITS: usize = 10;

pub const ACCOUNT_PROOF_MAX_DEPTH: usize = 10;
pub const STORAGE_PROOF_MAX_DEPTH: usize = 9;

#[derive(Clone, Debug)]
pub struct EthAccountTrace<F: Field> {
    pub nonce_trace: RlcTrace<F>,
    pub balance_trace: RlcTrace<F>,
    pub storage_root_trace: RlcTrace<F>,
    pub code_hash_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthAccountTraceWitness<F: Field> {
    pub address: AssignedBytes<F>,
    pub(crate) array_witness: RlpArrayTraceWitness<F>,
    pub(crate) mpt_witness: MPTFixedKeyProofWitness<F>,
}

impl<F: Field> EthAccountTraceWitness<F> {
    pub fn get_nonce(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[0]
    }
    pub fn get_balance(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[1]
    }
    pub fn get_storage_root(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[2]
    }
    pub fn get_code_hash(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[3]
    }
}

#[derive(Clone, Debug)]
pub struct EthStorageTrace<F: Field> {
    pub value_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthStorageTraceWitness<F: Field> {
    pub slot: AssignedBytes<F>,
    pub(crate) value_witness: RlpFieldTraceWitness<F>,
    pub(crate) mpt_witness: MPTFixedKeyProofWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub acct_trace: EthAccountTrace<F>,
    pub storage_trace: Vec<EthStorageTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub acct_witness: EthAccountTraceWitness<F>,
    pub storage_witness: Vec<EthStorageTraceWitness<F>>,
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub address: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<(AssignedH256<F>, AssignedH256<F>)>,
    pub address_is_empty: AssignedValue<F>,
    pub slot_is_empty: Vec<AssignedValue<F>>,
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthStorageTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthAccountTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

pub trait EthStorageChip<F: Field> {
    /// Does inclusion/exclusion proof of `key = keccak(addr)` into an alleged MPT state trie.
    /// RLP decodes the ethereumAccount.
    ///
    /// There is one global state trie, and it is updated every time a client processes a block. In it, a path is always: keccak256(ethereumAddress) and a value is always: rlp(ethereumAccount). More specifically an ethereum account is a 4 item array of [nonce,balance,storageRoot,codeHash].
    fn parse_account_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        addr: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthAccountTraceWitness<F>;

    /// SecondPhase of account proof parsing.
    fn parse_account_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthAccountTraceWitness<F>,
    ) -> EthAccountTrace<F>;

    /// Does multiple calls to [`parse_account_proof_phase0`] in parallel.
    fn parse_account_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        addr_proofs: Vec<(AssignedBytes<F>, MPTFixedKeyProof<F>)>,
    ) -> Vec<EthAccountTraceWitness<F>>
    where
        Self: Sync,
    {
        parallelize_keccak_phase0(thread_pool, keccak, addr_proofs, |ctx, keccak, (addr, proof)| {
            self.parse_account_proof_phase0(ctx, keccak, addr, proof)
        })
    }

    /// SecondPhase of account proofs parsing.
    fn parse_account_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: Vec<EthAccountTraceWitness<F>>,
    ) -> Vec<EthAccountTrace<F>>;

    /// Does inclusion/exclusion proof of `keccak(slot)` into an alleged MPT storage trie.
    ///
    /// storageRoot: A 256-bit hash of the root node of a Merkle Patricia tree that encodes the storage contents of the account (a mapping between 256-bit integer values), encoded into the trie as a mapping from the Keccak 256-bit hash of the 256-bit integer keys to the RLP-encoded 256-bit integer values. The hash is formally denoted σ[a]_s.
    fn parse_storage_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        slot: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthStorageTraceWitness<F>;

    /// SecondPhase of storage proof parsing.
    fn parse_storage_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthStorageTraceWitness<F>,
    ) -> EthStorageTrace<F>;

    /// Does multiple calls to [`parse_storage_proof_phase0`] in parallel.
    fn parse_storage_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        slot_proofs: Vec<(AssignedBytes<F>, MPTFixedKeyProof<F>)>,
    ) -> Vec<EthStorageTraceWitness<F>>
    where
        Self: Sync,
    {
        parallelize_keccak_phase0(thread_pool, keccak, slot_proofs, |ctx, keccak, (slot, proof)| {
            self.parse_storage_proof_phase0(ctx, keccak, slot, proof)
        })
    }

    /// SecondPhase of account proofs parsing.
    fn parse_storage_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: Vec<EthStorageTraceWitness<F>>,
    ) -> Vec<EthStorageTrace<F>>;

    /// Does inclusion/exclusion proof of `key = keccak(addr)` into an alleged MPT state trie.
    /// RLP decodes the ethereumAccount, which in particular gives the storageRoot.
    /// Does (multiple) inclusion/exclusion proof of `keccak(slot)` into the MPT storage trie with root storageRoot.
    fn parse_eip1186_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        addr: AssignedBytes<F>,
        acct_pf: MPTFixedKeyProof<F>,
        storage_pfs: Vec<(AssignedBytes<F>, MPTFixedKeyProof<F>)>, // (slot_bytes, storage_proof)
    ) -> (EthAccountTraceWitness<F>, Vec<EthStorageTraceWitness<F>>)
    where
        Self: Sync,
    {
        // TODO: spawn separate thread for account proof; just need to get storage_root first somehow
        let ctx = thread_pool.main(FIRST_PHASE);
        let acct_trace = self.parse_account_proof_phase0(ctx, keccak, addr, acct_pf);
        // ctx dropped
        let storage_root = &acct_trace.get_storage_root().field_cells;
        let storage_trace = parallelize_keccak_phase0(
            thread_pool,
            keccak,
            storage_pfs,
            |ctx, keccak, (slot, storage_pf)| {
                let witness = self.parse_storage_proof_phase0(ctx, keccak, slot, storage_pf);
                // check MPT root is storage_root
                for (pf_byte, byte) in
                    witness.mpt_witness.root_hash_bytes.iter().zip_eq(storage_root.iter())
                {
                    ctx.constrain_equal(pf_byte, byte);
                }
                witness
            },
        );
        (acct_trace, storage_trace)
    }

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
        address: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthAccountTraceWitness<F> {
        assert_eq!(32, proof.key_bytes.len());

        // check key is keccak(addr)
        assert_eq!(address.len(), 20);
        let hash_query_idx = keccak.keccak_fixed_len(ctx, self.gate(), address.clone(), None);
        let hash_addr = &keccak.fixed_len_queries[hash_query_idx].output_assigned;

        for (byte, key) in hash_addr.iter().zip_eq(proof.key_bytes.iter()) {
            ctx.constrain_equal(byte, key);
        }

        // parse value RLP([nonce, balance, storage_root, code_hash])
        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            proof.value_bytes.clone(),
            &ACCOUNT_STATE_FIELDS_MAX_BYTES,
            false,
        );
        // Check MPT inclusion for:
        // keccak(addr) => RLP([nonce, balance, storage_root, code_hash])
        let mpt_witness = self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, proof);

        EthAccountTraceWitness { address, array_witness, mpt_witness }
    }

    fn parse_account_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthAccountTraceWitness<F>,
    ) -> EthAccountTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.parse_mpt_inclusion_fixed_key_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(array_witness.rlp_array.len())
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

    fn parse_account_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        acct_witness: Vec<EthAccountTraceWitness<F>>,
    ) -> Vec<EthAccountTrace<F>> {
        // pre-load rlc cache so later parallelization is deterministic
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);

        parallelize_phase1(thread_pool, acct_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_account_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    fn parse_storage_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        slot: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthStorageTraceWitness<F> {
        assert_eq!(32, proof.key_bytes.len());

        // check key is keccak(slot)
        let hash_query_idx = keccak.keccak_fixed_len(ctx, self.gate(), slot.clone(), None);
        let hash_bytes = &keccak.fixed_len_queries[hash_query_idx].output_assigned;

        for (hash, key) in hash_bytes.iter().zip_eq(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }

        // parse slot value
        let value_witness =
            self.rlp().decompose_rlp_field_phase0(ctx, proof.value_bytes.clone(), 32);
        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, proof);
        EthStorageTraceWitness { slot, value_witness, mpt_witness }
    }

    fn parse_storage_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthStorageTraceWitness<F>,
    ) -> EthStorageTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.parse_mpt_inclusion_fixed_key_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let value_trace =
            self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness.value_witness);
        let value_trace = value_trace.field_trace;
        debug_assert_eq!(value_trace.max_len, 32);
        EthStorageTrace { value_trace }
    }

    fn parse_storage_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        storage_witness: Vec<EthStorageTraceWitness<F>>,
    ) -> Vec<EthStorageTrace<F>> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);
        parallelize_phase1(thread_pool, storage_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_storage_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
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
        let storage_trace = self.parse_storage_proofs_phase1(thread_pool, storage_witness);

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

        let state_root = &block_witness.get_state_root().field_cells;
        let block_hash_hi_lo = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.get_number().field_cells;
        let block_num_len = block_witness.get_number().field_len;
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
            addr_bytes,
            input.storage.acct_pf,
            storage_pfs,
        );

        let ctx = thread_pool.main(FIRST_PHASE);
        // check MPT root of acct_witness is state root
        for (pf_byte, byte) in
            acct_witness.mpt_witness.root_hash_bytes.iter().zip_eq(state_root.iter())
        {
            ctx.constrain_equal(pf_byte, byte);
        }

        let slots_values = slots
            .into_iter()
            .zip(storage_witness.iter())
            .map(|(slot, witness)| {
                // get value as U256 from RLP decoding, convert to H256, then to hi-lo
                let value_bytes: ByteArray<F> = (&witness.value_witness.witness).into();
                let value_bytes = value_bytes.to_fixed(ctx, self.gate());
                let value: [_; 2] =
                    bytes_be_to_u128(ctx, self.gate(), &value_bytes.0).try_into().unwrap();
                (slot, value)
            })
            .collect_vec();
        let digest = EIP1186ResponseDigest {
            block_hash: block_hash_hi_lo.try_into().unwrap(),
            block_number,
            address,
            slots_values,
            address_is_empty: acct_witness.mpt_witness.slot_is_empty,
            slot_is_empty: storage_witness
                .iter()
                .map(|witness| witness.mpt_witness.slot_is_empty)
                .collect_vec(),
        };
        (
            EthBlockAccountStorageTraceWitness { block_witness, acct_witness, storage_witness },
            digest,
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

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthStorageInput {
    pub addr: Address,
    pub acct_pf: MPTFixedKeyInput,
    pub acct_state: Vec<Vec<u8>>,
    /// A vector of (slot, value, proof) tuples
    pub storage_pfs: Vec<(H256, U256, MPTFixedKeyInput)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

    pub fn assign_account<F: Field>(
        self,
        ctx: &mut Context<F>,
        range: &impl RangeInstructions<F>,
    ) -> AccountQuery<F> {
        let address = FixedByteArray::new(ctx, range, self.addr.as_bytes());
        let acct_pf = self.acct_pf.assign(ctx);
        AccountQuery { address, acct_pf }
    }

    pub fn assign_storage<F: Field>(
        self,
        ctx: &mut Context<F>,
        range: &impl RangeInstructions<F>,
    ) -> StorageQuery<F> {
        assert_eq!(self.storage_pfs.len(), 1);
        let (slot, _, storage_pf) = self.storage_pfs.into_iter().next().unwrap();
        let slot = FixedByteArray::new(ctx, range, slot.as_bytes());
        let storage_pf = storage_pf.assign(ctx);
        StorageQuery { slot, storage_pf }
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
pub struct AccountQuery<F: Field> {
    pub address: FixedByteArray<F>, // 20 bytes
    pub acct_pf: MPTFixedKeyProof<F>,
}

#[derive(Clone, Debug)]
pub struct StorageQuery<F: Field> {
    pub slot: FixedByteArray<F>, // 20 bytes
    pub storage_pf: MPTFixedKeyProof<F>,
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
pub struct EthBlockStorageCircuit {
    pub inputs: EthBlockStorageInput, // public and private inputs
    pub network: Network,
}

impl EthBlockStorageCircuit {
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
        Self { inputs, network }
    }

    // MAYBE UNUSED
    // blockHash, blockNumber, address, (slot, value)s
    // with H256 encoded as hi-lo (u128, u128)
    pub fn instance<F: Field>(&self) -> Vec<F> {
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

impl EthPreCircuit for EthBlockStorageCircuit {
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
        let input = self.inputs.assign(ctx);
        let (witness, digest) = chip.parse_eip1186_proofs_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            self.network,
        );
        let EIP1186ResponseDigest {
            block_hash,
            block_number,
            address,
            slots_values,
            address_is_empty,
            slot_is_empty,
        } = digest;
        let assigned_instances = block_hash
            .into_iter()
            .chain([block_number, address])
            .chain(
                slots_values
                    .into_iter()
                    .flat_map(|(slot, value)| slot.into_iter().chain(value.into_iter())),
            )
            .collect_vec();
        // For now this circuit is going to constrain that all slots are occupied. We can also create a circuit that exposes the bitmap of slot_is_empty
        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            range.gate.assert_is_const(ctx, &address_is_empty, &Fr::zero());
            for slot_is_empty in slot_is_empty {
                range.gate.assert_is_const(ctx, &slot_is_empty, &Fr::zero());
            }
        }

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
                let _trace = chip.parse_eip1186_proofs_from_block_phase1(builder, witness);
            },
        )
    }
}
