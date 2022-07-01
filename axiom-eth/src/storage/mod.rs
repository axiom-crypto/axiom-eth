use ethers_core::types::Chain;
use getset::Getters;
use halo2_base::{
    gates::{flex_gate::threads::parallelize_core, GateChip, RangeChip},
    safe_types::{SafeAddress, SafeBytes32, SafeTypeChip},
    AssignedValue, Context,
};
use itertools::Itertools;

use crate::{
    block_header::{EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderWitness},
    keccak::KeccakChip,
    mpt::{MPTChip, MPTProof, MPTProofWitness},
    rlc::{
        chip::RlcChip,
        circuit::builder::{RlcCircuitBuilder, RlcContextPair},
        types::RlcTrace,
        FIRST_PHASE,
    },
    rlp::{
        types::{RlpArrayWitness, RlpFieldWitness},
        RlpChip,
    },
    utils::{bytes_be_to_u128, uint_to_bytes_be, AssignedH256},
    Field,
};

pub mod circuit;
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
pub const NUM_ACCOUNT_STATE_FIELDS: usize = 4;
pub const ACCOUNT_STATE_FIELDS_MAX_BYTES: [usize; NUM_ACCOUNT_STATE_FIELDS] = [8, 12, 32, 32];
#[allow(dead_code)]
pub const ACCOUNT_STATE_FIELD_IS_VAR_LEN: [bool; NUM_ACCOUNT_STATE_FIELDS] =
    [true, true, false, false];
pub(crate) const ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN: usize = 90;
pub(crate) const STORAGE_PROOF_VALUE_MAX_BYTE_LEN: usize = 33;
#[allow(dead_code)]
pub(crate) const STORAGE_PROOF_KEY_MAX_BYTE_LEN: usize = 32;

/// Stores Account rlcs to be used in later functions. Is returned by `parse_account_proof_phase1`.
#[derive(Clone, Debug)]
pub struct EthAccountTrace<F: Field> {
    pub nonce_trace: RlcTrace<F>,
    pub balance_trace: RlcTrace<F>,
    pub storage_root_trace: RlcTrace<F>,
    pub code_hash_trace: RlcTrace<F>,
}

/// Stores Account information to be used in later functions. Is returned by `parse_account_proof_phase0`.
#[derive(Clone, Debug, Getters)]
pub struct EthAccountWitness<F: Field> {
    pub address: SafeAddress<F>,
    #[getset(get = "pub")]
    pub(crate) array_witness: RlpArrayWitness<F>,
    #[getset(get = "pub")]
    pub(crate) mpt_witness: MPTProofWitness<F>,
}

impl<F: Field> EthAccountWitness<F> {
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

/// Stores the rlc of a value in a storage slot. Is returned by `parse_storage_proof_phase1`.
#[derive(Clone, Debug)]
pub struct EthStorageTrace<F: Field> {
    pub value_trace: RlcTrace<F>,
}

/// Stores storage slot information as well as a proof of inclusion to be verified in parse_storage_phase1. Is returned
/// by `parse_storage_phase0`.
#[derive(Clone, Debug, Getters)]
pub struct EthStorageWitness<F: Field> {
    pub slot: SafeBytes32<F>,
    #[getset(get = "pub")]
    pub(crate) value_witness: RlpFieldWitness<F>,
    #[getset(get = "pub")]
    pub(crate) mpt_witness: MPTProofWitness<F>,
}

///  Stores the rlcs for an account in a block, and the rlcs of slots in the account. Is returned by `parse_eip1186_proofs_from_block_phase1`.
#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub acct_trace: EthAccountTrace<F>,
    pub storage_trace: Vec<EthStorageTrace<F>>,
}

///  Stores a block, an account, and multiple storage witnesses. Is returned by `parse_eip1186_proofs_from_block_phase0`.
#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageWitness<F: Field> {
    pub block_witness: EthBlockHeaderWitness<F>,
    pub acct_witness: EthAccountWitness<F>,
    pub storage_witness: Vec<EthStorageWitness<F>>,
}

/// Returns public instances from `parse_eip1186_proofs_from_block_phase0`.
#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub address: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    /// Pairs of (slot, value) where value is a left padded with 0s to fixed width 32 bytes
    pub slots_values: Vec<(AssignedH256<F>, AssignedH256<F>)>,
    pub address_is_empty: AssignedValue<F>,
    pub slot_is_empty: Vec<AssignedValue<F>>,
}

/// Chip to prove correctness of account and storage proofs
pub struct EthStorageChip<'chip, F: Field> {
    pub mpt: &'chip MPTChip<'chip, F>,
    /// The network to use for block header decoding. Must be provided if using functions that prove into block header (as opposed to state / storage root)
    pub network: Option<Chain>,
}

impl<'chip, F: Field> EthStorageChip<'chip, F> {
    pub fn new(mpt: &'chip MPTChip<'chip, F>, network: Option<Chain>) -> Self {
        Self { mpt, network }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.mpt.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.mpt.range()
    }

    pub fn rlc(&self) -> &RlcChip<F> {
        self.mpt.rlc()
    }

    pub fn rlp(&self) -> RlpChip<F> {
        self.mpt.rlp()
    }

    pub fn keccak(&self) -> &KeccakChip<F> {
        self.mpt.keccak()
    }
    /// Does inclusion/exclusion proof of `key = keccak(addr)` into an alleged MPT state trie. Alleged means the proof is with respect to an alleged stateRoot.
    /// RLP decodes the ethereumAccount.
    ///
    /// There is one global state trie, and it is updated every time a client processes a block. In it, a path is always: keccak256(ethereumAddress) and a value is always: rlp(ethereumAccount). More specifically an ethereum account is a 4 item array of [nonce,balance,storageRoot,codeHash].
    ///
    /// Does input validation of `proof` (e.g., checking witnesses are bytes).
    pub fn parse_account_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        address: SafeAddress<F>,
        proof: MPTProof<F>,
    ) -> EthAccountWitness<F> {
        assert_eq!(32, proof.key_bytes.len());

        // check key is keccak(addr)
        let hash_query = self.keccak().keccak_fixed_len(ctx, address.as_ref().to_vec());
        let hash_addr = hash_query.output_bytes.as_ref();

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
        let mpt_witness = self.mpt.parse_mpt_inclusion_phase0(ctx, proof);

        EthAccountWitness { address, array_witness, mpt_witness }
    }

    /// SecondPhase of account proof parsing.
    pub fn parse_account_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthAccountWitness<F>,
    ) -> EthAccountTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.mpt.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
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

    /// Does multiple calls to [`parse_account_proof_phase0`] in parallel.
    pub fn parse_account_proofs_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        addr_proofs: Vec<(SafeAddress<F>, MPTProof<F>)>,
    ) -> Vec<EthAccountWitness<F>> {
        parallelize_core(builder.base.pool(0), addr_proofs, |ctx, (addr, proof)| {
            self.parse_account_proof_phase0(ctx, addr, proof)
        })
    }

    /// SecondPhase of account proofs parsing.
    pub fn parse_account_proofs_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        acct_witness: Vec<EthAccountWitness<F>>,
    ) -> Vec<EthAccountTrace<F>> {
        // rlc cache is loaded globally when `builder` was constructed; no longer done here to avoid concurrency issues
        builder.parallelize_phase1(acct_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_account_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    /// Does inclusion/exclusion proof of `keccak(slot)` into an alleged MPT storage trie. Alleged means the proof is with respect to an alleged storageRoot.
    ///
    /// storageRoot: A 256-bit hash of the root node of a Merkle Patricia tree that encodes the storage contents of the account (a mapping between 256-bit integer values), encoded into the trie as a mapping from the Keccak 256-bit hash of the 256-bit integer keys to the RLP-encoded 256-bit integer values. The hash is formally denoted σ[a]_s.
    ///
    /// Will do input validation on `proof` (e.g., checking witnesses are bytes).
    pub fn parse_storage_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        slot: SafeBytes32<F>,
        proof: MPTProof<F>,
    ) -> EthStorageWitness<F> {
        assert_eq!(32, proof.key_bytes.len());

        // check key is keccak(slot)
        let hash_query = self.keccak().keccak_fixed_len(ctx, slot.as_ref().to_vec());
        let hash_bytes = hash_query.output_bytes.as_ref();

        for (hash, key) in hash_bytes.iter().zip_eq(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }

        // parse slot value
        let value_witness =
            self.rlp().decompose_rlp_field_phase0(ctx, proof.value_bytes.clone(), 32);
        // check MPT inclusion
        let mpt_witness = self.mpt.parse_mpt_inclusion_phase0(ctx, proof);
        EthStorageWitness { slot, value_witness, mpt_witness }
    }

    /// SecondPhase of storage proof parsing.
    pub fn parse_storage_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthStorageWitness<F>,
    ) -> EthStorageTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.mpt.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let value_trace =
            self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness.value_witness);
        let value_trace = value_trace.field_trace;
        debug_assert_eq!(value_trace.max_len, 32);
        EthStorageTrace { value_trace }
    }

    /// Does multiple calls to [`parse_storage_proof_phase0`] in parallel.
    pub fn parse_storage_proofs_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        slot_proofs: Vec<(SafeBytes32<F>, MPTProof<F>)>,
    ) -> Vec<EthStorageWitness<F>> {
        parallelize_core(builder.base.pool(0), slot_proofs, |ctx, (slot, proof)| {
            self.parse_storage_proof_phase0(ctx, slot, proof)
        })
    }

    /// SecondPhase of account proofs parsing.
    pub fn parse_storage_proofs_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        storage_witness: Vec<EthStorageWitness<F>>,
    ) -> Vec<EthStorageTrace<F>> {
        // rlc cache is loaded globally when `builder` was constructed; no longer done here to avoid concurrency issues
        builder.parallelize_phase1(storage_witness, |(ctx_gate, ctx_rlc), witness| {
            self.parse_storage_proof_phase1((ctx_gate, ctx_rlc), witness)
        })
    }

    /// Does inclusion/exclusion proof of `key = keccak(addr)` into an alleged MPT state trie. Alleged means the proof is with respect to an alleged stateRoot.
    ///
    /// RLP decodes the ethereumAccount, which in particular gives the storageRoot.
    ///
    /// Does (multiple) inclusion/exclusion proof of `keccak(slot)` into the MPT storage trie with root storageRoot.
    pub fn parse_eip1186_proofs_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        addr: SafeAddress<F>,
        acct_pf: MPTProof<F>,
        storage_pfs: Vec<(SafeBytes32<F>, MPTProof<F>)>, // (slot_bytes, storage_proof)
    ) -> (EthAccountWitness<F>, Vec<EthStorageWitness<F>>) {
        // TODO: spawn separate thread for account proof; just need to get storage_root first somehow
        let ctx = builder.base.main(FIRST_PHASE);
        let acct_trace = self.parse_account_proof_phase0(ctx, addr, acct_pf);
        // ctx dropped
        let storage_root = &acct_trace.get_storage_root().field_cells;
        let storage_trace =
            parallelize_core(builder.base.pool(0), storage_pfs, |ctx, (slot, storage_pf)| {
                let witness = self.parse_storage_proof_phase0(ctx, slot, storage_pf);
                // check MPT root is storage_root
                for (pf_byte, byte) in
                    witness.mpt_witness.root_hash_bytes.iter().zip_eq(storage_root.iter())
                {
                    ctx.constrain_equal(pf_byte, byte);
                }
                witness
            });
        (acct_trace, storage_trace)
    }

    /// SecondPhase of `parse_eip1186_proofs_phase0`
    pub fn parse_eip1186_proofs_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        (acct_witness, storage_witness): (EthAccountWitness<F>, Vec<EthStorageWitness<F>>),
    ) -> (EthAccountTrace<F>, Vec<EthStorageTrace<F>>) {
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        let acct_trace = self.parse_account_proof_phase1((ctx_gate, ctx_rlc), acct_witness);
        let storage_trace = self.parse_storage_proofs_phase1(builder, storage_witness);

        (acct_trace, storage_trace)
    }

    /// Proves (multiple) storage proofs into storageRoot, prove account proof of storageRoot into stateRoot, and proves stateRoot is an RLP decoded block header.
    /// Computes the block hash by hashing the RLP encoded block header.
    /// In other words, proves block, account, storage with respect to an alleged block hash.
    // inputs have H256 represented in (hi,lo) format as two u128s
    // block number and slot values can be derived from the final trace output
    pub fn parse_eip1186_proofs_from_block_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        input: EthBlockStorageInputAssigned<F>,
    ) -> (EthBlockAccountStorageWitness<F>, EIP1186ResponseDigest<F>) {
        let ctx = builder.base.main(FIRST_PHASE);
        let address = input.storage.address;
        let block_header = input.block_header;
        let block_witness = {
            let block_header_chip =
                EthBlockHeaderChip::new_from_network(self.rlp(), self.network.unwrap());
            block_header_chip.decompose_block_header_phase0(ctx, self.keccak(), &block_header)
        };

        let state_root = &block_witness.get_state_root().field_cells;
        let block_hash_hi_lo = block_witness.get_block_hash_hi_lo();

        // compute block number from big-endian bytes
        let block_number = block_witness.get_number_value(ctx, self.gate());

        // verify account + storage proof
        let addr_bytes = uint_to_bytes_be(ctx, self.range(), &address, 20);
        let (slots, storage_pfs): (Vec<_>, Vec<_>) = input
            .storage
            .storage_pfs
            .into_iter()
            .map(|(slot, storage_pf)| {
                let slot_bytes =
                    slot.iter().map(|u128| uint_to_bytes_be(ctx, self.range(), u128, 16)).concat();
                (slot, (slot_bytes.try_into().unwrap(), storage_pf))
            })
            .unzip();
        // drop ctx
        let (acct_witness, storage_witness) = self.parse_eip1186_proofs_phase0(
            builder,
            addr_bytes.try_into().unwrap(),
            input.storage.acct_pf,
            storage_pfs,
        );

        let ctx = builder.base.main(FIRST_PHASE);
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
                let value_bytes = witness.value_witness.field_cells.clone();
                let value_bytes_len = witness.value_witness.field_len;
                let var_bytes =
                    SafeTypeChip::unsafe_to_var_len_bytes_vec(value_bytes, value_bytes_len, 32);
                let value_bytes = var_bytes.left_pad_to_fixed(ctx, self.gate());
                let value: [_; 2] =
                    bytes_be_to_u128(ctx, self.gate(), value_bytes.bytes()).try_into().unwrap();
                (slot, value)
            })
            .collect_vec();
        let digest = EIP1186ResponseDigest {
            block_hash: block_hash_hi_lo,
            block_number,
            address,
            slots_values,
            address_is_empty: acct_witness.mpt_witness.slot_is_empty,
            slot_is_empty: storage_witness
                .iter()
                .map(|witness| witness.mpt_witness.slot_is_empty)
                .collect_vec(),
        };
        (EthBlockAccountStorageWitness { block_witness, acct_witness, storage_witness }, digest)
    }

    pub fn parse_eip1186_proofs_from_block_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        witness: EthBlockAccountStorageWitness<F>,
    ) -> EthBlockAccountStorageTrace<F> {
        let block_trace = {
            let block_header_chip =
                EthBlockHeaderChip::new_from_network(self.rlp(), self.network.unwrap());
            block_header_chip
                .decompose_block_header_phase1(builder.rlc_ctx_pair(), witness.block_witness)
        };
        let (acct_trace, storage_trace) = self
            .parse_eip1186_proofs_phase1(builder, (witness.acct_witness, witness.storage_witness));
        EthBlockAccountStorageTrace { block_trace, acct_trace, storage_trace }
    }
}

/// Account and storage proof inputs in compressed form
#[derive(Clone, Debug)]
pub struct EthStorageInputAssigned<F: Field> {
    pub address: AssignedValue<F>, // U160
    pub acct_pf: MPTProof<F>,
    pub storage_pfs: Vec<(AssignedH256<F>, MPTProof<F>)>, // (slot, proof) where slot is H256 as (u128, u128)
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageInputAssigned<F: Field> {
    // block_hash: AssignedH256<F>, // H256 as (u128, u128)
    /// The RLP encoded block header for the block that alleged contains the stateRoot from `storage`.
    pub block_header: Vec<AssignedValue<F>>,
    /// Account proof and (multiple) storage proofs, with respect to an alleged stateRoot.
    pub storage: EthStorageInputAssigned<F>,
}
