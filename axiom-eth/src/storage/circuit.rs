use ethers_core::types::{Address, Block, Chain, H256, U256};
#[cfg(feature = "providers")]
use ethers_providers::{JsonRpcClient, Provider};
use halo2_base::{gates::GateInstructions, Context};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zkevm_hashes::util::eth_types::ToBigEndian;

use crate::{
    block_header::get_block_header_rlp_max_lens,
    mpt::{MPTChip, MPTInput},
    rlc::{circuit::builder::RlcCircuitBuilder, FIRST_PHASE},
    utils::{
        assign_vec, encode_addr_to_field, encode_h256_to_hilo, eth_circuit::EthCircuitInstructions,
    },
    Field,
};

use super::{
    EIP1186ResponseDigest, EthBlockAccountStorageWitness, EthBlockStorageInputAssigned,
    EthStorageChip, EthStorageInputAssigned,
};

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct EthStorageInput {
    pub addr: Address,
    pub acct_pf: MPTInput,
    pub acct_state: Vec<Vec<u8>>,
    /// A vector of (slot, value, proof) tuples
    pub storage_pfs: Vec<(U256, U256, MPTInput)>,
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
                let slot = encode_h256_to_hilo(&H256(slot.to_be_bytes())).hi_lo();
                let slot = slot.map(|slot| ctx.load_witness(slot));
                let pf = pf.assign(ctx);
                (slot, pf)
            })
            .collect();
        EthStorageInputAssigned { address, acct_pf, storage_pfs }
    }
}

impl EthBlockStorageInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
        network: Chain,
    ) -> EthBlockStorageInputAssigned<F> {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let storage = self.storage.assign(ctx);
        let max_len = get_block_header_rlp_max_lens(network).0;
        let block_header = assign_vec(ctx, self.block_header, max_len);
        EthBlockStorageInputAssigned { block_header, storage }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageCircuit<F> {
    pub inputs: EthBlockStorageInput, // public and private inputs
    pub network: Chain,
    _marker: PhantomData<F>,
}

impl<F> EthBlockStorageCircuit<F> {
    pub fn new(inputs: EthBlockStorageInput, network: Chain) -> Self {
        Self { inputs, network, _marker: PhantomData }
    }

    #[cfg(feature = "providers")]
    pub fn from_provider<P: JsonRpcClient>(
        provider: &Provider<P>,
        block_number: u32,
        address: Address,
        slots: Vec<H256>,
        acct_pf_max_depth: usize,
        storage_pf_max_depth: usize,
        network: Chain,
    ) -> Self {
        use crate::providers::storage::get_block_storage_input;

        let inputs = get_block_storage_input(
            provider,
            block_number,
            address,
            slots,
            acct_pf_max_depth,
            storage_pf_max_depth,
        );
        Self::new(inputs, network)
    }
}

impl<F: Field> EthCircuitInstructions<F> for EthBlockStorageCircuit<F> {
    type FirstPhasePayload = (EthBlockAccountStorageWitness<F>, Chain);

    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let chip = EthStorageChip::new(mpt, Some(self.network));
        // ================= FIRST PHASE ================
        let ctx = builder.base.main(FIRST_PHASE);
        let input = self.inputs.clone().assign(ctx, self.network);
        let (witness, digest) = chip.parse_eip1186_proofs_from_block_phase0(builder, input);
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
            .chain(slots_values.into_iter().flat_map(|(slot, value)| slot.into_iter().chain(value)))
            .collect_vec();
        assert_eq!(builder.base.assigned_instances.len(), 1);
        builder.base.assigned_instances[0] = assigned_instances;
        // For now this circuit is going to constrain that all slots are occupied. We can also create a circuit that exposes the bitmap of slot_is_empty
        {
            let ctx = builder.base.main(FIRST_PHASE);
            mpt.gate().assert_is_const(ctx, &address_is_empty, &F::ZERO);
            for slot_is_empty in slot_is_empty {
                mpt.gate().assert_is_const(ctx, &slot_is_empty, &F::ZERO);
            }
        }
        (witness, self.network)
    }

    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        (witness, network): Self::FirstPhasePayload,
    ) {
        let chip = EthStorageChip::new(mpt, Some(network));
        let _trace = chip.parse_eip1186_proofs_from_block_phase1(builder, witness);
    }
}
