use ethers_core::types::{H160, H256};

use ethers_core::types::Chain;
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::dev::MockProver,
    halo2_proofs::{
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk, Circuit},
    },
    safe_types::SafeTypeChip,
    utils::{
        fs::gen_srs,
        testing::{check_proof_with_instances, gen_proof_with_instances},
    },
};
use itertools::Itertools;
use std::{panic::catch_unwind, path::Path, vec};

use crate::{
    mpt::MPTChip,
    providers::{setup_provider, storage::get_block_storage_input},
    rlc::{circuit::builder::RlcCircuitBuilder, virtual_region::RlcThreadBreakPoints, FIRST_PHASE},
    solidity::{tests::utils::*, types::NestedMappingWitness, SolidityChip},
    storage::{circuit::EthStorageInput, EthStorageWitness},
    utils::eth_circuit::{create_circuit, EthCircuitImpl, EthCircuitInstructions},
    Field,
};

pub mod mapping;
pub mod mapping_storage;
pub mod nested_mappings;
pub mod prop_pos;
pub mod utils;

const MAX_NESTING: usize = 3;
