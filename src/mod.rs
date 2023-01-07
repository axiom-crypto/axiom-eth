// Currently being refactored, not in use
#[cfg(feature = "input_gen")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::{biguint_to_fe, fe_to_biguint, value_to_option},
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_curves::FieldExt;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Challenge, Circuit, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed,
        Instance, SecondPhase, Selector,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use hex::FromHex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{cast::ToPrimitive, Num};
use rand_core::block;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::{cmp::max, fs};

use crate::{
    keccak::{print_bytes, KeccakChip},
    mpt::mpt::{AssignedBytes, MPTChip, MPTFixedKeyProof},
    rlp::rlc::{RlcFixedTrace, RlcTrace},
    rlp::rlp::{RlpArrayChip, RlpArrayTrace},
};

pub mod storage;

use block_header::{bytes_be_to_u128, decompose_eth_block_header, EthBlockHeaderTrace};
