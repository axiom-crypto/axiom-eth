use std::marker::PhantomData;

use crate::rlc::{
    chip::RlcChip,
    circuit::{builder::RlcCircuitBuilder, instructions::RlcCircuitInstructions},
    utils::executor::{RlcCircuit, RlcExecutor},
};

use halo2_base::{
    gates::{circuit::CircuitBuilderStage, GateInstructions, RangeChip, RangeInstructions},
    utils::ScalarField,
    QuantumCell::Constant,
};

use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use hex::FromHex;

use super::{max_rlp_encoding_len, types::RlpArrayWitness, RlpChip};

mod combo;
mod list;
mod string;

const DEGREE: u32 = 10;
