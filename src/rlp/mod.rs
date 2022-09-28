use std::marker::PhantomData;
use halo2_ecc::{
    gates::{
	Context, ContextParams,
	GateInstructions,
	QuantumCell::Witness,
	range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
	RangeInstructions},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error,
	    Expression, FirstPhase, Fixed, Instance, SecondPhase, Selector},
    poly::Rotation,
};

use eth_types::Field;

pub mod rlc;

