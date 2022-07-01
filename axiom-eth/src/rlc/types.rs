use halo2_base::{safe_types::VarLenBytesVec, utils::ScalarField, AssignedValue, Context};

#[derive(Clone, Copy, Debug)]
/// RLC of a vector of `F` values of variable length but known maximum length
pub struct RlcTrace<F: ScalarField> {
    pub rlc_val: AssignedValue<F>, // in SecondPhase
    pub len: AssignedValue<F>,     // in FirstPhase
    pub max_len: usize,
    // We no longer store the input values as they should be exposed elsewhere
    // pub values: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> RlcTrace<F> {
    pub fn new(rlc_val: AssignedValue<F>, len: AssignedValue<F>, max_len: usize) -> Self {
        Self { rlc_val, len, max_len }
    }

    pub fn from_fixed(ctx: &mut Context<F>, trace: RlcFixedTrace<F>) -> Self {
        let len = ctx.load_constant(F::from(trace.len as u64));
        Self { rlc_val: trace.rlc_val, len, max_len: trace.len }
    }
}

#[derive(Clone, Copy, Debug)]
/// RLC of a trace of known fixed length
pub struct RlcFixedTrace<F: ScalarField> {
    pub rlc_val: AssignedValue<F>, // SecondPhase
    // pub values: Vec<AssignedValue<'v, F>>, // FirstPhase
    pub len: usize,
}

// to deal with selecting / comparing RLC of variable length strings

#[derive(Clone, Copy, Debug)]
pub struct RlcVar<F: ScalarField> {
    pub rlc_val: AssignedValue<F>,
    pub len: AssignedValue<F>,
}

impl<F: ScalarField> From<RlcTrace<F>> for RlcVar<F> {
    fn from(trace: RlcTrace<F>) -> Self {
        RlcVar { rlc_val: trace.rlc_val, len: trace.len }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RlcVarPtr<'a, F: ScalarField> {
    pub rlc_val: &'a AssignedValue<F>,
    pub len: &'a AssignedValue<F>,
}

impl<'a, F: ScalarField> From<&'a RlcTrace<F>> for RlcVarPtr<'a, F> {
    fn from(trace: &'a RlcTrace<F>) -> Self {
        RlcVarPtr { rlc_val: &trace.rlc_val, len: &trace.len }
    }
}

impl<'a, F: ScalarField> From<&'a RlcVar<F>> for RlcVarPtr<'a, F> {
    fn from(trace: &'a RlcVar<F>) -> RlcVarPtr<'a, F> {
        RlcVarPtr { rlc_val: &trace.rlc_val, len: &trace.len }
    }
}

/// Length of `values` known at compile time.
/// Represents a variable length array with length given by `len`.
///
/// Construction of this struct assumes you have checked `len < values.len()`.
#[derive(Clone, Debug)]
pub struct AssignedVarLenVec<F: ScalarField> {
    pub values: Vec<AssignedValue<F>>,
    pub len: AssignedValue<F>,
}

impl<F: ScalarField> AssignedVarLenVec<F> {
    pub fn max_len(&self) -> usize {
        self.values.len()
    }
}

impl<F: ScalarField> From<VarLenBytesVec<F>> for AssignedVarLenVec<F> {
    fn from(array: VarLenBytesVec<F>) -> Self {
        let values = array.bytes().iter().map(|b| *b.as_ref()).collect();
        let len = *array.len();
        Self { values, len }
    }
}

#[derive(Clone, Debug)]
pub struct ConcatVarFixedArrayWitness<F: ScalarField> {
    pub prefix: AssignedVarLenVec<F>,
    pub suffix: Vec<AssignedValue<F>>,
    pub concat: AssignedVarLenVec<F>,
}

/// Rlc traces of the rlc concatenation used to constrain the concatenation
/// of variable length `prefix` and fixed length `suffix` arrays.
#[derive(Debug, Clone)]
pub struct ConcatVarFixedArrayTrace<F: ScalarField> {
    pub prefix_rlc: RlcTrace<F>,
    pub suffix_rlc: RlcFixedTrace<F>,
    pub concat_rlc: RlcTrace<F>,
}
