use super::*;

/// Tests the hash root calculation
pub struct SSZBasicTypeTestCircuit<F> {
    pub hash_root: Vec<u8>,
    pub int_bit_size: usize,
    pub value: u64,
    _marker: PhantomData<F>,
}

impl<F> SSZBasicTypeTestCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_input(hash_root: Vec<u8>, int_bit_size: usize, value: u64) -> Self {
        Self { hash_root, int_bit_size, value, _marker: PhantomData }
    }
}

impl<F: Field> RlcCircuitInstructions<F> for SSZBasicTypeTestCircuit<F> {
    type FirstPhasePayload = ();
    fn generate_witnesses_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let sha = Sha256Chip::new(range);
        let ctx = builder.base.main(0);
        let ssz = SszChip::new(None, &range, sha);
        let hash_root = assign_vec(ctx, self.hash_root.clone(), 32);
        let basic_type = SszBasicType::new_from_int(ctx, &range, self.value, self.int_bit_size);
        let calc_root = ssz.basic_type_hash_tree_root(ctx, &basic_type);
        for (hash_byte, calc_byte) in hash_root.into_iter().zip(calc_root.into_iter()).collect_vec()
        {
            let diff = range.gate.sub(ctx, hash_byte, calc_byte);
            range.gate.assert_is_const(ctx, &diff, &F::ZERO);
        }
    }
    fn generate_witnesses_phase1(
        _builder: &mut RlcCircuitBuilder<F>,
        _range: &RangeChip<F>,
        _rlc: &RlcChip<F>,
        _payload: Self::FirstPhasePayload,
    ) {
    }
}

pub struct SSZVectorTestCircuit<F> {
    pub hash_root: Vec<u8>,
    pub int_bit_size: usize,
    pub value: Vec<u64>,
    _marker: PhantomData<F>,
}

impl<F> SSZVectorTestCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_input(hash_root: Vec<u8>, int_bit_size: usize, value: Vec<u64>) -> Self {
        Self { hash_root, int_bit_size, value, _marker: PhantomData }
    }
}

impl<F: Field> RlcCircuitInstructions<F> for SSZVectorTestCircuit<F> {
    type FirstPhasePayload = ();
    fn generate_witnesses_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let sha = Sha256Chip::new(range);
        let ctx = builder.base.main(0);
        let ssz = SszChip::new(None, &range, sha);
        let hash_root = assign_vec(ctx, self.hash_root.clone(), 32);
        let basic_type =
            SszBasicTypeVector::new_from_ints(ctx, &range, self.value.clone(), self.int_bit_size);
        let calc_root = ssz.basic_type_vector_hash_tree_root(ctx, &basic_type);
        for (hash_byte, calc_byte) in hash_root.into_iter().zip(calc_root.into_iter()).collect_vec()
        {
            println!("CALC: {:?}", calc_byte);
            println!("HASH: {:?}", hash_byte);
            ctx.constrain_equal(&hash_byte, &calc_byte);
        }
    }
    fn generate_witnesses_phase1(
        _builder: &mut RlcCircuitBuilder<F>,
        _range: &RangeChip<F>,
        _rlc: &RlcChip<F>,
        _payload: Self::FirstPhasePayload,
    ) {
    }
}

pub struct SSZListTestCircuit<F> {
    pub hash_root: Vec<u8>,
    pub int_bit_size: usize,
    pub value: Vec<u64>,
    pub len: usize,
    pub max_len: usize,
    _marker: PhantomData<F>,
}

impl<F> SSZListTestCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_input(
        hash_root: Vec<u8>,
        int_bit_size: usize,
        value: Vec<u64>,
        len: usize,
        max_len: usize,
    ) -> Self {
        Self { hash_root, int_bit_size, value, len, max_len, _marker: PhantomData }
    }
}

impl<F: Field> RlcCircuitInstructions<F> for SSZListTestCircuit<F> {
    type FirstPhasePayload = ();
    fn generate_witnesses_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let sha = Sha256Chip::new(range);
        let ctx = builder.base.main(0);
        let ssz = SszChip::new(None, &range, sha);
        let hash_root = assign_vec(ctx, self.hash_root.clone(), 32);
        let mut value = self.value.clone();
        value.resize(self.max_len, 0);
        let basic_type =
            SszBasicTypeList::new_from_ints(ctx, &range, value, self.int_bit_size, self.len);
        let calc_root = ssz.basic_type_list_hash_tree_root(ctx, &basic_type);
        for (hash_byte, calc_byte) in hash_root.into_iter().zip(calc_root.into_iter()).collect_vec()
        {
            let diff = ssz.gate().sub(ctx, hash_byte, calc_byte);
            ssz.gate().assert_is_const(ctx, &diff, &F::ZERO);
        }
    }
    fn generate_witnesses_phase1(
        _builder: &mut RlcCircuitBuilder<F>,
        _range: &RangeChip<F>,
        _rlc: &RlcChip<F>,
        _payload: Self::FirstPhasePayload,
    ) {
    }
}

pub struct SSZAssignedListTestCircuit<F> {
    pub hash_root: Vec<u8>,
    pub int_bit_size: usize,
    pub value: Vec<u64>,
    pub len: usize,
    pub max_len: usize,
    _marker: PhantomData<F>,
}

impl<F> SSZAssignedListTestCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_input(
        hash_root: Vec<u8>,
        int_bit_size: usize,
        value: Vec<u64>,
        len: usize,
        max_len: usize,
    ) -> Self {
        Self { hash_root, int_bit_size, value, len, max_len, _marker: PhantomData }
    }
}

impl<F: Field> RlcCircuitInstructions<F> for SSZAssignedListTestCircuit<F> {
    type FirstPhasePayload = ();
    fn generate_witnesses_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let sha = Sha256Chip::new(range);
        let ctx = builder.base.main(0);
        let ssz = SszChip::new(None, &range, sha);
        let hash_root = assign_vec(ctx, self.hash_root.clone(), 32);
        let mut value = self.value.clone();
        value.resize(self.max_len, 0);
        let newvalue = value
            .into_iter()
            .map(|v| SszBasicType::new_from_int(ctx, &range, v, self.int_bit_size))
            .collect_vec();
        let len = ctx.load_witness(F::from(self.len as u64));
        let basic_type = SszBasicTypeList::new(ctx, &range, newvalue, self.int_bit_size, len);
        let calc_root = ssz.basic_type_list_hash_tree_root(ctx, &basic_type);
        for (hash_byte, calc_byte) in hash_root.into_iter().zip(calc_root.into_iter()).collect_vec()
        {
            let diff = ssz.gate().sub(ctx, hash_byte, calc_byte);
            ssz.gate().assert_is_const(ctx, &diff, &F::ZERO);
        }
    }
    fn generate_witnesses_phase1(
        _builder: &mut RlcCircuitBuilder<F>,
        _range: &RangeChip<F>,
        _rlc: &RlcChip<F>,
        _payload: Self::FirstPhasePayload,
    ) {
    }
}
