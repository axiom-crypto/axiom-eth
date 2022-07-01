use crate::Field;
use crate::{
    mpt::AssignedBytes,
    ssz::{BASIC_TYPE_BIT_SIZES, NUM_BASIC_TYPES},
    utils::assign_vec,
};
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context,
};
use itertools::Itertools;

use super::SszChip;

pub type Chunk<F> = AssignedBytes<F>;

// pub trait SszContainer<F: Field>: SszStruct<F> {
//     /// Verifies inclusion of another SszStruct within a SszContainer.
//     /// Include own root so that computation isn't wasted on recomputing the root
//     fn verify_inclusion(
//         &self,
//         ctx: &mut Context<F>,
//         ssz: &SszChip<F>,
//         sha: &mut Sha256Chip<F>,
//         root: Chunk<F>,
//         proof: SSZInputAssigned<F>,
//         field_num: AssignedValue<F>,
//         max_fields: usize,
//         comp: &dyn SszStruct<F>,
//     ) -> SSZInputAssigned<F> {
//         let inclusion_val = comp.hash_root(ctx, ssz, sha);
//         for i in 0..32 {
//             ctx.constrain_equal(&inclusion_val[i], &proof.val[i]);
//         }
//         for i in 0..32 {
//             ctx.constrain_equal(&root[i], &proof.root_bytes[i]);
//         }
//         ssz.verify_field_hash(ctx, sha, field_num, max_fields, proof)
//     }
// }

pub trait SszStruct<F: Field> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F>;
}

impl<F: Field> SszStruct<F> for SszBasicType<F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        ssz.basic_type_hash_tree_root(ctx, self)
    }
}

impl<F: Field> SszStruct<F> for SszBasicTypeVector<F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        ssz.basic_type_vector_hash_tree_root(ctx, self)
    }
}

impl<F: Field> SszStruct<F> for SszBasicTypeList<F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        ssz.basic_type_list_hash_tree_root(ctx, self)
    }
}

impl<F: Field> SszStruct<F> for Chunk<F> {
    fn hash_root(&self, _ctx: &mut Context<F>, _ssz: &SszChip<F>) -> Chunk<F> {
        self.to_vec()
    }
}

pub fn num_to_bytes_le(n: u64, max_len: usize) -> Vec<u8> {
    let mut temp = n;
    let mut ans = Vec::new();
    for _ in 0..max_len {
        ans.push((temp % 256) as u8);
        temp /= 256;
    }
    assert_eq!(temp, 0);
    ans
}

#[derive(Clone, Debug)]
pub struct SszBasicType<F: ScalarField> {
    /// Constrained to be length 32
    value: AssignedBytes<F>,
    int_bit_size: usize,
}

impl<F: ScalarField> SszBasicType<F> {
    pub fn new(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        value: AssignedBytes<F>,
        int_bit_size: usize,
    ) -> Self {
        let mut is_valid_int_bit_size = false;
        for i in 0..NUM_BASIC_TYPES {
            if int_bit_size == BASIC_TYPE_BIT_SIZES[i] {
                is_valid_int_bit_size = true;
            }
        }
        assert!(is_valid_int_bit_size);
        assert!(value.len() == ((int_bit_size + 7) / 8));
        if int_bit_size == 1 {
            range.check_less_than_safe(ctx, value[0], 2);
        } else {
            for i in 0..value.len() {
                range.check_less_than_safe(ctx, value[i], 256);
            }
        }
        Self { value, int_bit_size }
    }

    pub fn new_from_unassigned_vec(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        value: Vec<u8>,
        int_bit_size: usize,
    ) -> Self {
        let len = value.len();
        let assigned_bytes = assign_vec(ctx, value, len);
        Self::new(ctx, range, assigned_bytes, int_bit_size)
    }

    pub fn new_from_int(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        value: u64,
        int_bit_size: usize,
    ) -> Self {
        let byte_size = (int_bit_size + 7) / 8;
        let value_vec = num_to_bytes_le(value, byte_size);
        Self::new_from_unassigned_vec(ctx, range, value_vec, int_bit_size)
    }

    pub fn value(&self) -> &AssignedBytes<F> {
        &self.value
    }

    pub fn int_bit_size(&self) -> usize {
        self.int_bit_size
    }
}

#[derive(Clone, Debug)]
pub struct SszBasicTypeVector<F: ScalarField> {
    /// Constrained to be length 32
    values: Vec<SszBasicType<F>>,
    int_bit_size: usize,
}

impl<F: ScalarField> SszBasicTypeVector<F> {
    pub fn new(values: Vec<SszBasicType<F>>, int_bit_size: usize) -> Self {
        for i in 0..values.len() {
            assert!(int_bit_size == values[i].int_bit_size);
        }
        Self { values, int_bit_size }
    }

    pub fn new_from_bytes(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        vals: Vec<AssignedBytes<F>>,
        int_bit_size: usize,
    ) -> Self {
        let mut values = Vec::new();
        for value in vals {
            values.push(SszBasicType::new(ctx, range, value, int_bit_size));
        }
        Self { values, int_bit_size }
    }

    pub fn new_from_unassigned_vecs(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        vals: Vec<Vec<u8>>,
        int_bit_size: usize,
    ) -> Self {
        let mut values = Vec::new();
        for value in vals {
            values.push(SszBasicType::new_from_unassigned_vec(ctx, range, value, int_bit_size));
        }
        Self { values, int_bit_size }
    }

    pub fn new_from_ints(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        vals: Vec<u64>,
        int_bit_size: usize,
    ) -> Self {
        let mut values = Vec::new();
        for value in vals {
            values.push(SszBasicType::new_from_int(ctx, range, value, int_bit_size));
        }
        Self { values, int_bit_size }
    }

    pub fn values(&self) -> &Vec<SszBasicType<F>> {
        &self.values
    }

    pub fn int_bit_size(&self) -> usize {
        self.int_bit_size
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }
}

#[derive(Clone, Debug)]
pub struct SszBasicTypeList<F: ScalarField> {
    /// Constrained to be length 32
    values: Vec<SszBasicType<F>>,
    int_bit_size: usize,
    len: AssignedValue<F>,
}

impl<F: ScalarField> SszBasicTypeList<F> {
    pub fn new(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        values: Vec<SszBasicType<F>>,
        int_bit_size: usize,
        len: AssignedValue<F>,
    ) -> Self {
        range.check_less_than_safe(ctx, len, (values.len() + 1) as u64);
        for i in 0..values.len() {
            assert!(int_bit_size == values[i].int_bit_size);
        }
        // safety constraints?
        let len_minus_one = range.gate.dec(ctx, len);
        let len_minus_one_indicator = range.gate.idx_to_indicator(ctx, len_minus_one, values.len());
        let zero = ctx.load_zero();
        let one = ctx.load_constant(F::from(1));
        let mut pre_len = vec![zero; values.len()];
        pre_len[values.len() - 1] = len_minus_one_indicator[values.len() - 1];
        // creates an indicator for all slots less than len
        for i in 1..values.len() {
            pre_len[values.len() - 1 - i] = range.gate.add(
                ctx,
                pre_len[values.len() - i],
                len_minus_one_indicator[values.len() - 1 - i],
            );
        }
        let int_byte_size = (int_bit_size + 7) / 8;
        for j in 0..values.len() {
            for i in 0..int_byte_size {
                let is_zero = range.gate().is_zero(ctx, values[j].value()[i]);
                let is_valid = range.gate().or(ctx, is_zero, pre_len[j]);
                ctx.constrain_equal(&is_valid, &one);
            }
        }
        Self { values, int_bit_size, len }
    }

    pub fn new_mask(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        values: Vec<SszBasicType<F>>,
        int_bit_size: usize,
        len: AssignedValue<F>,
    ) -> Self {
        range.check_less_than_safe(ctx, len, (values.len() + 1) as u64);
        for i in 0..values.len() {
            assert!(int_bit_size == values[i].int_bit_size);
        }
        // safety constraints?
        let len_minus_one = range.gate.dec(ctx, len);
        let len_minus_one_indicator = range.gate.idx_to_indicator(ctx, len_minus_one, values.len());
        let zero = ctx.load_zero();
        let mut pre_len = vec![zero; values.len()];
        pre_len[values.len() - 1] = len_minus_one_indicator[values.len() - 1];
        // creates an indicator for all slots less than len
        for i in 1..values.len() {
            pre_len[values.len() - 1 - i] = range.gate.add(
                ctx,
                pre_len[values.len() - i],
                len_minus_one_indicator[values.len() - 1 - i],
            );
        }
        let int_byte_size = (int_bit_size + 7) / 8;
        let mut new_list = Vec::new();
        for j in 0..values.len() {
            let mut new_bytes = Vec::new();
            for i in 0..int_byte_size {
                let val = range.gate().mul(ctx, values[j].value()[i], pre_len[j]);
                new_bytes.push(val);
            }
            let new_basic = SszBasicType::new(ctx, range, new_bytes, int_bit_size);
            new_list.push(new_basic);
        }
        Self { values: new_list, int_bit_size, len }
    }

    pub fn new_from_unassigned_vecs(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        vals: Vec<Vec<u8>>,
        int_bit_size: usize,
        len: usize,
    ) -> Self {
        assert!(len <= vals.len());
        for i in len..vals.len() {
            for j in 0..32 {
                assert!(vals[i][j] == 0);
            }
        }
        let mut values = Vec::new();
        for value in vals {
            values.push(SszBasicType::new_from_unassigned_vec(ctx, range, value, int_bit_size));
        }
        let len = ctx.load_witness(F::from(len as u64));
        Self { values, int_bit_size, len }
    }

    pub fn new_from_ints(
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        vals: Vec<u64>,
        int_bit_size: usize,
        len: usize,
    ) -> Self {
        assert!(len <= vals.len());
        for i in len..vals.len() {
            assert!(vals[i] == 0);
        }
        let mut values = Vec::new();
        for value in vals {
            values.push(SszBasicType::new_from_int(ctx, range, value, int_bit_size));
        }
        let len = ctx.load_witness(F::from(len as u64));
        Self { values, int_bit_size, len }
    }

    pub fn values(&self) -> &Vec<SszBasicType<F>> {
        &self.values
    }

    pub fn int_bit_size(&self) -> usize {
        self.int_bit_size
    }

    pub fn len(&self) -> AssignedValue<F> {
        self.len
    }

    pub fn max_len(&self) -> usize {
        self.values.len()
    }
}

#[derive(Debug, Clone)]
pub struct SszVector<T> {
    pub values: Vec<T>,
}

/// Put dummy SszStruct<F> to fill to full capacity
#[derive(Debug, Clone)]
pub struct SszList<T, F: ScalarField> {
    pub values: Vec<T>,
    pub len: AssignedValue<F>,
}

impl<F: Field, T: SszStruct<F>> SszStruct<F> for SszVector<T> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        let roots = self.values.iter().map(|val| val.hash_root(ctx, ssz)).collect();
        let roots = SszBasicTypeVector::new_from_bytes(ctx, ssz.range, roots, 256);
        roots.hash_root(ctx, ssz)
    }
}

impl<F: Field, T: SszStruct<F>> SszStruct<F> for SszList<T, F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        let roots = self
            .values
            .iter()
            .map(|val| SszBasicType { value: val.hash_root(ctx, ssz), int_bit_size: 256 })
            .collect_vec();
        let roots = SszBasicTypeList::new_mask(ctx, ssz.range, roots, 256, self.len);
        roots.hash_root(ctx, ssz)
    }
}
