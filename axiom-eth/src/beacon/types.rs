use crate::Field;
use halo2_base::{gates::range::RangeChip, utils::ScalarField, Context};

use crate::{
    mpt::AssignedBytes,
    ssz::{
        types::SszStruct,
        types::{Chunk, SszBasicType, SszBasicTypeVector},
        SszChip,
    },
};

pub type Gwei<F> = SszUint64<F>;
pub type Epoch<F> = SszUint64<F>;
/// Wrapper for SszBasicType for uint64
#[derive(Debug, Clone)]
pub struct SszUint64<F: ScalarField> {
    val: SszBasicType<F>,
}

impl<F: ScalarField> SszUint64<F> {
    pub fn from(val: SszBasicType<F>) -> Self {
        Self { val }
    }
    pub fn from_int(ctx: &mut Context<F>, range: &RangeChip<F>, val: u64) -> Self {
        let val = SszBasicType::new_from_int(ctx, range, val, 64);
        Self { val }
    }
    pub fn new(ctx: &mut Context<F>, range: &mut RangeChip<F>, value: AssignedBytes<F>) -> Self {
        assert!(value.len() == 8);
        let val = SszBasicType::new(ctx, range, value, 64);
        Self { val }
    }
    pub fn val(&self) -> &SszBasicType<F> {
        &self.val
    }
}

impl<F: Field> SszStruct<F> for SszUint64<F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        return self.val.hash_root(ctx, ssz);
    }
}

#[derive(Debug, Clone)]
pub struct Validator<F: ScalarField> {
    bls_pub_key: SszBasicTypeVector<F>,
    withdrawal_creds: SszBasicTypeVector<F>,
    effective_balance: Gwei<F>,
    slashed: SszBasicType<F>,
    activation_eligibility_epoch: Epoch<F>,
    activation_epoch: Epoch<F>,
    exit_epoch: Epoch<F>,
    withdrawable_epoch: Epoch<F>,
}

impl<F: Field> SszStruct<F> for Validator<F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        let ae_root = ssz.basic_type_hash_tree_root(ctx, &self.activation_epoch.val);
        let aee_root = ssz.basic_type_hash_tree_root(ctx, &self.activation_eligibility_epoch.val);
        let ee_root = ssz.basic_type_hash_tree_root(ctx, &self.exit_epoch.val);
        let we_root = ssz.basic_type_hash_tree_root(ctx, &self.withdrawable_epoch.val);
        let bls_root = ssz.basic_type_vector_hash_tree_root(ctx, &self.bls_pub_key);
        let wc_root = ssz.basic_type_vector_hash_tree_root(ctx, &self.withdrawal_creds);
        let s_root = ssz.basic_type_hash_tree_root(ctx, &self.slashed);
        let eb_root = ssz.basic_type_hash_tree_root(ctx, &self.effective_balance.val);
        let chunks = vec![bls_root, wc_root, eb_root, s_root, aee_root, ae_root, ee_root, we_root];
        ssz.merkleize(ctx, chunks)
    }
}

impl<F: Field> Validator<F> {
    pub fn from(
        bls_pub_key: SszBasicTypeVector<F>,
        withdrawal_creds: SszBasicTypeVector<F>,
        effective_balance: Gwei<F>,
        slashed: SszBasicType<F>,
        activation_eligibility_epoch: Epoch<F>,
        activation_epoch: Epoch<F>,
        exit_epoch: Epoch<F>,
        withdrawable_epoch: Epoch<F>,
    ) -> Self {
        assert!(bls_pub_key.int_bit_size() == 8);
        assert!(withdrawal_creds.int_bit_size() == 8);
        assert!(slashed.int_bit_size() == 1);
        assert!(bls_pub_key.values().len() == 48);
        assert!(withdrawal_creds.values().len() == 32);
        Self {
            bls_pub_key,
            withdrawal_creds,
            effective_balance,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        }
    }
    pub fn bls_pub_key(self) -> SszBasicTypeVector<F> {
        self.bls_pub_key
    }
    pub fn withdrawal_creds(self) -> SszBasicTypeVector<F> {
        self.withdrawal_creds
    }
    pub fn effective_balance(self) -> Gwei<F> {
        self.effective_balance
    }
    pub fn slashed(self) -> SszBasicType<F> {
        self.slashed
    }
    pub fn activation_eligibility_epoch(self) -> Epoch<F> {
        self.activation_eligibility_epoch
    }
    pub fn activation_epoch(self) -> Epoch<F> {
        self.activation_epoch
    }
    pub fn exit_epoch(self) -> Epoch<F> {
        self.exit_epoch
    }
    pub fn withdrawable_epoch(self) -> Epoch<F> {
        self.withdrawable_epoch
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorInfo<F: ScalarField> {
    bls_pubkey: SszBasicTypeVector<F>,
    withdrawal_creds: SszBasicTypeVector<F>,
}

impl<F: Field> SszStruct<F> for ValidatorInfo<F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> Chunk<F> {
        let bls_root = ssz.basic_type_vector_hash_tree_root(ctx, &self.bls_pubkey);
        let wc_root = ssz.basic_type_vector_hash_tree_root(ctx, &self.withdrawal_creds);
        let chunks = vec![bls_root, wc_root];
        ssz.merkleize(ctx, chunks)
    }
}

impl<F: Field> ValidatorInfo<F> {
    pub fn from(
        bls_pubkey: SszBasicTypeVector<F>,
        withdrawal_creds: SszBasicTypeVector<F>,
    ) -> Self {
        assert!(bls_pubkey.int_bit_size() == 8);
        assert!(withdrawal_creds.int_bit_size() == 8);
        assert!(bls_pubkey.values().len() == 48);
        assert!(withdrawal_creds.values().len() == 32);
        Self { bls_pubkey, withdrawal_creds }
    }
    pub fn bls_pub_key(self) -> SszBasicTypeVector<F> {
        self.bls_pubkey
    }
    pub fn withdrawal_creds(self) -> SszBasicTypeVector<F> {
        self.withdrawal_creds
    }
}
