use std::{cmp::max, marker::PhantomData};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use eth_types::Field;

use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    utils::fe_to_biguint,
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
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

use crate::{
    keccak::KeccakChip,
    rlp::rlc::RlcTrace,
    rlp::rlp::{max_rlp_len_len, RlpArrayChip, RlpArrayTrace}
};

#[derive(Clone, Debug)]
pub struct LeafTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    key_path: RlcTrace<F>,
    value: RlcTrace<F>,
    leaf_hash: RlcTrace<F>,
    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ExtensionTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    key_path: RlcTrace<F>,
    node_ref: RlcTrace<F>,
    ext_hash: RlcTrace<F>,
    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct BranchTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    node_refs: Vec<RlcTrace<F>>,
    branch_hash: RlcTrace<F>,
    prefix: AssignedValue<F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedValue<F>>,
    field_len_traces: Vec<RlcTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct MPTChip<F: Field> {
    rlp: RlpArrayChip<F>,
    keccak: KeccakChip<F>,
}

impl<F: Field> MPTChip<F> {
    pub fn configure(
	meta: &mut ConstraintSystem<F>,
	num_basic_chips: usize,
        num_chips_fixed: usize,
        challenge_id: String,
        context_id: String,
        range_strategy: RangeStrategy,
        num_advice: &[usize],
        mut num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
    ) -> Self {
	let rlp = RlpArrayChip::configure(
            meta,
            num_basic_chips,
            num_chips_fixed,
            challenge_id.clone(),
            context_id,
            range_strategy,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
        );
        let params_str = std::fs::read_to_string("configs/keccak.config").unwrap();
        let params: crate::keccak::KeccakCircuitParams =
            serde_json::from_str(params_str.as_str()).unwrap();
        println!("params adv {:?} fix {:?}", params.num_advice, params.num_fixed);
        let keccak = KeccakChip::configure(
            meta,
            "keccak".to_string(),
            1088,
            256,
            params.num_advice,
            params.num_xor,
            params.num_xorandn,
            params.num_fixed,
        );
        Self { rlp, keccak }
    }

    pub fn parse_leaf(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	leaf_bytes: &Vec<AssignedValue<F>>,
	max_key_bytes: usize,
	max_value_bytes: usize,
    ) -> Result<LeafTrace<F>, Error> {
	let max_encoded_path_bytes = max_key_bytes + 1;
	let max_encoded_path_rlp_bytes =
	    1 + max_rlp_len_len(max_encoded_path_bytes) + max_encoded_path_bytes;
	let max_value_rlp_bytes = 1 + max_rlp_len_len(max_value_bytes) + max_value_bytes;
	let max_field_bytes = vec![max_encoded_path_rlp_bytes, max_value_rlp_bytes];
	let max_leaf_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	assert!(leaf_bytes.len() == max_leaf_bytes);
		
	let rlp_trace = self.rlp.decompose_rlp_array(
	    ctx, range, leaf_bytes, max_field_bytes, max_leaf_bytes, 2
	)?;

	let hash_bytes = self.keccak.keccak_bytes_var_len(
	    ctx, range, leaf_bytes, rlp_trace.array_trace.rlc_len.clone(), 0usize, max_leaf_bytes,
	)?;
        let hash_len = range.gate.assign_region_smart(
            ctx, vec![Constant(F::from(32))], vec![], vec![], vec![],
        )?;
        let leaf_hash =
            self.rlp.rlc.compute_rlc(ctx, range, &hash_bytes, hash_len[0].clone(), 32)?;
	
	let leaf_trace = LeafTrace {
	    rlp_trace: rlp_trace.array_trace.clone(),
	    key_path: rlp_trace.field_traces[0].clone(),
	    value: rlp_trace.field_traces[1].clone(),	    
	    leaf_hash,
	    prefix: rlp_trace.prefix.clone(),
	    len_trace: rlp_trace.len_trace.clone(),
	    field_prefixs: rlp_trace.field_prefixs.clone(),
	    field_len_traces: rlp_trace.field_len_traces.clone()
	};
	Ok(leaf_trace)
    }

    pub fn parse_ext(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	ext_bytes: &Vec<AssignedValue<F>>,
	max_key_bytes: usize,
    ) -> Result<ExtensionTrace<F>, Error> {
	let max_node_ref_bytes = 32;
	let max_encoded_path_bytes = max_key_bytes + 1;
	let max_encoded_path_rlp_bytes =
	    1 + max_rlp_len_len(max_encoded_path_bytes) + max_encoded_path_bytes;
	let max_node_ref_rlp_bytes = 1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
	let max_field_bytes = vec![max_encoded_path_rlp_bytes, max_node_ref_rlp_bytes];
	let max_ext_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	assert!(ext_bytes.len() == max_ext_bytes);
		
	let rlp_trace = self.rlp.decompose_rlp_array(
	    ctx, range, ext_bytes, max_field_bytes, max_ext_bytes, 2
	)?;

	let hash_bytes = self.keccak.keccak_bytes_var_len(
	    ctx, range, ext_bytes, rlp_trace.array_trace.rlc_len.clone(), 0usize, max_ext_bytes,
	)?;
        let hash_len = range.gate.assign_region_smart(
            ctx, vec![Constant(F::from(32))], vec![], vec![], vec![],
        )?;
        let ext_hash =
            self.rlp.rlc.compute_rlc(ctx, range, &hash_bytes, hash_len[0].clone(), 32)?;
	
	let ext_trace = ExtensionTrace {
	    rlp_trace: rlp_trace.array_trace.clone(),
	    key_path: rlp_trace.field_traces[0].clone(),
	    node_ref: rlp_trace.field_traces[1].clone(),	    
	    ext_hash,
	    prefix: rlp_trace.prefix.clone(),
	    len_trace: rlp_trace.len_trace.clone(),
	    field_prefixs: rlp_trace.field_prefixs.clone(),
	    field_len_traces: rlp_trace.field_len_traces.clone()
	};
	Ok(ext_trace)
    }

    pub fn parse_nonterminal_branch(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	branch_bytes: &Vec<AssignedValue<F>>,
    ) -> Result<BranchTrace<F>, Error> {
	let max_node_ref_bytes = 32;
	let max_node_ref_rlp_bytes =
	    1 + max_rlp_len_len(max_node_ref_bytes) + max_node_ref_bytes;
	let mut max_field_bytes = vec![max_node_ref_rlp_bytes; 16];
	max_field_bytes.push(2);
	let max_branch_bytes: usize = 1 + max_rlp_len_len(max_field_bytes.iter().sum())
	    + max_field_bytes.iter().sum::<usize>();
	assert!(branch_bytes.len() == max_branch_bytes);

	let rlp_trace = self.rlp.decompose_rlp_array(
	    ctx, range, branch_bytes, max_field_bytes, max_branch_bytes, 17
	)?;

	let hash_bytes = self.keccak.keccak_bytes_var_len(
	    ctx, range, branch_bytes, rlp_trace.array_trace.rlc_len.clone(), 0usize, max_branch_bytes,
	)?;
        let hash_len = range.gate.assign_region_smart(
            ctx, vec![Constant(F::from(32))], vec![], vec![], vec![],
        )?;
        let branch_hash =
            self.rlp.rlc.compute_rlc(ctx, range, &hash_bytes, hash_len[0].clone(), 32)?;
	
	let branch_trace = BranchTrace {
	    rlp_trace: rlp_trace.array_trace.clone(),
	    node_refs: rlp_trace.field_traces.clone(),
	    branch_hash,
	    prefix: rlp_trace.prefix.clone(),
	    len_trace: rlp_trace.len_trace.clone(),
	    field_prefixs: rlp_trace.field_prefixs.clone(),
	    field_len_traces: rlp_trace.field_len_traces.clone()	    
	};
	Ok(branch_trace)
    }
}

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };

    #[test]
    pub fn test_mock_leaf_check() {

    }
}
