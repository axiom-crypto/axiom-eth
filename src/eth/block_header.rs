use std::cmp::max;
use std::marker::PhantomData;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use halo2_ecc::{
    gates::{
	Context, ContextParams,
	GateInstructions,
	QuantumCell::{Constant, Existing, Witness},
	range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
	RangeInstructions},
    utils::fe_to_biguint,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error,
	    Expression, FirstPhase, Fixed, Instance, SecondPhase, Selector},
    poly::Rotation,
};

use eth_types::Field;

use crate::{
    keccak::{KeccakChip},
    rlp::rlc::{RlcTrace},
    rlp::rlp::{RlpArrayChip, RlpArrayTrace},    
};


// parentHash	256 bits	32	33	264
// ommersHash	256 bits	32	33	264
// beneficiary	160 bits	20	21	168
// stateRoot	256 bits	32	33	264
// transactionsRoot	256 bits	32	33	264
// receiptsRoot	256 bits	32	33	264
// logsBloom	256 bytes	256	259	2072
// difficulty	big int scalar	variable	8	64
// number	big int scalar	variable	<= 4	<= 32
// gasLimit	big int scalar	variable	5	40
// gasUsed	big int scalar	variable	<= 5	<= 40
// timestamp	big int scalar	variable	5	40
// extraData	up to 256 bits	variable, <= 32	<= 33	<= 264
// mixHash	256 bits	32	33	264
// nonce	64 bits	8	9	72
// basefee (post-1559)	big int scalar	variable	<= 6	<= 48
#[derive(Clone, Debug)]
pub struct EthBlockHeaderTrace<F: Field> {
    rlp_trace: RlcTrace<F>,
    parent_hash: RlcTrace<F>,
    ommers_hash: RlcTrace<F>,
    beneficiary: RlcTrace<F>,
    state_root: RlcTrace<F>,
    transactions_root: RlcTrace<F>,
    receipts_root: RlcTrace<F>,
    logs_bloom: RlcTrace<F>,
    difficulty: RlcTrace<F>,
    number: RlcTrace<F>,
    gas_limit: RlcTrace<F>,
    gas_used: RlcTrace<F>,
    timestamp: RlcTrace<F>,
    extra_data: RlcTrace<F>,
    mix_hash: RlcTrace<F>,
    nonce: RlcTrace<F>,
    basefee: RlcTrace<F>,

    prefix: AssignedCell<F, F>,
    len_trace: RlcTrace<F>,
    field_prefixs: Vec<AssignedCell<F, F>>,
    field_len_traces: Vec<RlcTrace<F>>,    
}

#[derive(Clone, Debug)]
pub struct EthBlockHeaderChip<F: Field> {
    rlp: RlpArrayChip<F>,
    keccak: KeccakChip<F>
}

impl<F: Field> EthBlockHeaderChip<F> {
    pub fn configure(
	meta: &mut ConstraintSystem<F>,
	range_strategy: RangeStrategy,
	num_advice: usize,
	mut num_lookup_advice: usize,
	num_fixed: usize,
	lookup_bits: usize,
    ) -> Self {
	let rlp = RlpArrayChip::configure(
	    meta,
	    range_strategy,
	    num_advice,
	    num_lookup_advice,
	    num_fixed,
	    lookup_bits
	);
	let keccak = KeccakChip::configure(meta);
	Self {
	    rlp,
	    keccak
	}
    }

    pub fn decompose_eth_block_header(
	&self,
	layouter: &mut impl Layouter<F>,
	range: &RangeConfig<F>,
	block_header: &Vec<AssignedCell<F, F>>,
    ) -> Result<EthBlockHeaderTrace<F>, Error> {
	let max_len = 1 + 2 + 553;
	let max_field_lens = vec![
	    33, 33, 21, 33, 33, 33, 259, 8, 4, 5, 5, 5, 33, 33, 9, 6
	];
	let num_fields = 16;
	let rlp_array_trace = self.rlp.decompose_rlp_array(
	    layouter, range, block_header, max_field_lens, max_len, num_fields
	)?;
	
	let block_header_trace = EthBlockHeaderTrace {
	    rlp_trace: rlp_array_trace.array_trace.clone(),
	    parent_hash: rlp_array_trace.field_traces[0].clone(),
	    ommers_hash: rlp_array_trace.field_traces[1].clone(),
	    beneficiary: rlp_array_trace.field_traces[2].clone(),
	    state_root:  rlp_array_trace.field_traces[3].clone(),
	    transactions_root: rlp_array_trace.field_traces[4].clone(),
	    receipts_root: rlp_array_trace.field_traces[5].clone(),
	    logs_bloom: rlp_array_trace.field_traces[6].clone(),
	    difficulty: rlp_array_trace.field_traces[7].clone(),
	    number: rlp_array_trace.field_traces[8].clone(),
	    gas_limit: rlp_array_trace.field_traces[9].clone(),
	    gas_used: rlp_array_trace.field_traces[10].clone(),
	    timestamp: rlp_array_trace.field_traces[11].clone(),
	    extra_data: rlp_array_trace.field_traces[12].clone(),
	    mix_hash: rlp_array_trace.field_traces[13].clone(),
	    nonce: rlp_array_trace.field_traces[14].clone(),
	    basefee: rlp_array_trace.field_traces[15].clone(),
	    
	    prefix: rlp_array_trace.prefix.clone(),
	    len_trace: rlp_array_trace.len_trace.clone(),
	    field_prefixs: rlp_array_trace.field_prefixs.clone(),
	    field_len_traces: rlp_array_trace.field_len_traces.clone(),
	};
	Ok(block_header_trace)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EthBlockHeaderTestCircuit<F> {
    inputs: Vec<u8>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for EthBlockHeaderTestCircuit<F> {
    type Config = EthBlockHeaderChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
	Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
	EthBlockHeaderChip::configure(
	    meta,
	    Vertical,
	    1,
	    0,
	    1,
	    10		    
	)
    }

    fn synthesize(
	&self,
	config: Self::Config,
	mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
	config.rlp.range.load_lookup_table(&mut layouter)?;

	let using_simple_floor_planner = true;
	let mut first_pass = true;	   
	let inputs_assigned = layouter.assign_region(
	    || "load_inputs",
	    |mut region| {
		if first_pass && using_simple_floor_planner {
		    first_pass = false;
		}
		
		let mut aux = Context::new(
		    region,
		    ContextParams {
			num_advice: config.rlp.range.gate.num_advice,
			using_simple_floor_planner,
			first_pass,
		    },
		);
		let ctx = &mut aux;
		
		let inputs_assigned = config.rlp.range.gate.assign_region_smart(
		    ctx,
		    self.inputs.iter().map(|x| Witness(Value::known(F::from(*x as u64)))).collect(),
		    vec![],
		    vec![],
		    vec![]
		)?;
		let stats = config.rlp.range.finalize(ctx)?;
		Ok(inputs_assigned)
	    }
	)?;

	let block_header_trace = config.decompose_eth_block_header(
	    &mut layouter,
	    &config.rlp.range,
	    &inputs_assigned,
	)?;
	Ok(())
    }
}
    

#[cfg(test)]
mod tests {

    use hex::FromHex;
    use std::marker::PhantomData;
    use halo2_proofs::{
	dev::{MockProver},
	halo2curves::bn256::Fr,
    };
    use crate::{
	eth::block_header::{EthBlockHeaderTestCircuit},
    };

    #[test]
    pub fn test_eth_block_header() {
	let k = 18;
	let input_bytes: Vec<u8> = Vec::from_hex("f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
	    
	let circuit = EthBlockHeaderTestCircuit::<Fr> {
	    inputs: input_bytes,
	    _marker: PhantomData
	};
	let prover_try = MockProver::run(k, &circuit, vec![]);
	let prover = prover_try.unwrap();
	prover.assert_satisfied();
	assert_eq!(prover.verify(), Ok(()));
    }
}
