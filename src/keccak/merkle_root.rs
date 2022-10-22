use std::{
    fs::File,
    io::{Read, Write},
};

use crate::eth::eth::hexes_to_u128;

use super::{KeccakChip, KeccakCircuitParams};
use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    utils::{biguint_to_fe, decompose_option, fe_to_biguint, value_to_option},
    AssignedValue, Context, ContextParams,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_curves::bn256::Fr;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::FieldExt,
    plonk::{
        create_proof, Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed,
        Instance, Selector, TableColumn,
    },
    poly::{
        kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
        Rotation,
    },
    transcript::TranscriptWriterBuffer,
};
use hex::encode;
use itertools::Itertools;
use num_bigint::BigUint;
use plonk_verifier::{
    loader::native::NativeLoader,
    system::halo2::{
        aggregation::{
            create_snark_shplonk, gen_pk, gen_srs, write_instances, PoseidonTranscript, Snark,
            TargetCircuit, KZG_QUERY_INSTANCE,
        },
        compile,
        transcript::halo2::ChallengeScalar,
        Config,
    },
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Clone, Debug)]
pub struct MerkleChip<F: FieldExt> {
    pub keccak: KeccakChip<F>,
    pub gate: FlexGateConfig<F>,
    // the instance column will contain the latest blockhash and the merkle root of all the blockhashes
    pub instance: Column<Instance>,
}

impl<F: FieldExt> MerkleChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: KeccakCircuitParams) -> Self {
        let gate =
            FlexGateConfig::configure(meta, GateStrategy::Vertical, &[1], 1, "default".to_string());
        let keccak = KeccakChip::configure(
            meta,
            "keccak".to_string(),
            1088,
            256,
            params.num_advice,
            params.num_xor,
            params.num_xorandn,
            0,
        );
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self { gate, keccak, instance }
    }

    // this is u128 -> big endian byte array -> but then each byte is little endian hex (yes, weird)
    pub fn assign_u128_to_hexes(
        &self,
        ctx: &mut Context<'_, F>,
        a: F,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        let hex_vals = decompose_option::<F>(&Value::known(a), 32, 4);
        let (hex_assigned, _, a_assigned) = self.gate.inner_product(
            ctx,
            &hex_vals.into_iter().map(|v| Witness(v)).collect(),
            &(0..32).map(|i| Constant(biguint_to_fe(&(BigUint::from(1u64) << (4 * i))))).collect(),
        )?;
        let mut hex_assigned = hex_assigned.unwrap();
        for i in (0..32).step_by(2) {
            hex_assigned.swap(i, i + 1);
        }
        // range checks
        // we use existing lookup tables for xor and xorandn - the actual values of these computations doesn't matter, we are just using the input columns as a lookup table on ranges
        for i in (0..30).step_by(3) {
            self.keccak.xor_and_n(
                ctx,
                &hex_assigned[i],
                &hex_assigned[i + 1],
                &hex_assigned[i + 2],
            )?;
        }
        self.keccak.xor(ctx, &[&hex_assigned[30], &hex_assigned[31]])?;
        Ok((a_assigned, hex_assigned.into_iter().rev().collect()))
    }
}

#[derive(Clone, Debug)]
pub struct MerkleRootCircuit<F: FieldExt> {
    pub leaves: Vec<F>, // leaves are 256 bit integers stored as pairs of u128 in big endian
}

impl MerkleRootCircuit<Fr> {
    // inputs are leaves of merkle tree, each leaf is u256 represented as pair of u128 in big endian
    pub fn create_snark_shplonk(inputs: Vec<Fr>, name: &str) -> Snark {
        let mut leaves = inputs
            .iter()
            .chunks(2)
            .into_iter()
            .map(|pair| {
                pair.into_iter()
                    .flat_map(|x| x.to_bytes()[..16].iter().rev().cloned().collect_vec())
                    .collect_vec()
            })
            .collect_vec();
        assert_eq!(leaves.len(), 1 << (leaves.len().ilog2()));
        for d in (0..leaves.len().ilog2()).rev() {
            for i in 0..(1 << d) {
                let mut hasher = Keccak256::default();
                hasher.update(&[leaves[2 * i].as_slice(), leaves[2 * i + 1].as_slice()].concat());
                leaves[i] = hasher.finalize().to_vec();
            }
        }
        let root = BigUint::from_bytes_be(leaves[0].as_slice());
        let mut instance = inputs.clone();
        instance.extend(
            [root.clone() >> 128, root & ((BigUint::from(1u64) << 128) - 1usize)]
                .iter()
                .map(biguint_to_fe::<Fr>),
        );

        let circuit = Self { leaves: inputs };

        let conf_str = std::fs::read_to_string("configs/merkle_root.config").unwrap();
        let config: KeccakCircuitParams = serde_json::from_str(conf_str.as_str()).unwrap();

        // MockProver::run(config.degree, &circuit, vec![instance.clone()]).unwrap().assert_satisfied();
        let params = gen_srs(config.degree);
        let pk = gen_pk(
            &params,
            &circuit,
            format!("merkle_root_{}", circuit.leaves.len().ilog2() - 1).as_str(),
        );

        // copy from create_snark_shplonk
        let config = Config::kzg(KZG_QUERY_INSTANCE)
            .set_zk(true)
            .with_num_proof(1)
            .with_num_instance(vec![instance.len()]);
        let protocol = compile(&params, pk.get_vk(), config);

        let instance1: Vec<&[Fr]> = vec![&instance];
        let instance2: &[&[Fr]] = &instance1[..];

        let proof = {
            let path = format!("./data/proof_{}.dat", name);
            match File::open(path.as_str()) {
                Ok(mut file) => {
                    let mut buf = vec![];
                    file.read_to_end(&mut buf).unwrap();
                    buf
                }
                Err(_) => {
                    let mut transcript =
                        PoseidonTranscript::<NativeLoader, Vec<u8>, _>::init(Vec::new());
                    create_proof::<
                        KZGCommitmentScheme<_>,
                        ProverSHPLONK<_>,
                        ChallengeScalar<_>,
                        _,
                        _,
                        _,
                    >(
                        &params,
                        &pk,
                        &[circuit],
                        &[instance2],
                        &mut ChaCha20Rng::from_entropy(),
                        &mut transcript,
                    )
                    .unwrap();
                    let proof = transcript.finalize();
                    let mut file = File::create(path.as_str()).unwrap();
                    file.write_all(&proof).unwrap();
                    proof
                }
            }
        };

        let instance_path = format!("./data/instances_{}.dat", name);
        write_instances(&vec![vec![instance.clone()]], instance_path.as_str());

        Snark::new(protocol, vec![instance], proof)
    }
}

impl<F: FieldExt> Circuit<F> for MerkleRootCircuit<F> {
    type Config = MerkleChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { leaves: self.leaves.iter().map(|_| F::zero()).collect_vec() }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params_str = std::fs::read_to_string("configs/merkle_root.config").unwrap();
        let params: KeccakCircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
        MerkleChip::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.keccak.load_lookup_table(&mut layouter)?;
        let using_simple_floor_planner = true;
        let mut first_pass = true;
        let mut instance = None;
        layouter.assign_region(
            || "merkle tree root",
            |region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                    return Ok(());
                }
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![
                            ("default".to_string(), config.gate.num_advice),
                            ("keccak".to_string(), config.keccak.rotation.len()),
                            ("keccak_xor".to_string(), config.keccak.xor_values.len() / 3),
                            ("keccak_xorandn".to_string(), config.keccak.xorandn_values.len() / 4),
                        ],
                    },
                );
                let ctx = &mut aux;

                let mut leaves = Vec::with_capacity(self.leaves.len() + 2);
                let mut leaves_hex = Vec::with_capacity(self.leaves.len() / 2);
                for leaf in &self.leaves.iter().chunks(2) {
                    let hexes = leaf
                        .into_iter()
                        .flat_map(|&leaf| {
                            let (assigned, hexes) = config.assign_u128_to_hexes(ctx, leaf).unwrap();
                            leaves.push(assigned);
                            hexes
                        })
                        .collect_vec();
                    leaves_hex.push(hexes);
                }
                let root_hex = config.keccak.merkle_tree_root(
                    ctx,
                    &leaves_hex.iter().map(|l| l.as_slice()).collect_vec(),
                )?;
                let root_u128 = hexes_to_u128(ctx, &config.gate, &root_hex);
                leaves.extend_from_slice(&root_u128);
                instance = Some(leaves);

                let stats = config.gate.finalize(ctx)?;
                #[cfg(feature = "display")]
                {
                    println!("stats (fixed rows, total fixed) {:?}", stats);
                    println!(
                        "ctx.advice_rows sums: {:#?}",
                        ctx.advice_rows
                            .iter()
                            .map(|(key, val)| (key, val.iter().sum::<usize>()))
                            .collect::<Vec<_>>()
                    );
                    println!("{:#?}", ctx.op_count);
                }
                Ok(())
            },
        )?;
        Ok({
            for (i, assigned_instance) in instance.unwrap().into_iter().enumerate() {
                layouter.constrain_instance(assigned_instance.cell(), config.instance, i)?;
            }
        })
    }
}

#[test]
fn test_merkle_circuit() {
    MerkleRootCircuit::create_snark_shplonk(vec![Fr::zero(); 4], "test");
}
