use std::cell::RefCell;

use crate::util::EthConfigParams;

use super::{
    builder::*,
    rlc::{RlcChip, RlcConfig},
    RlcGateConfig, RlpConfig,
};
use halo2_base::{
    gates::flex_gate::{FlexGateConfig, GateStrategy},
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    },
    utils::ScalarField,
    SKIP_FIRST_PASS,
};

mod rlc {
    use super::RlcCircuitBuilder;
    use halo2_base::{
        gates::GateChip,
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::{Bn256, Fr, G1Affine},
            plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Error},
            poly::{
                commitment::ParamsProver,
                kzg::{
                    commitment::{KZGCommitmentScheme, ParamsKZG},
                    multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
                    strategy::SingleStrategy,
                },
            },
            transcript::{
                Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
                TranscriptWriterBuffer,
            },
        },
        utils::ScalarField,
    };
    use itertools::Itertools;
    use rand::{rngs::StdRng, SeedableRng};
    use test_log::test;

    use crate::rlp::{
        builder::{FnSynthesize, RlcThreadBuilder},
        rlc::RlcChip,
    };

    const DEGREE: u32 = 10;

    fn rlc_test_circuit<F: ScalarField>(
        mut builder: RlcThreadBuilder<F>,
        _inputs: Vec<F>,
        _len: usize,
    ) -> RlcCircuitBuilder<F, impl FnSynthesize<F>> {
        let ctx = builder.gate_builder.main(0);
        let inputs = ctx.assign_witnesses(_inputs.clone());
        let len = ctx.load_witness(F::from(_len as u64));

        let synthesize_phase1 = move |builder: &mut RlcThreadBuilder<F>, rlc: &RlcChip<F>| {
            // the closure captures the `inputs` variable
            log::info!("phase 1 synthesize begin");
            let gate = GateChip::default();

            let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
            let rlc_trace = rlc.compute_rlc((ctx_gate, ctx_rlc), &gate, inputs, len);
            let rlc_val = *rlc_trace.rlc_val.value();
            let real_rlc = compute_rlc_acc(&_inputs[.._len], *rlc.gamma());
            assert_eq!(real_rlc, rlc_val);
        };

        RlcCircuitBuilder::new(builder, synthesize_phase1)
    }

    fn compute_rlc_acc<F: ScalarField>(msg: &[F], r: F) -> F {
        let mut rlc = msg[0];
        for val in msg.iter().skip(1) {
            rlc = rlc * r + val;
        }
        rlc
    }

    #[test]
    pub fn test_mock_rlc() {
        let k = DEGREE;
        let input_bytes = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
        .into_iter()
        .map(|x| Fr::from(x as u64))
        .collect_vec();
        let len = 32;

        let circuit = rlc_test_circuit(RlcThreadBuilder::mock(), input_bytes, len);

        circuit.config(k as usize, Some(6));
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_rlc() -> Result<(), Error> {
        let k = DEGREE;
        let input_bytes = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
        .into_iter()
        .map(|x| Fr::from(x as u64))
        .collect_vec();
        let len = 32;

        let mut rng = StdRng::from_seed([0u8; 32]);
        let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let circuit = rlc_test_circuit(RlcThreadBuilder::keygen(), input_bytes.clone(), len);
        circuit.config(k as usize, Some(6));

        println!("vk gen started");
        let vk = keygen_vk(&params, &circuit)?;
        println!("vk gen done");
        let pk = keygen_pk(&params, vk, &circuit)?;
        println!("pk gen done");
        println!();
        println!("==============STARTING PROOF GEN===================");
        let break_points = circuit.break_points.take();
        drop(circuit);
        let circuit = rlc_test_circuit(RlcThreadBuilder::prover(), input_bytes, len);
        *circuit.break_points.borrow_mut() = break_points;

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        println!("proof gen done");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(verifier_params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .unwrap();
        println!("verify done");
        Ok(())
    }
}

mod rlp {
    use super::RlpCircuitBuilder;
    use crate::rlp::{
        builder::{FnSynthesize, RlcThreadBuilder},
        *,
    };
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use hex::FromHex;
    use std::env::set_var;
    use test_log::test;

    const DEGREE: u32 = 18;

    fn rlp_string_circuit<F: ScalarField>(
        mut builder: RlcThreadBuilder<F>,
        encoded: Vec<u8>,
        max_len: usize,
    ) -> RlpCircuitBuilder<F, impl FnSynthesize<F>> {
        let prover = builder.witness_gen_only();
        let ctx = builder.gate_builder.main(0);
        let inputs = ctx.assign_witnesses(encoded.iter().map(|x| F::from(*x as u64)));
        set_var("LOOKUP_BITS", "8");
        let range = RangeChip::default(8);
        let chip = RlpChip::new(&range, None);
        let witness = chip.decompose_rlp_field_phase0(ctx, inputs, max_len);

        let f = move |b: &mut RlcThreadBuilder<F>, rlc: &RlcChip<F>| {
            let chip = RlpChip::new(&range, Some(rlc));
            // closure captures `witness` variable
            log::info!("phase 1 synthesize begin");
            let (ctx_gate, ctx_rlc) = b.rlc_ctx_pair();
            chip.decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness);
        };
        let circuit = RlpCircuitBuilder::new(builder, f);
        // auto-configure circuit if not in prover mode for convenience
        if !prover {
            circuit.config(DEGREE as usize, Some(6));
        }
        circuit
    }

    fn rlp_list_circuit<F: ScalarField>(
        mut builder: RlcThreadBuilder<F>,
        encoded: Vec<u8>,
        max_field_lens: &[usize],
        is_var_len: bool,
    ) -> RlpCircuitBuilder<F, impl FnSynthesize<F>> {
        let prover = builder.witness_gen_only();
        let ctx = builder.gate_builder.main(0);
        let inputs = ctx.assign_witnesses(encoded.iter().map(|x| F::from(*x as u64)));
        let range = RangeChip::default(8);
        let chip = RlpChip::new(&range, None);
        let witness = chip.decompose_rlp_array_phase0(ctx, inputs, max_field_lens, is_var_len);

        let circuit = RlpCircuitBuilder::new(
            builder,
            move |builder: &mut RlcThreadBuilder<F>, rlc: &RlcChip<F>| {
                let chip = RlpChip::new(&range, Some(rlc));
                // closure captures `witness` variable
                log::info!("phase 1 synthesize begin");
                chip.decompose_rlp_array_phase1(builder.rlc_ctx_pair(), witness, is_var_len);
            },
        );
        if !prover {
            circuit.config(DEGREE as usize, Some(6));
        }
        circuit
    }

    #[test]
    pub fn test_mock_rlp_array() {
        let k = DEGREE;
        // the list [ "cat", "dog" ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
        let cat_dog: Vec<u8> = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
        // the empty list = [ 0xc0 ]
        let empty_list: Vec<u8> = vec![0xc0];
        let input_bytes: Vec<u8> = Vec::from_hex("f8408d123000000000000000000000028824232222222222238b32222222222222222412528a04233333333333332322912323333333333333333333333333333333000000").unwrap();

        for mut test_input in [cat_dog, empty_list, input_bytes] {
            test_input.append(&mut vec![0; 69 - test_input.len()]);
            let circuit = rlp_list_circuit(
                RlcThreadBuilder::<Fr>::mock(),
                test_input,
                &[15, 9, 11, 10, 17],
                true,
            );
            MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
        }
    }

    #[test]
    pub fn test_mock_rlp_field() {
        let k = DEGREE;
        let input_bytes: Vec<u8> =
            Vec::from_hex("a012341234123412341234123412341234123412341234123412341234123412340000")
                .unwrap();
        let circuit = rlp_string_circuit(RlcThreadBuilder::<Fr>::mock(), input_bytes, 34);
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_mock_rlp_short_field() {
        let k = DEGREE;
        let mut input_bytes: Vec<u8> = vec![127];
        input_bytes.resize(35, 0);

        let circuit = rlp_string_circuit(RlcThreadBuilder::<Fr>::mock(), input_bytes, 34);
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_mock_rlp_long_field() {
        let k = DEGREE;
        let input_bytes: Vec<u8> = Vec::from_hex("a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap();

        let circuit = rlp_string_circuit(RlcThreadBuilder::<Fr>::mock(), input_bytes, 60);
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_mock_rlp_long_long_field() {
        let k = DEGREE;
        let input_bytes: Vec<u8> = Vec::from_hex("b83adb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap();

        let circuit = rlp_string_circuit(RlcThreadBuilder::<Fr>::mock(), input_bytes, 60);
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }
}

// The circuits below are mostly used for testing.
// Unfortunately for `KeccakCircuitBuilder` we still need to do some more custom stuff beyond what's in this circuit
// due to the intricacies of 2-phase challenge API.

/// A wrapper struct to auto-build a circuit from a `RlcThreadBuilder`.
///
/// This struct is trickier because it uses the Multi-phase Challenge API. The intended use is as follows:
/// * The user can run phase 0 calculations on `builder` outside of the circuit (as usual) and supply the builder to construct the circuit.
/// * The user also specifies a closure `synthesize_phase1(builder, challenge)` that specifies all calculations that should be done in phase 1.
/// The builder will then handle the process of assigning all advice cells in phase 1, squeezing a challenge value `challenge` from the backend API, and then using that value to do all phase 1 witness generation.
pub struct RlcCircuitBuilder<F: ScalarField, FnPhase1>
where
    FnPhase1: FnSynthesize<F>,
{
    pub builder: RefCell<RlcThreadBuilder<F>>,
    pub break_points: RefCell<RlcThreadBreakPoints>, // `RefCell` allows the circuit to record break points in a keygen call of `synthesize` for use in later witness gen
    // we guarantee that `synthesize_phase1` is called *exactly once* during the proving stage, but since `Circuit::synthesize` takes `&self`, and `assign_region` takes a `Fn` instead of `FnOnce`, we need some extra engineering:
    pub synthesize_phase1: RefCell<Option<FnPhase1>>,
}

impl<F: ScalarField, FnPhase1> RlcCircuitBuilder<F, FnPhase1>
where
    FnPhase1: FnSynthesize<F>,
{
    pub fn new(builder: RlcThreadBuilder<F>, synthesize_phase1: FnPhase1) -> Self {
        Self {
            builder: RefCell::new(builder),
            break_points: RefCell::new(RlcThreadBreakPoints::default()),
            synthesize_phase1: RefCell::new(Some(synthesize_phase1)),
        }
    }

    pub fn prover(
        builder: RlcThreadBuilder<F>,
        break_points: RlcThreadBreakPoints,
        synthesize_phase1: FnPhase1,
    ) -> Self {
        assert!(builder.witness_gen_only());
        Self {
            builder: RefCell::new(builder),
            break_points: RefCell::new(break_points),
            synthesize_phase1: RefCell::new(Some(synthesize_phase1)),
        }
    }

    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
        // clone everything so we don't alter the circuit in any way for later calls
        let mut builder = self.builder.borrow().clone();
        let f = self.synthesize_phase1.borrow().clone().expect("synthesize_phase1 should exist");
        f(&mut builder, &RlcChip::new(F::zero()));
        builder.config(k, minimum_rows)
    }

    // re-usable function for synthesize
    pub fn two_phase_synthesize(
        &self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        rlc: &RlcConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) {
        let mut first_pass = SKIP_FIRST_PASS;
        #[cfg(feature = "halo2-axiom")]
        let witness_gen_only = self.builder.borrow().witness_gen_only();
        // in non halo2-axiom, the prover calls `synthesize` twice: first just to get FirstPhase advice columns, commit, and then generate challenge value; then the second time to actually compute SecondPhase advice
        // our "Prover" implementation is heavily optimized for the Axiom version, which only calls `synthesize` once
        #[cfg(not(feature = "halo2-axiom"))]
        let witness_gen_only = false;

        let mut gamma = None;
        if !witness_gen_only {
            // in these cases, synthesize is called twice, and challenge can be gotten after the first time, or we use dummy value 0
            layouter.get_challenge(rlc.gamma).map(|gamma_| gamma = Some(gamma_));
        }

        layouter
            .assign_region(
                || "RlcCircuitBuilder generated circuit",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    if !witness_gen_only {
                        let mut builder = self.builder.borrow().clone();
                        let f = self
                            .synthesize_phase1
                            .borrow()
                            .clone()
                            .expect("synthesize_phase1 should exist");
                        // call the actual synthesize function
                        let rlc_chip = RlcChip::new(gamma.unwrap_or_else(|| F::zero()));
                        f(&mut builder, &rlc_chip);
                        let KeygenAssignments {
                            assigned_advices: _,
                            assigned_constants: _,
                            break_points,
                        } = builder.assign_all(
                            gate,
                            lookup_advice,
                            q_lookup,
                            rlc,
                            &mut region,
                            Default::default(),
                        );
                        *self.break_points.borrow_mut() = break_points;
                    } else {
                        let builder = &mut self.builder.borrow_mut();
                        let break_points = &mut self.break_points.borrow_mut();
                        assign_prover_phase0(
                            &mut region,
                            gate,
                            lookup_advice,
                            builder,
                            break_points,
                        );
                        // this is a special backend API function (in halo2-axiom only) that computes the KZG commitments for all columns in FirstPhase and performs Fiat-Shamir on them to return the challenge value
                        region.next_phase();
                        // get challenge value
                        let mut gamma = None;
                        region.get_challenge(rlc.gamma).map(|gamma_| {
                            log::info!("gamma: {gamma_:?}");
                            gamma = Some(gamma_);
                        });
                        let rlc_chip =
                            RlcChip::new(gamma.expect("Could not get challenge in second phase"));
                        let f = RefCell::take(&self.synthesize_phase1)
                            .expect("synthesize_phase1 should exist"); // we `take` the closure during proving to avoid cloning captured variables (the captured variables would be the AssignedValue payload sent from FirstPhase to SecondPhase)
                        assign_prover_phase1(
                            &mut region,
                            gate,
                            lookup_advice,
                            rlc,
                            &rlc_chip,
                            builder,
                            break_points,
                            f,
                        );
                    }
                    Ok(())
                },
            )
            .unwrap();
    }
}

impl<F: ScalarField, FnPhase1> Circuit<F> for RlcCircuitBuilder<F, FnPhase1>
where
    FnPhase1: FnSynthesize<F>,
{
    type Config = RlcGateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> RlcGateConfig<F> {
        let EthConfigParams {
            degree,
            num_rlc_columns,
            num_range_advice,
            num_lookup_advice: _,
            num_fixed,
            unusable_rows: _,
            keccak_rows_per_round: _,
        } = serde_json::from_str(&std::env::var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        let mut gate = FlexGateConfig::configure(
            meta,
            GateStrategy::Vertical,
            &num_range_advice,
            num_fixed,
            degree as usize,
        );
        let rlc = RlcConfig::configure(meta, num_rlc_columns);
        // number of blinding factors may have changed due to introduction of new RLC gate
        gate.max_rows = (1 << degree) - meta.minimum_rows();
        RlcGateConfig { gate, rlc }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.two_phase_synthesize(&config.gate, &[], &[], &config.rlc, &mut layouter);
        Ok(())
    }
}

/// A wrapper around RlcCircuitBuilder where Gate is replaced by Range in the circuit
pub struct RlpCircuitBuilder<F: ScalarField, FnPhase1>(RlcCircuitBuilder<F, FnPhase1>)
where
    FnPhase1: FnSynthesize<F>;

impl<F: ScalarField, FnPhase1> RlpCircuitBuilder<F, FnPhase1>
where
    FnPhase1: FnSynthesize<F>,
{
    pub fn new(builder: RlcThreadBuilder<F>, synthesize_phase1: FnPhase1) -> Self {
        Self(RlcCircuitBuilder::new(builder, synthesize_phase1))
    }

    pub fn prover(
        builder: RlcThreadBuilder<F>,
        break_points: RlcThreadBreakPoints,
        synthesize_phase1: FnPhase1,
    ) -> Self {
        Self(RlcCircuitBuilder::prover(builder, break_points, synthesize_phase1))
    }

    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
        self.0.config(k, minimum_rows)
    }
}

impl<F: ScalarField, FnPhase1> Circuit<F> for RlpCircuitBuilder<F, FnPhase1>
where
    FnPhase1: FnSynthesize<F>,
{
    type Config = RlpConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> RlpConfig<F> {
        let EthConfigParams {
            degree,
            num_rlc_columns,
            num_range_advice,
            num_lookup_advice,
            num_fixed,
            unusable_rows: _,
            keccak_rows_per_round: _,
        } = serde_json::from_str(&std::env::var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        let lookup_bits = std::env::var("LOOKUP_BITS").unwrap().parse().unwrap();
        RlpConfig::configure(
            meta,
            num_rlc_columns,
            &num_range_advice,
            &num_lookup_advice,
            num_fixed,
            lookup_bits,
            degree as usize,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.range.load_lookup_table(&mut layouter)?;
        self.0.two_phase_synthesize(
            &config.range.gate,
            &config.range.lookup_advice,
            &config.range.q_lookup,
            &config.rlc,
            &mut layouter,
        );
        Ok(())
    }
}
