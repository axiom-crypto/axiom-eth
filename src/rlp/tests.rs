mod rlc {
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

    use crate::rlp::{
        builder::{RlcCircuitBuilder, RlcThreadBuilder},
        rlc::{RlcChip, RLC_PHASE},
    };

    const DEGREE: u32 = 10;

    fn rlc_test_circuit<F: ScalarField>(
        mut builder: RlcThreadBuilder<F>,
        _inputs: Vec<F>,
        _len: usize,
    ) -> RlcCircuitBuilder<F, impl Fn(&mut RlcThreadBuilder<F>, F)> {
        let ctx = builder.gate_builder.main(0);
        let inputs = ctx.assign_witnesses(_inputs.clone());
        let len = ctx.load_witness(F::from(_len as u64));

        let synthesize_phase1 = move |builder: &mut RlcThreadBuilder<F>, gamma: F| {
            log::info!("phase 1 synthesize begin");
            let gate = GateChip::default();
            let rlc = RlcChip::new(gamma);

            builder.new_thread_rlc();
            let ctx_gate = builder.gate_builder.main(RLC_PHASE);
            let ctx_rlc = builder.threads_rlc.last_mut().unwrap();
            let rlc_trace = rlc.compute_rlc(ctx_gate, ctx_rlc, &gate, inputs.clone(), len);
            let rlc_val = *rlc_trace.rlc_val.value();
            let real_rlc = compute_rlc_acc(&_inputs[.._len], gamma);
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
        let _ = env_logger::builder().is_test(true).try_init();
        let k = DEGREE;
        let input_bytes = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
        .into_iter()
        .map(|x| Fr::from(x as u64))
        .collect_vec();
        let len = 32;

        let circuit = rlc_test_circuit(RlcThreadBuilder::mock(), input_bytes.clone(), len);

        circuit.config(k as usize, Some(6));
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_rlc() -> Result<(), Error> {
        let _ = env_logger::builder().is_test(true).try_init();
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

/*
mod rlp {
    use crate::rlp::*;
    use halo2_base::{
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            dev::MockProver,
            halo2curves::bn256::Fr,
            plonk::{Circuit, Error},
        },
        ContextParams, SKIP_FIRST_PASS,
    };
    use hex::FromHex;
    use std::marker::PhantomData;

    const DEGREE: u32 = 18;

    #[derive(Clone, Debug, Default)]
    pub struct RlpTestCircuit<F> {
        inputs: Vec<u8>,
        max_len: usize,
        max_field_lens: Vec<usize>,
        is_array: bool,
        is_variable_len: bool,
        _marker: PhantomData<F>,
    }

    impl<F: ScalarField> Circuit<F> for RlpTestCircuit<F> {
        type Config = RlpConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            RlpConfig::configure(meta, 1, &[1, 1], &[1], 1, 8, 0, DEGREE as usize)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config
                .range
                .load_lookup_table(&mut layouter)
                .expect("load lookup table should not fail");

            let gamma = config.rlc.gamma;
            let mut chip = RlpChip::new(config, layouter.get_challenge(gamma));

            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "RLP test",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: chip.gate().max_rows,
                            num_context_ids: 2,
                            fixed_columns: chip.gate().constants.clone(),
                        },
                    );
                    let ctx = &mut aux;

                    let inputs_assigned = chip.gate().assign_witnesses(
                        ctx,
                        self.inputs.iter().map(|x| Value::known(F::from(*x as u64))),
                    );

                    if self.is_array {
                        // FirstPhase
                        let witness = chip.decompose_rlp_array_phase0(
                            ctx,
                            inputs_assigned,
                            &self.max_field_lens,
                            self.is_variable_len,
                        );

                        chip.range.finalize(ctx);
                        ctx.next_phase();

                        // SecondPhase
                        println!("=== SECOND PHASE ===");
                        chip.get_challenge(ctx);
                        chip.decompose_rlp_array_phase1(ctx, witness, self.is_variable_len);
                    } else {
                        // FirstPhase
                        let witness =
                            chip.decompose_rlp_field_phase0(ctx, inputs_assigned, self.max_len);

                        chip.range.finalize(ctx);
                        ctx.next_phase();

                        // SecondPhase
                        println!("=== SECOND PHASE ===");
                        chip.get_challenge(ctx);
                        chip.decompose_rlp_field_phase1(ctx, witness);
                    }

                    assert!(ctx.current_phase() <= 1);
                    #[cfg(feature = "display")]
                    {
                        let context_names = ["Range", "RLC"];
                        ctx.print_stats(&context_names);
                    }
                    Ok(())
                },
            )
        }
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
            let circuit = RlpTestCircuit::<Fr> {
                inputs: test_input,
                max_len: 69,
                max_field_lens: vec![15, 9, 11, 10, 17],
                is_array: true,
                is_variable_len: true,
                _marker: PhantomData,
            };
            MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
        }
    }

    #[test]
    pub fn test_mock_rlp_field() {
        let k = DEGREE;
        let input_bytes: Vec<u8> =
            Vec::from_hex("a012341234123412341234123412341234123412341234123412341234123412340000")
                .unwrap();

        let circuit = RlpTestCircuit::<Fr> {
            inputs: input_bytes,
            max_len: 34,
            max_field_lens: vec![],
            is_array: false,
            is_variable_len: false,
            _marker: PhantomData,
        };
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_mock_rlp_short_field() {
        let k = DEGREE;
        let mut input_bytes: Vec<u8> = vec![127];
        input_bytes.resize(35, 0);

        let circuit = RlpTestCircuit::<Fr> {
            inputs: input_bytes,
            max_len: 34,
            max_field_lens: vec![],
            is_array: false,
            is_variable_len: false,
            _marker: PhantomData,
        };
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_mock_rlp_long_field() {
        let k = DEGREE;
        let input_bytes: Vec<u8> = Vec::from_hex("a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap();

        let circuit = RlpTestCircuit::<Fr> {
            inputs: input_bytes,
            max_len: 60,
            max_field_lens: vec![],
            is_array: false,
            is_variable_len: false,
            _marker: PhantomData,
        };
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_mock_rlp_long_long_field() {
        let k = DEGREE;
        let input_bytes: Vec<u8> = Vec::from_hex("b83adb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap();

        let circuit = RlpTestCircuit::<Fr> {
            inputs: input_bytes,
            max_len: 60,
            max_field_lens: vec![],
            is_array: false,
            is_variable_len: false,
            _marker: PhantomData,
        };
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }
}
 */
