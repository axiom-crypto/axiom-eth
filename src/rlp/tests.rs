mod rlc {
    use crate::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use crate::rlp::rlc::*;
    use halo2_base::{
        gates::{
            flex_gate::{FlexGateConfig, GateStrategy},
            GateInstructions,
        },
        utils::{value_to_option, ScalarField},
        Context, ContextParams, SKIP_FIRST_PASS,
    };
    use itertools::Itertools;
    use rand_core::OsRng;
    use std::marker::PhantomData;

    #[derive(Clone, Debug)]
    pub struct TestConfig<F: ScalarField> {
        rlc: RlcConfig<F>,
        gate: FlexGateConfig<F>,
    }

    impl<F: ScalarField> TestConfig<F> {
        pub fn configure(
            meta: &mut ConstraintSystem<F>,
            num_rlc_columns: usize,
            num_advice: &[usize],
            num_fixed: usize,
            circuit_degree: usize,
        ) -> Self {
            assert_ne!(num_advice[0], 0, "Must create some phase 0 advice columns");
            let gate = FlexGateConfig::configure(
                meta,
                GateStrategy::Vertical,
                num_advice,
                num_fixed,
                0,
                circuit_degree,
            );
            // Only configure `rlc` after `gate`, otherwise backend will detect that you created no phase 0 advice columns
            let rlc = RlcConfig::configure(meta, num_rlc_columns, 1);
            Self { rlc, gate }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct TestCircuit<F> {
        inputs: Vec<Option<u8>>,
        len: usize,
        _marker: PhantomData<F>,
    }

    const DEGREE: u32 = 10;

    impl<F: ScalarField> Circuit<F> for TestCircuit<F> {
        type Config = TestConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            TestConfig::configure(meta, 1, &[1, 1], 1, DEGREE as usize)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let gamma = config.rlc.gamma;
            let mut rlc_chip = RlcChip::new(config.rlc, layouter.get_challenge(gamma));

            let mut first_pass = SKIP_FIRST_PASS;
            let mut rlc_val = None;
            layouter.assign_region(
                || "",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: config.gate.max_rows,
                            num_context_ids: 2,
                            fixed_columns: config.gate.constants.clone(),
                        },
                    );
                    let ctx = &mut aux;

                    // ============ FIRST PHASE =============
                    let inputs_assigned = config.gate.assign_witnesses(
                        ctx,
                        self.inputs
                            .iter()
                            .map(|x| {
                                x.map(|v| Value::known(F::from(v as u64)))
                                    .unwrap_or(Value::unknown())
                            })
                    );
                    let len_assigned = config
                        .gate
                        .assign_witnesses(ctx, vec![Value::known(F::from(self.len as u64))]);

                    // ============= SECOND PHASE ===============
                    ctx.next_phase();
                    // squeeze challenge now that it is available
                    rlc_chip.get_challenge(ctx);

                    let rlc_trace = rlc_chip.compute_rlc(
                        ctx,
                        &config.gate,
                        inputs_assigned,
                        len_assigned[0].clone(),
                    );
                    rlc_val = value_to_option(rlc_trace.rlc_val.value().copied());

                    assert!(ctx.current_phase() <= 1);
                    #[cfg(feature = "display")]
                    {
                        let context_names = ["Gate", "RLC"]; 
                        ctx.advice_alloc_cache[RLC_PHASE] = ctx.advice_alloc.clone();
                        for phase in 0..=RLC_PHASE {
                            for (context_id, alloc) in ctx.advice_alloc_cache[phase].iter().enumerate() {
                                if phase != 0 || context_id != 1 {
                                    println!("Context \"{}\" used {} advice columns and {} total advice cells in phase {phase}", context_names[context_id], alloc.0 + 1, alloc.0 * ctx.max_rows + alloc.1);
                                }
                            }
                        }
                        let (fixed_cols, total_fixed) = ctx.fixed_stats();
                        println!("Fixed columns: {fixed_cols}, Total fixed cells: {total_fixed}");
                    }
                    Ok(())
                },
            )?;

            // the multi-phase system might call synthesize multiple times, so only do final check once `gamma` is "known"
            if self.inputs[0].is_some() && value_to_option(rlc_chip.gamma).is_some() {
                let real_rlc = compute_rlc_acc(
                    &self.inputs[..self.len].iter().map(|x| x.unwrap()).collect_vec(),
                    value_to_option(rlc_chip.gamma).unwrap(),
                );
                assert_eq!(real_rlc, rlc_val.unwrap());
                println!("Passed test");
            }
            Ok(())
        }
    }

    fn compute_rlc_acc<F: ScalarField>(msg: &[u8], r: F) -> F {
        let mut rlc = F::from(msg[0] as u64);
        for val in msg.iter().skip(1) {
            rlc = rlc * r + F::from(*val as u64);
        }
        rlc
    }

    #[test]
    pub fn test_mock_rlc() {
        let k = DEGREE;
        let input_bytes = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let len = 32;

        let circuit = TestCircuit::<Fr> {
            inputs: input_bytes.iter().map(|x| Some(*x)).collect(),
            len,
            _marker: PhantomData,
        };

        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }

    #[test]
    pub fn test_rlc() -> Result<(), Error> {
        let k = DEGREE;
        let input_bytes_pre = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let input_bytes: Vec<Option<u8>> = input_bytes_pre.iter().map(|x| Some(*x)).collect();
        let input_bytes_none: Vec<Option<u8>> = input_bytes_pre.iter().map(|_| None).collect();
        let len = 32;

        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let circuit = TestCircuit::<Fr> { inputs: input_bytes_none, len, _marker: PhantomData };

        println!("vk gen started");
        let vk = keygen_vk(&params, &circuit)?;
        println!("vk gen done");
        let pk = keygen_pk(&params, vk, &circuit)?;
        println!("pk gen done");
        println!();
        println!("==============STARTING PROOF GEN===================");

        let proof_circuit = TestCircuit::<Fr> { inputs: input_bytes, len, _marker: PhantomData };

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            TestCircuit<Fr>,
        >(&params, &pk, &[proof_circuit], &[&[]], OsRng, &mut transcript)?;
        let proof = transcript.finalize();
        println!("proof gen done");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .is_ok());
        println!("verify done");
        Ok(())
    }
}

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
