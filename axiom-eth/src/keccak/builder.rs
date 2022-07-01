use halo2_base::gates::builder::GateThreadBuilder;

use crate::rlp::rlc::FIRST_PHASE;

use super::*;

/// We need a more custom synthesize function to work with the outputs of keccak RLCs.
pub trait FnSynthesize<F> =
    FnOnce(&mut RlcThreadBuilder<F>, RlpChip<F>, (FixedLenRLCs<F>, VarLenRLCs<F>)) + Clone;

pub struct KeccakCircuitBuilder<F: Field, FnPhase1>
where
    FnPhase1: FnSynthesize<F>,
{
    pub builder: RefCell<RlcThreadBuilder<F>>,
    pub break_points: RefCell<RlcThreadBreakPoints>,
    pub synthesize_phase1: RefCell<Option<FnPhase1>>,
    pub keccak: SharedKeccakChip<F>,
    pub range: RangeChip<F>,
}

impl<F: Field, FnPhase1> KeccakCircuitBuilder<F, FnPhase1>
where
    FnPhase1: FnSynthesize<F>,
{
    pub fn new(
        builder: RlcThreadBuilder<F>,
        keccak: SharedKeccakChip<F>,
        range: RangeChip<F>,
        break_points: Option<RlcThreadBreakPoints>,
        synthesize_phase1: FnPhase1,
    ) -> Self {
        Self {
            builder: RefCell::new(builder),
            break_points: RefCell::new(break_points.unwrap_or_default()),
            synthesize_phase1: RefCell::new(Some(synthesize_phase1)),
            keccak,
            range,
        }
    }

    /// Does a dry run of multi-phase synthesize to calculate optimal configuration parameters
    ///
    /// Beware: the `KECCAK_ROWS` is calculated based on the `minimum_rows = UNUSABLE_ROWS`,
    /// however at configuration time the `minimum_rows` will depend on `KECCAK_ROWS`.
    /// If you then reset `minimum_rows` to this smaller number, it might auto-configure
    /// to a higher `KECCAK_ROWS`, which now requires higher `minimum_rows`...
    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
        // clone everything so we don't alter the circuit in any way for later calls
        let mut builder = self.builder.borrow().clone();
        let mut keccak = self.keccak.borrow().clone();
        let optimal_rows_per_round =
            rows_per_round((1 << k) - minimum_rows.unwrap_or(0), keccak.capacity());
        // we don't want to actually call `keccak.assign_phase{0,1}` so we fake the output
        let table_input_rlcs = vec![
            AssignedValue {
                value: Assigned::Trivial(F::zero()),
                cell: Some(ContextCell { context_id: KECCAK_CONTEXT_ID, offset: 0 })
            };
            keccak.capacity()
        ];
        let table_output_rlcs = table_input_rlcs.clone();
        let rlc_chip = RlcChip::new(F::zero());
        let rlp_chip = RlpChip::new(&self.range, Some(&rlc_chip));
        let keccak_rlcs = keccak.process_phase1(
            &mut builder,
            &rlc_chip,
            &self.range,
            table_input_rlcs,
            table_output_rlcs,
        );
        let f = self.synthesize_phase1.borrow().clone().expect("synthesize_phase1 should exist");
        f(&mut builder, rlp_chip, keccak_rlcs);
        let mut params = builder.config(k, minimum_rows);
        params.keccak_rows_per_round = std::cmp::min(optimal_rows_per_round, 50); // empirically more than 50 rows per round makes the rotation offsets too large
        self.keccak.borrow_mut().num_rows_per_round = params.keccak_rows_per_round;
        #[cfg(feature = "display")]
        log::info!("KeccakCircuitBuilder auto-calculated config params: {:#?}", params);
        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
        set_var("KECCAK_DEGREE", k.to_string());
        set_var("KECCAK_ROWS", params.keccak_rows_per_round.to_string());

        params
    }

    // re-usable function for synthesize
    pub fn two_phase_synthesize(
        &self,
        config: &MPTConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> HashMap<(usize, usize), (circuit::Cell, usize)> {
        config.rlp.range.load_lookup_table(layouter).expect("load range lookup table");
        config.keccak.load_aux_tables(layouter).expect("load keccak lookup tables");

        let mut first_pass = SKIP_FIRST_PASS;
        let witness_gen_only = self.builder.borrow().witness_gen_only();

        let mut gamma = None;
        if !witness_gen_only {
            // in these cases, synthesize is called twice, and challenge can be gotten after the first time, or we use dummy value 0
            layouter.get_challenge(config.rlp.rlc.gamma).map(|gamma_| gamma = Some(gamma_));
        }
        let mut assigned_advices = HashMap::new();

        layouter
            .assign_region(
                || "KeccakCircuitBuilder generated circuit",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    if !witness_gen_only {
                        let start = std::time::Instant::now();
                        let mut builder = self.builder.borrow().clone();
                        let mut keccak = self.keccak.borrow().clone();
                        let f = self
                            .synthesize_phase1
                            .borrow()
                            .clone()
                            .expect("synthesize_phase1 should exist");
                        // tells zkevm keccak to assign its cells
                        let squeeze_digests = keccak.assign_phase0(&mut region, &config.keccak);
                        println!("{:?}", start.elapsed());
                        // end of FirstPhase
                        let rlc_chip = RlcChip::new(gamma.unwrap_or_else(|| F::zero()));
                        // SecondPhase: tell zkevm keccak to assign RLC cells and upload them into `assigned_advices`
                        let (keccak_advices, table_input_rlcs, table_output_rlcs) = keccak
                            .assign_phase1(
                                &mut region,
                                &config.keccak.keccak_table,
                                squeeze_digests,
                                *rlc_chip.gamma(),
                                Some(HashMap::new()),
                            );
                        // Constrain RLCs so keccak chip witnesses are actually correct
                        let keccak_rlcs = keccak.process_phase1(
                            &mut builder,
                            &rlc_chip,
                            &self.range,
                            table_input_rlcs,
                            table_output_rlcs,
                        );
                        // Do any custom synthesize functions in SecondPhase
                        let mut assignments = KeygenAssignments {
                            assigned_advices: keccak_advices,
                            ..Default::default()
                        };
                        let rlp_chip = RlpChip::new(&self.range, Some(&rlc_chip));
                        f(&mut builder, rlp_chip, keccak_rlcs);
                        assignments = builder.assign_all(
                            &config.rlp.range.gate,
                            &config.rlp.range.lookup_advice,
                            &config.rlp.range.q_lookup,
                            &config.rlp.rlc,
                            &mut region,
                            assignments,
                        );
                        *self.break_points.borrow_mut() = assignments.break_points;
                        assigned_advices = assignments.assigned_advices;
                    } else {
                        let builder = &mut self.builder.borrow_mut();
                        let break_points = &mut self.break_points.borrow_mut();
                        assign_prover_phase0(
                            &mut region,
                            &config.rlp.range.gate,
                            &config.rlp.range.lookup_advice,
                            builder,
                            break_points,
                        );
                        let squeeze_digests =
                            self.keccak.borrow().assign_phase0(&mut region, &config.keccak);
                        // == END OF FIRST PHASE ==
                        // this is a special backend API function (in halo2-axiom only) that computes the KZG commitments for all columns in FirstPhase and performs Fiat-Shamir on them to return the challenge value
                        #[cfg(feature = "halo2-axiom")]
                        region.next_phase();
                        // == BEGIN SECOND PHASE ==
                        // get challenge value
                        let mut gamma = None;
                        #[cfg(feature = "halo2-axiom")]
                        region.get_challenge(config.rlp.rlc.gamma).map(|gamma_| {
                            log::info!("gamma: {gamma_:?}");
                            gamma = Some(gamma_);
                        });
                        let rlc_chip =
                            RlcChip::new(gamma.expect("Could not get challenge in second phase"));
                        let (_, table_input_rlcs, table_output_rlcs) =
                            self.keccak.borrow().assign_phase1(
                                &mut region,
                                &config.keccak.keccak_table,
                                squeeze_digests,
                                *rlc_chip.gamma(),
                                None,
                            );
                        // Constrain RLCs so keccak chip witnesses are actually correct
                        let keccak_rlcs = self.keccak.borrow_mut().process_phase1(
                            builder,
                            &rlc_chip,
                            &self.range,
                            table_input_rlcs,
                            table_output_rlcs,
                        );
                        let f = RefCell::take(&self.synthesize_phase1)
                            .expect("synthesize_phase1 should exist"); // we `take` the closure during proving to avoid cloning captured variables (the captured variables would be the AssignedValue payload sent from FirstPhase to SecondPhase)
                        assign_prover_phase1(
                            &mut region,
                            &config.rlp.range.gate,
                            &config.rlp.range.lookup_advice,
                            &config.rlp.rlc,
                            &rlc_chip,
                            builder,
                            break_points,
                            |builder: &mut RlcThreadBuilder<F>, rlc_chip: &RlcChip<F>| {
                                let rlp_chip = RlpChip::new(&self.range, Some(rlc_chip));
                                f(builder, rlp_chip, keccak_rlcs);
                            },
                        );
                    }
                    Ok(())
                },
            )
            .unwrap();
        assigned_advices
    }
}

impl<F: Field, FnPhase1: FnSynthesize<F>> Circuit<F> for KeccakCircuitBuilder<F, FnPhase1> {
    type Config = MPTConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> MPTConfig<F> {
        let params: EthConfigParams =
            serde_json::from_str(&std::env::var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        MPTConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.two_phase_synthesize(&config, &mut layouter);
        Ok(())
    }
}

// The following is a hack to allow parallelization of KeccakChip. Should refactor more generally in future.

/// Trait for structs that contain references to keccak query indices.
/// Due to current [`KeccakChip`] implementation, these indices must be shifted
/// if multiple structs are created in parallel, to avoid race conditions on the circuit.
pub trait ContainsParallelizableKeccakQueries {
    /// Shifts all fixed (resp. variable) length keccak query indices by `fixed_shift` (resp. `var_shift`).
    /// This is necessary when joining parallel (multi-threaded) keccak chips into one.
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize);
}

/// Utility function to parallelize an operation involving KeccakChip that outputs something referencing
/// keccak query indices. This should be done in FirstPhase.
///
/// When `R` stores keccak queries by index, in a parallel setting, we need to shift
/// the indices at the end.
pub fn parallelize_keccak_phase0<F, T, R, FR>(
    thread_pool: &mut GateThreadBuilder<F>,
    keccak: &mut KeccakChip<F>,
    input: Vec<T>,
    f: FR,
) -> Vec<R>
where
    F: Field,
    T: Send,
    R: ContainsParallelizableKeccakQueries + Send,
    FR: Fn(&mut Context<F>, &mut KeccakChip<F>, T) -> R + Send + Sync,
{
    let witness_gen_only = thread_pool.witness_gen_only();
    let ctx_ids = input.iter().map(|_| thread_pool.get_new_thread_id()).collect_vec();
    let (mut trace, ctxs): (Vec<_>, Vec<_>) = input
        .into_par_iter()
        .zip(ctx_ids.into_par_iter())
        .map(|(input, ctx_id)| {
            let mut ctx = Context::new(witness_gen_only, ctx_id);
            let mut keccak = KeccakChip::default();
            let trace = f(&mut ctx, &mut keccak, input);
            (trace, (ctx, keccak))
        })
        .unzip();
    // join gate contexts and keccak queries; need to shift keccak query indices because of the join
    for (trace, (ctx, mut _keccak)) in trace.iter_mut().zip(ctxs.into_iter()) {
        thread_pool.threads[FIRST_PHASE].push(ctx);
        trace.shift_query_indices(keccak.fixed_len_queries.len(), keccak.var_len_queries.len());
        keccak.fixed_len_queries.append(&mut _keccak.fixed_len_queries);
        keccak.var_len_queries.append(&mut _keccak.var_len_queries);
    }
    trace
}
