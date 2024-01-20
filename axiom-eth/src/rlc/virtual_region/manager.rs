use std::cell::RefCell;

use crate::rlc::{circuit::PureRlcConfig, RLC_PHASE};
use getset::CopyGetters;
use halo2_base::{
    gates::{
        circuit::CircuitBuilderStage,
        flex_gate::{
            threads::single_phase::{assign_with_constraints, assign_witnesses},
            ThreadBreakPoints,
        },
    },
    halo2_proofs::circuit::Region,
    utils::ScalarField,
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, manager::VirtualRegionManager,
    },
    Context,
};

/// Virtual region manager for managing virtual columns ([Context]s) in [RLC_PHASE] corresponding to [RlcConfig].
///
/// Note: this uses a similar vertical gate structure as [FlexGateConfig] **however** the RLC gate uses only 3 contiguous rows instead of 4.
///
/// The implementation and functionality of this manager is very similar to `SinglePhaseCoreManager` for [FlexGateConfig] except the aforementioned 3 rows vs 4 rows gate.
#[derive(Clone, Debug, Default, CopyGetters)]
pub struct RlcManager<F: ScalarField> {
    /// Virtual columns. These cannot be shared across CPU threads while keeping the circuit deterministic.
    pub threads: Vec<Context<F>>,
    /// Global shared copy manager
    pub copy_manager: SharedCopyConstraintManager<F>,
    /// Flag for witness generation. If true, the gate thread builder is used for witness generation only.
    #[getset(get_copy = "pub")]
    witness_gen_only: bool,
    /// The `unknown` flag is used during key generation. If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    #[getset(get_copy = "pub")]
    pub(crate) use_unknown: bool,
    /// A very simple computation graph for the basic vertical RLC gate. Must be provided as a "pinning"
    /// when running the production prover.
    pub break_points: RefCell<Option<ThreadBreakPoints>>,
}

// Copied impl from `SinglePhaseCoreManager`, modified so TypeId is of RlcManager, and phase is always RLC_PHASE = 1 (SecondPhase)
impl<F: ScalarField> RlcManager<F> {
    /// Creates a new [RlcManager] and spawns a main thread.
    /// * `witness_gen_only`: If true, the [RlcManager] is used for witness generation only and does not impose any constraints.
    pub fn new(witness_gen_only: bool, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        Self {
            threads: vec![],
            witness_gen_only,
            use_unknown: false,
            copy_manager,
            ..Default::default()
        }
    }

    /// The phase of this manager is always [RLC_PHASE]
    pub fn phase(&self) -> usize {
        RLC_PHASE
    }

    /// Creates a new [GateThreadBuilder] depending on the stage of circuit building. If the stage is [CircuitBuilderStage::Prover], the [GateThreadBuilder] is used for witness generation only.
    pub fn from_stage(
        stage: CircuitBuilderStage,
        copy_manager: SharedCopyConstraintManager<F>,
    ) -> Self {
        Self::new(stage.witness_gen_only(), copy_manager)
            .unknown(stage == CircuitBuilderStage::Keygen)
    }

    /// Creates a new [RlcManager] with `use_unknown` flag set.
    /// * `use_unknown`: If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    pub fn unknown(self, use_unknown: bool) -> Self {
        Self { use_unknown, ..self }
    }

    /// Sets the copy manager to the given one in all shared references.
    pub fn set_copy_manager(&mut self, copy_manager: SharedCopyConstraintManager<F>) {
        for ctx in &mut self.threads {
            ctx.copy_manager = copy_manager.clone();
        }
        self.copy_manager = copy_manager;
    }

    /// Returns `self` with a given copy manager
    pub fn use_copy_manager(mut self, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        self.set_copy_manager(copy_manager);
        self
    }

    pub fn clear(&mut self) {
        self.threads.clear();
        self.copy_manager.lock().unwrap().clear();
    }

    /// Returns a mutable reference to the [Context] of a gate thread. Spawns a new thread for the given phase, if none exists.
    pub fn main(&mut self) -> &mut Context<F> {
        if self.threads.is_empty() {
            self.new_thread()
        } else {
            self.threads.last_mut().unwrap()
        }
    }

    /// Returns the number of threads
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    /// Creates new context but does not append to `self.threads`
    pub(crate) fn new_context(&self, context_id: usize) -> Context<F> {
        Context::new(
            self.witness_gen_only,
            RLC_PHASE,
            "axiom-eth:RlcManager:SecondPhase",
            context_id,
            self.copy_manager.clone(),
        )
    }

    /// Spawns a new thread for a new given `phase`. Returns a mutable reference to the [Context] of the new thread.
    /// * `phase`: The phase (index) of the gate thread.
    pub fn new_thread(&mut self) -> &mut Context<F> {
        let context_id = self.thread_count();
        self.threads.push(self.new_context(context_id));
        self.threads.last_mut().unwrap()
    }

    /// Returns total advice cells
    pub fn total_advice(&self) -> usize {
        self.threads.iter().map(|ctx| ctx.advice.len()).sum::<usize>()
    }
}

impl<F: ScalarField> VirtualRegionManager<F> for RlcManager<F> {
    type Config = PureRlcConfig<F>;

    fn assign_raw(&self, rlc_config: &Self::Config, region: &mut Region<F>) {
        if self.witness_gen_only {
            let binding = self.break_points.borrow();
            let break_points = binding.as_ref().expect("break points not set");
            assign_witnesses(&self.threads, &rlc_config.basic_gates, region, break_points);
        } else {
            let mut copy_manager = self.copy_manager.lock().unwrap();
            assert!(
                self.threads.iter().all(|ctx| ctx.phase() == RLC_PHASE),
                "all threads must be in RLC_PHASE"
            );
            let break_points = assign_with_constraints::<F, 3>(
                &self.threads,
                &rlc_config.basic_gates,
                region,
                &mut copy_manager,
                rlc_config.usable_rows,
                self.use_unknown,
            );
            let mut bp = self.break_points.borrow_mut();
            if let Some(bp) = bp.as_ref() {
                assert_eq!(bp, &break_points, "break points don't match");
            } else {
                *bp = Some(break_points);
            }
        }
    }
}
