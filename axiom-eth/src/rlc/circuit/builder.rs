use halo2_base::{
    gates::{
        circuit::{
            builder::{BaseCircuitBuilder, RangeStatistics},
            CircuitBuilderStage,
        },
        GateInstructions, RangeChip,
    },
    halo2_proofs::plonk::Circuit,
    utils::ScalarField,
    virtual_region::copy_constraints::SharedCopyConstraintManager,
    AssignedValue, Context,
};
use itertools::Itertools;
use rayon::prelude::*;

use crate::rlc::{
    chip::RlcChip,
    virtual_region::{manager::RlcManager, RlcThreadBreakPoints},
    RLC_PHASE,
};

use super::RlcCircuitParams;

/// Circuit builder that extends [BaseCircuitBuilder] with support for RLC gate
#[derive(Clone, Debug, Default)]
pub struct RlcCircuitBuilder<F: ScalarField> {
    pub base: BaseCircuitBuilder<F>,
    pub rlc_manager: RlcManager<F>,
    /// Number of advice columns for RLC gate
    pub num_rlc_columns: usize,
    /// The challenge value, will be set after FirstPhase
    pub gamma: Option<F>,
    /// To avoid concurrency issues with `RlcChip::load_rlc_cache`, we will call it once
    /// when `RlcChip` is first created. This means we compute `gamma^{2^i}` for `i=0..max_cache_bits`.
    /// Concretely this means this circuit builder will only support concatenating strings where
    /// the max length of a fragment is < 2^max_cache_bits.
    max_cache_bits: usize,
}

impl<F: ScalarField> RlcCircuitBuilder<F> {
    pub fn new(witness_gen_only: bool, max_cache_bits: usize) -> Self {
        let base = BaseCircuitBuilder::new(witness_gen_only);
        let rlc_manager = RlcManager::new(witness_gen_only, base.core().copy_manager.clone());
        Self { base, rlc_manager, max_cache_bits, ..Default::default() }
    }

    pub fn unknown(mut self, use_unknown: bool) -> Self {
        self.base = self.base.unknown(use_unknown);
        self.rlc_manager = self.rlc_manager.unknown(use_unknown);
        self
    }

    pub fn from_stage(stage: CircuitBuilderStage, max_cache_bits: usize) -> Self {
        Self::new(stage.witness_gen_only(), max_cache_bits)
            .unknown(stage == CircuitBuilderStage::Keygen)
    }

    pub fn prover(
        config_params: RlcCircuitParams,
        break_points: RlcThreadBreakPoints,
        max_cache_bits: usize,
    ) -> Self {
        Self::new(true, max_cache_bits).use_params(config_params).use_break_points(break_points)
    }

    /// Returns global shared copy manager
    pub fn copy_manager(&self) -> &SharedCopyConstraintManager<F> {
        &self.base.core().copy_manager
    }

    /// Sets the copy manager to the given one in all shared references.
    pub fn set_copy_manager(&mut self, copy_manager: SharedCopyConstraintManager<F>) {
        self.base.set_copy_manager(copy_manager.clone());
        self.rlc_manager.set_copy_manager(copy_manager);
    }

    /// Returns `self` with a given copy manager
    pub fn use_copy_manager(mut self, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        self.set_copy_manager(copy_manager);
        self
    }

    pub fn set_max_cache_bits(&mut self, max_cache_bits: usize) {
        self.max_cache_bits = max_cache_bits;
    }

    pub fn use_max_cache_bits(mut self, max_cache_bits: usize) -> Self {
        self.set_max_cache_bits(max_cache_bits);
        self
    }

    /// Deep clone of `self`, where the underlying object of shared references in [SharedCopyConstraintManager] and [LookupAnyManager] are cloned.
    pub fn deep_clone(&self) -> Self {
        let base = self.base.deep_clone();
        let rlc_manager =
            self.rlc_manager.clone().use_copy_manager(base.core().copy_manager.clone());
        Self {
            base,
            rlc_manager,
            num_rlc_columns: self.num_rlc_columns,
            gamma: self.gamma,
            max_cache_bits: self.max_cache_bits,
        }
    }

    pub fn clear(&mut self) {
        self.base.clear();
        self.rlc_manager.clear();
    }

    /// Returns whether or not the circuit is only used for witness generation.
    pub fn witness_gen_only(&self) -> bool {
        assert_eq!(self.base.witness_gen_only(), self.rlc_manager.witness_gen_only());
        self.base.witness_gen_only()
    }

    /// Circuit configuration parameters
    pub fn params(&self) -> RlcCircuitParams {
        RlcCircuitParams { base: self.base.params(), num_rlc_columns: self.num_rlc_columns }
    }

    /// Set config params
    pub fn set_params(&mut self, params: RlcCircuitParams) {
        self.base.set_params(params.base);
        self.num_rlc_columns = params.num_rlc_columns;
    }

    /// Returns new with config params
    pub fn use_params(mut self, params: RlcCircuitParams) -> Self {
        self.set_params(params);
        self
    }

    /// The break points of the circuit.
    pub fn break_points(&self) -> RlcThreadBreakPoints {
        let base = self.base.break_points();
        let rlc =
            self.rlc_manager.break_points.borrow().as_ref().expect("break points not set").clone();
        RlcThreadBreakPoints { base, rlc }
    }

    /// Sets the break points of the circuit.
    pub fn set_break_points(&mut self, break_points: RlcThreadBreakPoints) {
        self.base.set_break_points(break_points.base);
        *self.rlc_manager.break_points.borrow_mut() = Some(break_points.rlc);
    }

    /// Returns new with break points
    pub fn use_break_points(mut self, break_points: RlcThreadBreakPoints) -> Self {
        self.set_break_points(break_points);
        self
    }

    /// Set lookup bits
    pub fn set_lookup_bits(&mut self, lookup_bits: usize) {
        self.base.config_params.lookup_bits = Some(lookup_bits);
    }

    /// Returns new with lookup bits
    pub fn use_lookup_bits(mut self, lookup_bits: usize) -> Self {
        self.set_lookup_bits(lookup_bits);
        self
    }

    /// Set `k` = log2 of domain
    pub fn set_k(&mut self, k: usize) {
        self.base.config_params.k = k;
    }

    /// Returns new with `k` set
    pub fn use_k(mut self, k: usize) -> Self {
        self.set_k(k);
        self
    }

    pub fn rlc_ctx_pair(&mut self) -> RlcContextPair<F> {
        (self.base.main(RLC_PHASE), self.rlc_manager.main())
    }

    /// Returns some statistics about the virtual region.
    pub fn statistics(&self) -> RlcStatistics {
        let base = self.base.statistics();
        let total_rlc_advice = self.rlc_manager.total_advice();
        RlcStatistics { base, total_rlc_advice }
    }

    /// Virtual cells that will be copied to public instance columns
    pub fn public_instances(&mut self) -> &mut [Vec<AssignedValue<F>>] {
        &mut self.base.assigned_instances
    }

    /// Auto-calculates configuration parameters for the circuit and sets them.
    ///
    /// * `minimum_rows`: The minimum number of rows in the circuit that cannot be used for witness assignments and contain random `blinding factors` to ensure zk property, defaults to 0.
    pub fn calculate_params(&mut self, minimum_rows: Option<usize>) -> RlcCircuitParams {
        let base = self.base.calculate_params(minimum_rows);
        let total_rlc_advice = self.rlc_manager.total_advice();
        let max_rows = (1 << base.k) - minimum_rows.unwrap_or(0);
        let num_rlc_columns = (total_rlc_advice + max_rows - 1) / max_rows;
        self.num_rlc_columns = num_rlc_columns;

        let params = RlcCircuitParams { base, num_rlc_columns };
        #[cfg(feature = "display")]
        {
            println!("Total RLC advice cells: {total_rlc_advice}");
            log::info!("Auto-calculated config params:\n {params:#?}");
        }
        params
    }

    /// Creates a new [RangeChip] sharing the same [LookupAnyManager]s as `self`.
    pub fn range_chip(&self) -> RangeChip<F> {
        self.base.range_chip()
    }

    /// Returns [RlcChip] if challenge value `gamma` is available. Panics otherwise.
    /// This should only be called in SecondPhase.
    pub fn rlc_chip(&mut self, gate: &impl GateInstructions<F>) -> RlcChip<F> {
        #[cfg(feature = "halo2-axiom")]
        {
            // safety check
            assert!(
                !self.witness_gen_only() || self.gamma.is_some(),
                "Challenge value not available before SecondPhase"
            );
        }
        let gamma = self.gamma.unwrap_or(F::ZERO);
        let rlc_chip = RlcChip::new(gamma);
        // Precompute gamma^{2^i} to avoid concurrency issues
        let cache_bits = self.max_cache_bits;
        let (ctx_gate, ctx_rlc) = self.rlc_ctx_pair();
        rlc_chip.load_rlc_cache((ctx_gate, ctx_rlc), gate, cache_bits);
        rlc_chip
    }

    /// Utility function to parallelize an operation involving RLC. This should be called in SecondPhase.
    //
    // **Warning:** if `f` calls `rlc.load_rlc_cache`, then this call must be done *before* calling `parallelize_phase1`.
    // Otherwise the cells where the rlc_cache gets stored will be different depending on which thread calls it first,
    // leading to non-deterministic behavior.
    pub fn parallelize_phase1<T, R, FR>(&mut self, input: Vec<T>, f: FR) -> Vec<R>
    where
        F: ScalarField,
        T: Send,
        R: Send,
        FR: Fn(RlcContextPair<F>, T) -> R + Send + Sync,
    {
        // to prevent concurrency issues with context id, we generate all the ids first
        let core_thread_count = self.base.pool(RLC_PHASE).thread_count();
        let rlc_thread_count = self.rlc_manager.thread_count();
        let mut ctxs_gate = (0..input.len())
            .map(|i| self.base.pool(RLC_PHASE).new_context(core_thread_count + i))
            .collect_vec();
        let mut ctxs_rlc = (0..input.len())
            .map(|i| self.rlc_manager.new_context(rlc_thread_count + i))
            .collect_vec();
        let outputs: Vec<_> = input
            .into_par_iter()
            .zip((ctxs_gate.par_iter_mut()).zip(ctxs_rlc.par_iter_mut()))
            .map(|(input, (ctx_gate, ctx_rlc))| f((ctx_gate, ctx_rlc), input))
            .collect();
        // we collect the new threads to ensure they are a FIXED order, otherwise the circuit will not be deterministic
        self.base.pool(RLC_PHASE).threads.append(&mut ctxs_gate);
        self.rlc_manager.threads.append(&mut ctxs_rlc);
        outputs
    }
}

/// Wrapper so we don't need to pass around two contexts separately. The pair consists of `(ctx_gate, ctx_rlc)` where
/// * `ctx_gate` should be an `RLC_PHASE` context for use with `GateChip`.
/// * `ctx_rlc` should be a context for use with `RlcChip`.
pub type RlcContextPair<'a, F> = (&'a mut Context<F>, &'a mut Context<F>);

pub struct RlcStatistics {
    pub base: RangeStatistics,
    pub total_rlc_advice: usize,
}
