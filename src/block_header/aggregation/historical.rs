#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use halo2_base::{
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, ConstraintSystem, Error},
        poly::kzg::commitment::ParamsKZG,
    },
    Context, ContextParams,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::{
    halo2::aggregation::{
        aggregate, flatten_accumulator, AggregationCircuit, AggregationConfig,
        AggregationConfigParams, Halo2Loader,
    },
    Snark, LIMBS,
};
use std::{env::var, fs::File};

/// Same as [`PublicAggregationCircuit`](snark_verifier_sdk::halo2::aggregation::PublicAggregationCircuit) but with special logic around how to handle joining instances
#[derive(Clone)]
pub struct HistoricalAggregationCircuit {
    pub aggregation: AggregationCircuit,
    // max depth of the block hash merkle mountain ranges
    max_depth: usize,
    // the snarks to aggregation are `round` rounds post `EthBlockHeaderChainFinalAggregationCircuit`
    pub round: usize,
}

impl HistoricalAggregationCircuit {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: Vec<Snark>,
        max_depth: usize,
        round: usize,
        rng: &mut (impl Rng + Send),
    ) -> Self {
        Self { aggregation: AggregationCircuit::new(params, snarks, rng), max_depth, round }
    }
}

#[derive(Serialize, Deserialize)]
/// `HistoricalAggregationConfig(config, num_snarks)`
pub struct HistoricalAggConfigParams {
    pub aggregation: AggregationConfigParams,
    pub num_snarks: u32,
    // each snark to be aggregated already has instances of `prev_agg_total` number of `EthBlockHeaderChainFinalAggregationCircuit`s
    pub prev_agg_total: u32,
}

impl HistoricalAggConfigParams {
    pub fn get() -> Self {
        let path = var("HISTORICAL_AGG_CONFIG").expect("HISTORICAL_AGG_CONFIG not set");
        serde_json::from_reader(
            File::open(&path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
        )
        .unwrap()
    }
}

impl Circuit<Fr> for HistoricalAggregationCircuit {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { aggregation: self.aggregation.without_witnesses(), ..*self }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params = HistoricalAggConfigParams::get().aggregation;
        AggregationConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: AggregationConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        #[cfg(feature = "display")]
        let witness_time = start_timer!(|| { "synthesize | Historical aggregation circuit" });
        config.range().load_lookup_table(&mut layouter).expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let mut instances = vec![];
        layouter
            .assign_region(
                || "",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let ctx = Context::new(
                        region,
                        ContextParams {
                            max_rows: config.gate().max_rows,
                            num_context_ids: 1,
                            fixed_columns: config.gate().constants.clone(),
                        },
                    );

                    let ecc_chip = config.ecc_chip();
                    let loader = Halo2Loader::new(ecc_chip, ctx);
                    let (prev_instances, acc) = aggregate::<Kzg<Bn256, Bdfg21>>(
                        self.aggregation.succinct_verifying_key(),
                        &loader,
                        self.aggregation.snarks(),
                        self.aggregation.as_proof(),
                    );

                    let ctx = &mut loader.ctx_mut();
                    let mut new_instances = vec![];
                    // accumulator
                    new_instances.extend(flatten_accumulator(acc));
                    // process previous instances
                    const START: usize = 4 * LIMBS;
                    for prev_instance in prev_instances {
                        if self.round == 0 {
                            // we assume we're only aggregating a full merkle tree, so truncate the rest of the merkle mountain range
                            new_instances.extend_from_slice(&prev_instance[START..START + 7]);
                        } else {
                            new_instances.extend_from_slice(&prev_instance[START..]);
                        }
                    }
                    instances = new_instances.iter().map(|a| a.cell().clone()).collect();

                    config.range().finalize(ctx);
                    #[cfg(feature = "display")]
                    loader.ctx_mut().print_stats(&["Range"]);
                    Ok(())
                },
            )
            .unwrap();
        // Expose instances
        for (i, cell) in instances.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instance, i);
        }
        #[cfg(feature = "display")]
        end_timer!(witness_time);
        Ok(())
    }
}
