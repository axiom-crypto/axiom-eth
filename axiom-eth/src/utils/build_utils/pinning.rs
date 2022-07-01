use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
        flex_gate::MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{Circuit, ProvingKey},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::ScalarField,
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::gen_pk;
use std::{fs::File, io, path::Path};

use crate::{
    rlc::{circuit::RlcCircuitParams, virtual_region::RlcThreadBreakPoints},
    utils::eth_circuit::ETH_LOOKUP_BITS,
};

/// Perhaps `CircuitPinning` and `CircuitParams` are the same thing.
/// For now the distinction is that `CircuitParams` is what is needed
/// in `configure` to build the `Circuit::Config` and the pinning can be
/// derived from that by running `synthesize` during keygen.
/// The difference
pub trait Halo2CircuitPinning: Serialize + Sized + for<'de> Deserialize<'de> {
    type CircuitParams;
    type BreakPoints;
    /// Constructor
    fn new(params: Self::CircuitParams, break_points: Self::BreakPoints) -> Self;
    /// Returns the configuration parameters
    fn params(&self) -> Self::CircuitParams;
    /// Returns break points
    fn break_points(&self) -> Self::BreakPoints;
    /// Degree of the circuit, log_2(number of rows)
    fn k(&self) -> usize;
    /// Loads from a file
    fn from_path<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let p = serde_json::from_reader(File::open(&path)?)?;
        Ok(p)
    }
    /// Writes to file
    fn write<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(File::create(path)?, self)?;
        Ok(())
    }
}

pub trait CircuitPinningInstructions {
    type Pinning: Halo2CircuitPinning;

    fn pinning(&self) -> Self::Pinning;
}

pub trait PinnableCircuit: CircuitPinningInstructions + Sized + Circuit<Fr> {
    /// Reads the proving key for the pre-circuit.
    fn read_pk(
        path: impl AsRef<Path>,
        circuit_params: <Self as Circuit<Fr>>::Params,
    ) -> io::Result<ProvingKey<G1Affine>> {
        snark_verifier_sdk::read_pk::<Self>(path.as_ref(), circuit_params)
    }

    /// Creates the proving key for the pre-circuit if file at `pk_path` is not found.
    /// If a new proving key is created, the new pinning data is written to `pinning_path`.
    fn create_pk(
        &self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
    ) -> anyhow::Result<(ProvingKey<G1Affine>, Self::Pinning)> {
        let circuit_params = self.params();
        if let Ok(pk) = Self::read_pk(pk_path.as_ref(), circuit_params) {
            let pinning = Self::Pinning::from_path(pinning_path.as_ref())?;
            Ok((pk, pinning))
        } else {
            let pk = gen_pk(params, self, Some(pk_path.as_ref()));
            // should only write pinning data if we created a new pkey
            let pinning = self.pinning();
            pinning.write(pinning_path)?;
            Ok((pk, pinning))
        }
    }
}

impl<C> PinnableCircuit for C where C: CircuitPinningInstructions + Sized + Circuit<Fr> {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RlcCircuitPinning {
    pub params: RlcCircuitParams,
    pub break_points: RlcThreadBreakPoints,
}

impl Halo2CircuitPinning for RlcCircuitPinning {
    type CircuitParams = RlcCircuitParams;
    type BreakPoints = RlcThreadBreakPoints;

    fn new(params: Self::CircuitParams, break_points: Self::BreakPoints) -> Self {
        Self { params, break_points }
    }

    fn from_path<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut pinning: Self = serde_json::from_reader(File::open(&path)?)?;
        if pinning.params.base.lookup_bits.is_none() {
            pinning.params.base.lookup_bits = Some(ETH_LOOKUP_BITS);
        }
        Ok(pinning)
    }

    fn params(&self) -> Self::CircuitParams {
        self.params.clone()
    }

    fn break_points(&self) -> RlcThreadBreakPoints {
        self.break_points.clone()
    }

    fn k(&self) -> usize {
        self.params.base.k
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Hash)]
pub struct BaseCircuitPinning {
    pub params: BaseCircuitParams,
    pub break_points: MultiPhaseThreadBreakPoints,
}

impl Halo2CircuitPinning for BaseCircuitPinning {
    type CircuitParams = BaseCircuitParams;
    type BreakPoints = MultiPhaseThreadBreakPoints;

    fn new(params: Self::CircuitParams, break_points: Self::BreakPoints) -> Self {
        Self { params, break_points }
    }

    fn params(&self) -> Self::CircuitParams {
        self.params.clone()
    }

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.break_points.clone()
    }

    fn k(&self) -> usize {
        self.params.k
    }
}

impl<F: ScalarField> CircuitPinningInstructions for BaseCircuitBuilder<F> {
    type Pinning = BaseCircuitPinning;
    fn pinning(&self) -> Self::Pinning {
        let break_points = self.break_points();
        let params = self.params();
        Self::Pinning::new(params, break_points)
    }
}

#[cfg(feature = "aggregation")]
pub mod aggregation {
    use halo2_base::{
        gates::flex_gate::MultiPhaseThreadBreakPoints,
        halo2_proofs::{
            halo2curves::bn256::{Bn256, G1Affine},
            plonk::Circuit,
        },
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use snark_verifier::{pcs::kzg::KzgDecidingKey, verifier::plonk::PlonkProtocol};
    use snark_verifier_sdk::halo2::aggregation::{AggregationCircuit, AggregationConfigParams};

    use super::{CircuitPinningInstructions, Halo2CircuitPinning};

    #[derive(Clone, Debug, Serialize, Deserialize, Default)]
    pub struct AggregationCircuitPinning {
        pub params: AggregationConfigParams,
        pub break_points: MultiPhaseThreadBreakPoints,
    }

    impl Halo2CircuitPinning for AggregationCircuitPinning {
        type CircuitParams = AggregationConfigParams;
        type BreakPoints = MultiPhaseThreadBreakPoints;

        fn new(params: Self::CircuitParams, break_points: Self::BreakPoints) -> Self {
            Self { params, break_points }
        }

        fn params(&self) -> Self::CircuitParams {
            self.params
        }

        fn break_points(&self) -> MultiPhaseThreadBreakPoints {
            self.break_points.clone()
        }

        fn k(&self) -> usize {
            self.params.degree as usize
        }
    }

    impl CircuitPinningInstructions for AggregationCircuit {
        type Pinning = AggregationCircuitPinning;
        fn pinning(&self) -> Self::Pinning {
            let break_points = self.break_points();
            let params = self.params();
            AggregationCircuitPinning::new(params, break_points)
        }
    }

    /// Generic aggregation pinning
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct GenericAggPinning<AggParams> {
        /// Aggregation configuration parameters
        pub params: AggParams,
        /// Number of instances in each instance column
        pub num_instance: Vec<usize>,
        /// The indices of the KZG accumulator in the public instance column(s)
        pub accumulator_indices: Vec<(usize, usize)>,
        /// Aggregate vk hash, if universal aggregation circuit.
        /// * ((i, j), agg_vkey_hash), where the hash is located at (i, j) in the public instance columns
        pub agg_vk_hash_data: Option<((usize, usize), String)>,
        /// g1 generator, g2 generator, s_g2 (s is generator of trusted setup).
        /// Together with domain size `2^k`, this commits to the trusted setup used.
        /// This is all that's needed to verify the final ecpairing check on the KZG proof.
        pub dk: KzgDecidingKey<Bn256>,
        /// Break points. Should only have phase0, so MultiPhase is extraneous.
        pub break_points: MultiPhaseThreadBreakPoints,
    }

    /// Generic aggregation circuit configuration parameters
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct GenericAggParams {
        /// The compiled verification key of each dependency circuit to be aggregated.
        #[serde_as(as = "Vec<crate::utils::snark_verifier::Base64Bytes>")]
        pub to_agg: Vec<PlonkProtocol<G1Affine>>,
        pub agg_params: AggregationConfigParams,
    }

    /// The circuit IDs of the aggregation tree
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct AggTreeId {
        /// Root circuit ID
        pub circuit_id: String,
        /// Children aggregation tree IDs
        pub children: Vec<AggTreeId>,
        /// If the root circuit is a universal aggregation circuit, this is the aggregate vkey hash.
        /// None otherwise.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub aggregate_vk_hash: Option<String>,
    }
}
