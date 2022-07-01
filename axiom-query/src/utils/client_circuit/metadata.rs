use anyhow::bail;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ethers_core::types::H256;
use serde::{Deserialize, Serialize};

/// All configuration parameters of an Axiom Client Circuit that are
/// hard-coded into the Verify Compute Circuit (which is an Aggregation Circuit with Universality::Full).
///
/// This metadata is only for a circuit built using `RlcCircuitBuilder`
/// or `BaseCircuitBuilder`, where the circuit _may_ be an aggregation circuit.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct AxiomV2CircuitMetadata {
    /// Version byte for domain separation on version of Axiom client, halo2-lib, snark-verifier (for example if we switch to mv_lookup)
    /// If `version = x`, this should be thought of as Axiom Query v2.x
    pub version: u8,
    /// Number of instances in each instance polynomial
    pub num_instance: Vec<u32>,
    /// Number of challenges to squeeze from transcript after each phase.
    /// This `num_challenge` counts only the challenges used inside the circuit - it excludes challenges that are part of the halo2 system.
    /// The full challenges, which is what `plonk_protocol.num_challenge` stores, is:
    /// ```ignore
    /// [
    ///   my_phase0_challenges,
    ///   ...
    ///   [..my_phasen_challenges, theta],
    ///   [beta, gamma],
    ///   [alpha],
    /// ]
    /// ```
    pub num_challenge: Vec<u8>,

    /// Boolean for whether this is an Aggregation Circuit which has a KZG accumulator in the public instances. If true, it must be the first 12 instances.
    pub is_aggregation: bool,

    // RlcCircuitParams:
    /// The number of advice columns per phase
    pub num_advice_per_phase: Vec<u16>,
    /// The number of special advice columns that have range lookup enabled per phase
    pub num_lookup_advice_per_phase: Vec<u8>,
    /// Number of advice columns for the RLC custom gate
    pub num_rlc_columns: u16,
    /// The number of fixed columns **only** for constants
    pub num_fixed: u8,

    // This is specific to the current Verify Compute Circuit implementation and provided just for data availability:
    /// The maximum number of user outputs. Used to determine where to split off `compute_snark`'s public instances between user outputs and data subqueries.
    /// This does **not** include the old accumulator elliptic curve points if
    /// the `compute_snark` is from an aggregation circuit.
    pub max_outputs: u16,
}

impl AxiomV2CircuitMetadata {
    pub fn encode(&self) -> anyhow::Result<H256> {
        let mut encoded = vec![];
        encoded.write_u8(self.version)?;

        encoded.write_u8(self.num_instance.len().try_into()?)?;
        for &num_instance in &self.num_instance {
            encoded.write_u32::<BigEndian>(num_instance)?;
        }

        let num_phase = self.num_challenge.len();
        if num_phase == 0 {
            bail!("num_challenge must be non-empty")
        }
        encoded.write_u8(num_phase.try_into()?)?;
        for &num_challenge in &self.num_challenge {
            encoded.write_u8(num_challenge)?;
        }

        encoded.write_u8(self.is_aggregation as u8)?;

        // encode RlcCircuitParams:
        if self.num_advice_per_phase.len() > num_phase {
            bail!("num_advice_per_phase must be <= num_phase")
        }
        let mut num_advice_cols = self.num_advice_per_phase.clone();
        num_advice_cols.resize(num_phase, 0);
        for num_advice_col in num_advice_cols {
            encoded.write_u16::<BigEndian>(num_advice_col)?;
        }

        if self.num_lookup_advice_per_phase.len() > num_phase {
            bail!("num_lookup_advice_per_phase must be <= num_phase")
        }
        let mut num_lookup_advice_cols = self.num_lookup_advice_per_phase.clone();
        num_lookup_advice_cols.resize(num_phase, 0);
        for num_lookup_advice_col in num_lookup_advice_cols {
            encoded.write_u8(num_lookup_advice_col)?;
        }

        encoded.write_u16::<BigEndian>(self.num_rlc_columns)?;
        encoded.write_u8(self.num_fixed)?;

        encoded.write_u16::<BigEndian>(self.max_outputs)?;

        if encoded.len() > 32 {
            bail!("circuit metadata cannot be packed into bytes32")
        }
        encoded.resize(32, 0);
        Ok(H256::from_slice(&encoded))
    }
}

pub fn decode_axiom_v2_circuit_metadata(encoded: H256) -> anyhow::Result<AxiomV2CircuitMetadata> {
    let mut reader = &encoded[..];
    let version = reader.read_u8()?;
    if version != 0 {
        bail!("invalid version")
    }
    let num_instance_len = reader.read_u8()? as usize;
    let mut num_instance = Vec::with_capacity(num_instance_len);
    for _ in 0..num_instance_len {
        num_instance.push(reader.read_u32::<BigEndian>()?);
    }
    let num_phase = reader.read_u8()? as usize;
    let mut num_challenge = Vec::with_capacity(num_phase);
    for _ in 0..num_phase {
        num_challenge.push(reader.read_u8()?);
    }

    let is_aggregation = reader.read_u8()?;
    if is_aggregation > 1 {
        bail!("is_aggregation is not boolean");
    }
    let is_aggregation = is_aggregation == 1;

    // decode RlcCircuitParams:
    let mut num_advice_per_phase = Vec::with_capacity(num_phase);
    for _ in 0..num_phase {
        num_advice_per_phase.push(reader.read_u16::<BigEndian>()?);
    }
    let mut num_lookup_advice_per_phase = Vec::with_capacity(num_phase);
    for _ in 0..num_phase {
        num_lookup_advice_per_phase.push(reader.read_u8()?);
    }

    let num_rlc_columns = reader.read_u16::<BigEndian>()?;
    let num_fixed = reader.read_u8()?;

    let max_outputs = reader.read_u16::<BigEndian>()?;

    Ok(AxiomV2CircuitMetadata {
        version,
        num_instance,
        num_challenge,
        num_advice_per_phase,
        num_lookup_advice_per_phase,
        num_rlc_columns,
        num_fixed,
        is_aggregation,
        max_outputs,
    })
}
