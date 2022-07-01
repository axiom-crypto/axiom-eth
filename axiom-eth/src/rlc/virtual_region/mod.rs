use halo2_base::gates::flex_gate::{MultiPhaseThreadBreakPoints, ThreadBreakPoints};
use serde::{Deserialize, Serialize};

pub mod manager;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RlcThreadBreakPoints {
    pub base: MultiPhaseThreadBreakPoints,
    pub rlc: ThreadBreakPoints,
}
