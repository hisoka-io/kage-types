use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverProfile {
    pub noise_public_key: B256,
    pub active: bool,
}
