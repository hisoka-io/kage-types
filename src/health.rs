use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    pub ready: bool,
    pub pricing: bool,
    pub registry: bool,
    pub solver: bool,
    pub chain: bool,
    pub actor: bool,
    pub missing: Vec<String>,
}
