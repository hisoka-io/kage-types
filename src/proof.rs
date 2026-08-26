use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentProofV1 {
    pub version: u8,
    pub circuit: String,
    pub proof_system: String,
    pub verifier_target: String,
    pub proof: String,
    pub proof_as_fields: Vec<String>,
    pub public_inputs: Vec<String>,
    pub verification_key_fields: Vec<String>,
    pub verification_key_hash: String,
}
