use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use crate::identifiers::TokenAddress;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TradeTerms {
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub amount_in: U256,
    pub amount_out: U256,
    pub expires_at_ms: i64,
}
