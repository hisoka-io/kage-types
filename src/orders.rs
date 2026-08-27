use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use crate::identifiers::{OrderId, SolverId, TokenAddress};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderV1 {
    pub id: OrderId,
    pub state: OrderState,
    pub version: u64,
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub amount_in: U256,
    pub amount_out: U256,
    pub expires_at_ms: Option<i64>,
    pub solver: Option<SolverId>,
    pub solver_noise_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverJobV1 {
    pub id: OrderId,
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub amount_in: U256,
    pub amount_out: U256,
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderState {
    Created,
    Validated,
    Reserving,
    Assigned,
    AwaitingUserProof,
    Expired,
}

impl OrderState {
    pub fn is_terminal(self) -> bool {
        self == Self::Expired
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TradeTerms {
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub amount_in: U256,
    pub amount_out: U256,
    pub expires_at_ms: i64,
}
