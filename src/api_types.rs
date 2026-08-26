use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use crate::events::OrderEvent;
use crate::identifiers::{OrderCommitment, OrderId, SettlementBinding, TokenAddress, TxHash};

pub const ORDER_COMMITMENT_HEADER: &str = "x-order-commitment";
pub const SOLVER_ADDRESS_HEADER: &str = "x-solver-address";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrderRequest {
    pub order_commitment: OrderCommitment,
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub amount_in: U256,
    pub amount_out: U256,
    pub ttl_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrderResponse {
    pub order_id: OrderId,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedProofRequest {
    pub ciphertext: Vec<u8>,
    pub settlement_binding: SettlementBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverProofDeliveryV1 {
    pub order_id: OrderId,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionStartedRequest {
    pub tx_hash: TxHash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementRequest {
    pub tx_hash: TxHash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UserEventClientMessage {
    Subscribe {
        order_id: OrderId,
        order_commitment: OrderCommitment,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UserEventServerMessage {
    Subscribed { order_id: OrderId },
    Rejected { order_id: OrderId },
    Event { event: OrderEvent },
}
