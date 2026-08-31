use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::events::OrderEvent;
use crate::identifiers::OrderId;
use crate::proof_orders::ComplaintEvidenceKind;

pub const ORDER_ACCESS_TOKEN_HEADER: &str = "x-order-access-token";
pub const ORDER_ACCESS_TOKEN_HASH_DOMAIN: &[u8] = b"kage-order-access-token/v1";

pub fn order_access_token_hash(token: B256) -> B256 {
    let mut bytes = Vec::with_capacity(ORDER_ACCESS_TOKEN_HASH_DOMAIN.len() + token.len());
    bytes.extend_from_slice(ORDER_ACCESS_TOKEN_HASH_DOMAIN);
    bytes.extend_from_slice(token.as_slice());
    alloy_primitives::keccak256(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrderResponse {
    pub order_id: OrderId,
    pub expires_at_ms: i64,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateComplaintRequest {
    pub nullifier: B256,
    pub salt: B256,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplaintStatus {
    Verified,
    Rejected,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplaintResponse {
    pub order_id: OrderId,
    pub status: ComplaintStatus,
    pub evidence_kind: ComplaintEvidenceKind,
    pub solver_id: Address,
    pub proof_expires_at_secs: u64,
    pub nullifier_spent: bool,
    pub reason: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UserEventClientMessage {
    Subscribe {
        order_id: OrderId,
        access_token: B256,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UserEventServerMessage {
    Subscribed { order_id: OrderId },
    Rejected { order_id: OrderId },
    Event { event: OrderEvent },
}
