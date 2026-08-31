use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};

use crate::identifiers::{EncryptionKeyId, PreviewId, SolverId, TokenAddress};
use crate::orders::TradeTerms;
use crate::proof::IntentProof;
use crate::proof_orders::{AssignmentTicket, PreviewCategory};

pub const PROOF_ENVELOPE_SUITE: &str = "HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305+XCHACHA20POLY1305";
pub const MAX_PROOF_RECIPIENTS: usize = 8;
pub const HPKE_INFO: &[u8] = b"kage-proof-key-wrap/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverMarket {
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub min_amount_in: U256,
    pub max_amount_in: U256,
    /// Live output-token liquidity available for new reservations. This is an
    /// internal routing hint and is never returned in a public preview route.
    pub available_amount_out: U256,
    pub minimum_margin_bps: u16,
}

/// Runtime routing hints published through an authenticated solver session.
/// A solver must still re-check price and inventory for every order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverCapabilities {
    pub revision: u64,
    pub max_in_flight: u16,
    pub encryption_key_id: EncryptionKeyId,
    pub encryption_public_key: Vec<u8>,
    pub key_expires_at_ms: i64,
    pub markets: Vec<SolverMarket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreviewRequest {
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub amount_in: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreviewRoute {
    pub solver_id: SolverId,
    pub min_amount_in: U256,
    pub max_amount_in: U256,
    pub encryption_key_id: EncryptionKeyId,
    pub encryption_public_key: Vec<u8>,
    pub key_expires_at_ms: i64,
}

/// Fixed-point pricing and category-scoped live solver routes captured from
/// one oracle snapshot. Internal oracle and solver-margin inputs are omitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreviewResponse {
    pub preview_id: PreviewId,
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
    pub token_in_decimals: u8,
    pub token_out_decimals: u8,
    pub amount_in: U256,
    /// Midpoint output before confidence adjustment or solver fee.
    pub midpoint_amount_out: U256,
    /// Output after oracle confidence adjustment and before solver fee.
    pub confidence_amount_out: U256,
    pub oracle_adjustment_bps: u16,
    pub oracle_adjustment_amount: U256,
    pub valid_until_ms: i64,
    /// Operator-recommended lifetime for a proof generated from this preview.
    pub recommended_proof_lifetime_seconds: u32,
    /// Proofs must have strictly more than this much lifetime at admission.
    pub minimum_remaining_seconds: u32,
    pub categories: Vec<PreviewCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientKeyWrap {
    pub solver_id: SolverId,
    pub key_id: EncryptionKeyId,
    /// RFC 9180 KEM output (`enc`).
    pub encapsulated_key: Vec<u8>,
    /// HPKE ciphertext containing the 32-byte proof content-encryption key.
    pub wrapped_key: Vec<u8>,
}

/// One large authenticated ciphertext and one small HPKE key wrap per solver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiRecipientProof {
    pub suite: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphertext_digest: B256,
    pub recipients: Vec<RecipientKeyWrap>,
}

/// The proof-order delivery used after a signed reservation is accepted.
/// It carries the category/domain bindings and canonical assignment ticket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverProofDelivery {
    pub suite: String,
    pub order_id: crate::identifiers::OrderId,
    pub preview_id: PreviewId,
    pub category_id: String,
    pub terms: TradeTerms,
    pub domain_hash: B256,
    pub fee_bps: u16,
    pub settlement_commitment: B256,
    pub assignment_ticket: AssignmentTicket,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphertext_digest: B256,
    pub recipient: RecipientKeyWrap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedIntentPayload {
    pub proof: IntentProof,
    pub settlement_salt: B256,
}
