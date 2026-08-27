use alloy_primitives::{B256, keccak256};
use serde::{Deserialize, Serialize};

use crate::identifiers::{OrderId, SolverId};
use crate::orders::TradeTerms;

/// Domain for the bytes signed by the orderbook assignment key.
///
/// V1 uses an EIP-191 personal-message signature over
/// [`AssignmentTicketClaimsV1::signing_bytes`]. The solver must recover the
/// configured orderbook signer and must not trust a signer supplied by the
/// request itself.
pub const ASSIGNMENT_TICKET_V1_DOMAIN: &[u8] = b"kage-orderbook/assignment-ticket/v1";
const ASSIGNMENT_ORDER_DIGEST_V1_DOMAIN: &[u8] = b"kage-orderbook/order-digest/v1";

/// Hashes immutable, non-secret trade terms for assignment-ticket binding.
///
/// This must never include or be replaced by the user's order commitment,
/// which is a bearer capability for the orderbook user API.
pub fn assignment_order_digest(terms: &TradeTerms) -> B256 {
    let mut bytes =
        Vec::with_capacity(ASSIGNMENT_ORDER_DIGEST_V1_DOMAIN.len() + 8 + 20 + 20 + 32 + 32 + 8);
    bytes.extend_from_slice(ASSIGNMENT_ORDER_DIGEST_V1_DOMAIN);
    bytes.extend_from_slice(&terms.chain_id.to_be_bytes());
    bytes.extend_from_slice(terms.token_in.as_slice());
    bytes.extend_from_slice(terms.token_out.as_slice());
    bytes.extend_from_slice(&terms.amount_in.to_be_bytes::<32>());
    bytes.extend_from_slice(&terms.amount_out.to_be_bytes::<32>());
    bytes.extend_from_slice(&terms.expires_at_ms.to_be_bytes());
    keccak256(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentTicketClaimsV1 {
    pub order_id: OrderId,
    pub order_version: u64,
    pub solver_id: SolverId,
    pub chain_id: u64,
    /// Digest of immutable public trade terms, never the user's bearer capability.
    pub order_digest: B256,
    pub solver_endpoint: String,
    pub solver_noise_public_key: B256,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: B256,
}

impl AssignmentTicketClaimsV1 {
    /// Canonical, language-independent signing preimage.
    ///
    /// Integer fields are big-endian. UUID, address, hash and key fields use
    /// their fixed-width raw bytes. The only variable-width field is the UTF-8
    /// endpoint, prefixed by an eight-byte big-endian length.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let endpoint = self.solver_endpoint.as_bytes();
        let mut bytes = Vec::with_capacity(
            ASSIGNMENT_TICKET_V1_DOMAIN.len()
                + 16
                + 8
                + 20
                + 8
                + 32
                + 8
                + endpoint.len()
                + 32
                + 8
                + 8
                + 32,
        );
        bytes.extend_from_slice(ASSIGNMENT_TICKET_V1_DOMAIN);
        bytes.extend_from_slice(self.order_id.as_bytes());
        bytes.extend_from_slice(&self.order_version.to_be_bytes());
        bytes.extend_from_slice(self.solver_id.as_slice());
        bytes.extend_from_slice(&self.chain_id.to_be_bytes());
        bytes.extend_from_slice(self.order_digest.as_slice());
        bytes.extend_from_slice(&(endpoint.len() as u64).to_be_bytes());
        bytes.extend_from_slice(endpoint);
        bytes.extend_from_slice(self.solver_noise_public_key.as_slice());
        bytes.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        bytes.extend_from_slice(self.nonce.as_slice());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentTicketV1 {
    pub claims: AssignmentTicketClaimsV1,
    /// A 65-byte recoverable EIP-191 signature encoded as JSON bytes.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverAssignmentV1 {
    pub ticket: AssignmentTicketV1,
}
