use std::collections::HashSet;

use alloy_primitives::{Address, B256, U256, keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    identifiers::{
        EncryptionKeyId, OrderAccessTokenHash, OrderId, PreviewId, SolverId, TokenAddress,
    },
    orders::TradeTerms,
    routing::{MAX_PROOF_RECIPIENTS, MultiRecipientProof, PreviewRoute},
};

pub type FeeCategoryId = String;

pub const EXACT_TERMS_DIGEST_DOMAIN: &[u8] = b"kage-proof-order/exact-terms/v1";
pub const ENVELOPE_AAD_DOMAIN: &[u8] = b"kage-proof-order/envelope-aad/v1";
pub const RESERVATION_REQUEST_DOMAIN: &[u8] = b"kage-proof-order/reservation-request/v1";
pub const RESERVATION_ACK_DOMAIN: &[u8] = b"kage-proof-order/reservation-ack/v1";
pub const RESERVATION_DECLINE_DOMAIN: &[u8] = b"kage-proof-order/reservation-decline/v1";
pub const PROOF_ACCEPTANCE_ACK_DOMAIN: &[u8] = b"kage-proof-order/proof-acceptance/v1";
pub const PROOF_REJECTION_ACK_DOMAIN: &[u8] = b"kage-proof-order/proof-rejection/v1";
pub const ASSIGNMENT_TICKET_DOMAIN: &[u8] = b"kage-orderbook/assignment-ticket/v2";
pub const ASSIGNMENT_TICKET_DIGEST_DOMAIN: &[u8] = b"kage-orderbook/assignment-ticket-digest/v2";
pub const SETTLEMENT_COMMITMENT_DOMAIN: &[u8] = b"kage-proof-order/settlement-commitment/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeCategoryMarket {
    pub chain_id: u64,
    pub token_in: TokenAddress,
    pub token_out: TokenAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeCategory {
    pub id: FeeCategoryId,
    pub fee_bps: u16,
    pub markets: Vec<FeeCategoryMarket>,
    pub solver_ids: Vec<SolverId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreviewCategory {
    pub id: FeeCategoryId,
    pub fee_bps: u16,
    pub exact_amount_out: U256,
    pub fee_amount: U256,
    pub routes: Vec<PreviewRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrderRequest {
    pub client_order_id: OrderId,
    pub access_token_hash: OrderAccessTokenHash,
    pub preview_id: PreviewId,
    pub category_id: FeeCategoryId,
    pub terms: TradeTerms,
    pub domain_hash: B256,
    pub settlement_commitment: B256,
    pub encrypted_proof: MultiRecipientProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOrderBindings {
    pub order_id: OrderId,
    pub preview_id: PreviewId,
    pub category_id: FeeCategoryId,
    pub solver_id: SolverId,
    pub exact_terms_digest: B256,
    pub ciphertext_digest: B256,
    pub proof_expires_at_secs: u64,
}

impl ProofOrderBindings {
    fn append_canonical_bytes(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.order_id.as_bytes());
        bytes.extend_from_slice(self.preview_id.as_slice());
        append_string(bytes, &self.category_id);
        bytes.extend_from_slice(self.solver_id.as_slice());
        bytes.extend_from_slice(self.exact_terms_digest.as_slice());
        bytes.extend_from_slice(self.ciphertext_digest.as_slice());
        bytes.extend_from_slice(&self.proof_expires_at_secs.to_be_bytes());
    }
}

pub fn exact_terms_digest(terms: &TradeTerms, domain_hash: B256) -> B256 {
    let mut bytes =
        Vec::with_capacity(EXACT_TERMS_DIGEST_DOMAIN.len() + 32 + 8 + 20 + 20 + 32 + 32 + 8);
    bytes.extend_from_slice(EXACT_TERMS_DIGEST_DOMAIN);
    bytes.extend_from_slice(domain_hash.as_slice());
    bytes.extend_from_slice(&terms.chain_id.to_be_bytes());
    bytes.extend_from_slice(terms.token_in.as_slice());
    bytes.extend_from_slice(terms.token_out.as_slice());
    bytes.extend_from_slice(&terms.amount_in.to_be_bytes::<32>());
    bytes.extend_from_slice(&terms.amount_out.to_be_bytes::<32>());
    bytes.extend_from_slice(&terms.expires_at_ms.to_be_bytes());
    keccak256(bytes)
}

pub fn settlement_commitment(
    domain_hash: B256,
    chain_id: u64,
    darkpool: Address,
    nullifier: B256,
    salt: B256,
) -> B256 {
    let mut bytes = Vec::with_capacity(SETTLEMENT_COMMITMENT_DOMAIN.len() + 32 + 8 + 20 + 32 + 32);
    bytes.extend_from_slice(SETTLEMENT_COMMITMENT_DOMAIN);
    bytes.extend_from_slice(domain_hash.as_slice());
    bytes.extend_from_slice(&chain_id.to_be_bytes());
    bytes.extend_from_slice(darkpool.as_slice());
    bytes.extend_from_slice(nullifier.as_slice());
    bytes.extend_from_slice(salt.as_slice());
    keccak256(bytes)
}

pub fn proof_envelope_aad(
    order_id: OrderId,
    preview_id: PreviewId,
    category_id: &str,
    exact_terms_digest: B256,
    proof_expires_at_secs: u64,
    ciphertext_digest: B256,
) -> Vec<u8> {
    let mut bytes = proof_ciphertext_aad(
        order_id,
        preview_id,
        category_id,
        exact_terms_digest,
        proof_expires_at_secs,
    );
    bytes.extend_from_slice(ciphertext_digest.as_slice());
    bytes
}

/// Authenticated context for the one shared XChaCha20-Poly1305 ciphertext.
/// The ciphertext digest is appended only after encryption when constructing
/// [`proof_envelope_aad`] for the recipient key wraps.
pub fn proof_ciphertext_aad(
    order_id: OrderId,
    preview_id: PreviewId,
    category_id: &str,
    exact_terms_digest: B256,
    proof_expires_at_secs: u64,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(ENVELOPE_AAD_DOMAIN.len() + 16 + 32 + 8 + category_id.len() + 32 + 8);
    bytes.extend_from_slice(ENVELOPE_AAD_DOMAIN);
    bytes.extend_from_slice(order_id.as_bytes());
    bytes.extend_from_slice(preview_id.as_slice());
    append_string(&mut bytes, category_id);
    bytes.extend_from_slice(exact_terms_digest.as_slice());
    bytes.extend_from_slice(&proof_expires_at_secs.to_be_bytes());
    bytes
}

#[allow(clippy::too_many_arguments)]
pub fn proof_recipient_aad(
    order_id: OrderId,
    preview_id: PreviewId,
    category_id: &str,
    exact_terms_digest: B256,
    proof_expires_at_secs: u64,
    ciphertext_digest: B256,
    solver_id: SolverId,
    key_id: EncryptionKeyId,
) -> Vec<u8> {
    let mut bytes = proof_envelope_aad(
        order_id,
        preview_id,
        category_id,
        exact_terms_digest,
        proof_expires_at_secs,
        ciphertext_digest,
    );
    bytes.extend_from_slice(solver_id.as_slice());
    bytes.extend_from_slice(key_id.as_slice());
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientSetError {
    Empty,
    TooMany,
    ZeroSolver,
    ZeroKeyId,
    DuplicateSolver,
    DuplicateSolverKey,
}

pub fn validate_recipient_set(proof: &MultiRecipientProof) -> Result<(), RecipientSetError> {
    if proof.recipients.is_empty() {
        return Err(RecipientSetError::Empty);
    }
    if proof.recipients.len() > MAX_PROOF_RECIPIENTS {
        return Err(RecipientSetError::TooMany);
    }
    let mut solvers = HashSet::with_capacity(proof.recipients.len());
    let mut solver_keys = HashSet::with_capacity(proof.recipients.len());
    for recipient in &proof.recipients {
        if recipient.solver_id == Address::ZERO {
            return Err(RecipientSetError::ZeroSolver);
        }
        if recipient.key_id == B256::ZERO {
            return Err(RecipientSetError::ZeroKeyId);
        }
        if !solver_keys.insert((recipient.solver_id, recipient.key_id)) {
            return Err(RecipientSetError::DuplicateSolverKey);
        }
        if !solvers.insert(recipient.solver_id) {
            return Err(RecipientSetError::DuplicateSolver);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationRequestClaims {
    pub bindings: ProofOrderBindings,
    pub attempt_nonce: B256,
    pub requested_at_ms: i64,
    pub attempt_expires_at_ms: i64,
}

impl ReservationRequestClaims {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(RESERVATION_REQUEST_DOMAIN);
        self.bindings.append_canonical_bytes(&mut bytes);
        bytes.extend_from_slice(self.attempt_nonce.as_slice());
        bytes.extend_from_slice(&self.requested_at_ms.to_be_bytes());
        bytes.extend_from_slice(&self.attempt_expires_at_ms.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationRequest {
    pub claims: ReservationRequestClaims,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationOffer {
    pub request: ReservationRequest,
    pub terms: TradeTerms,
    pub domain_hash: B256,
    pub fee_bps: u16,
    pub settlement_commitment: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationAckClaims {
    pub bindings: ProofOrderBindings,
    pub attempt_nonce: B256,
    pub accepted_at_ms: i64,
}

impl ReservationAckClaims {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(RESERVATION_ACK_DOMAIN);
        self.bindings.append_canonical_bytes(&mut bytes);
        bytes.extend_from_slice(self.attempt_nonce.as_slice());
        bytes.extend_from_slice(&self.accepted_at_ms.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationAck {
    pub claims: ReservationAckClaims,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReservationDeclineReason {
    UnsupportedMarket,
    AmountOutOfRange,
    InsufficientLiquidity,
    PricingUnavailable,
    Unprofitable,
    Busy,
    ExpiryTooClose,
    InternalSafetyCheck,
}

impl ReservationDeclineReason {
    fn canonical_tag(self) -> u8 {
        match self {
            Self::UnsupportedMarket => 0,
            Self::AmountOutOfRange => 1,
            Self::InsufficientLiquidity => 2,
            Self::PricingUnavailable => 3,
            Self::Unprofitable => 4,
            Self::Busy => 5,
            Self::ExpiryTooClose => 6,
            Self::InternalSafetyCheck => 7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationDeclineClaims {
    pub bindings: ProofOrderBindings,
    pub attempt_nonce: B256,
    pub reason: ReservationDeclineReason,
    pub declined_at_ms: i64,
}

impl ReservationDeclineClaims {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(RESERVATION_DECLINE_DOMAIN);
        self.bindings.append_canonical_bytes(&mut bytes);
        bytes.extend_from_slice(self.attempt_nonce.as_slice());
        bytes.push(self.reason.canonical_tag());
        bytes.extend_from_slice(&self.declined_at_ms.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationDecline {
    pub claims: ReservationDeclineClaims,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentTicketClaims {
    pub bindings: ProofOrderBindings,
    pub settlement_commitment: B256,
    pub proof_encryption_key_id: EncryptionKeyId,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: B256,
}

impl AssignmentTicketClaims {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ASSIGNMENT_TICKET_DOMAIN);
        self.bindings.append_canonical_bytes(&mut bytes);
        bytes.extend_from_slice(self.settlement_commitment.as_slice());
        bytes.extend_from_slice(self.proof_encryption_key_id.as_slice());
        bytes.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        bytes.extend_from_slice(self.nonce.as_slice());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentTicket {
    pub claims: AssignmentTicketClaims,
    pub signature: Vec<u8>,
}

pub fn assignment_ticket_digest(ticket: &AssignmentTicket) -> B256 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ASSIGNMENT_TICKET_DIGEST_DOMAIN);
    bytes.extend_from_slice(&ticket.claims.signing_bytes());
    bytes.extend_from_slice(&ticket.signature);
    keccak256(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofAcceptanceClaims {
    pub bindings: ProofOrderBindings,
    pub assignment_ticket_digest: B256,
    pub settlement_commitment: B256,
    pub accepted_at_ms: i64,
}

impl ProofAcceptanceClaims {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PROOF_ACCEPTANCE_ACK_DOMAIN);
        self.bindings.append_canonical_bytes(&mut bytes);
        bytes.extend_from_slice(self.assignment_ticket_digest.as_slice());
        bytes.extend_from_slice(self.settlement_commitment.as_slice());
        bytes.extend_from_slice(&self.accepted_at_ms.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofAcceptanceAck {
    pub claims: ProofAcceptanceClaims,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofRejectionReason {
    InvalidEnvelope,
    InvalidCommitment,
    InvalidProofEncoding,
    InvalidProof,
    TermsMismatch,
    DomainMismatch,
    Expired,
    StaleRoot,
    InvalidComplianceKey,
    PricingUnsafe,
    NullifierAlreadySpent,
}

impl ProofRejectionReason {
    fn canonical_tag(self) -> u8 {
        match self {
            Self::InvalidEnvelope => 0,
            Self::InvalidCommitment => 1,
            Self::InvalidProofEncoding => 2,
            Self::InvalidProof => 3,
            Self::TermsMismatch => 4,
            Self::DomainMismatch => 5,
            Self::Expired => 6,
            Self::StaleRoot => 7,
            Self::InvalidComplianceKey => 8,
            Self::PricingUnsafe => 9,
            Self::NullifierAlreadySpent => 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofRejectionClaims {
    pub bindings: ProofOrderBindings,
    pub assignment_ticket_digest: B256,
    pub reason: ProofRejectionReason,
    pub rejected_at_ms: i64,
}

impl ProofRejectionClaims {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PROOF_REJECTION_ACK_DOMAIN);
        self.bindings.append_canonical_bytes(&mut bytes);
        bytes.extend_from_slice(self.assignment_ticket_digest.as_slice());
        bytes.push(self.reason.canonical_tag());
        bytes.extend_from_slice(&self.rejected_at_ms.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofRejectionAck {
    pub claims: ProofRejectionClaims,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum SolverProofDecisionRequest {
    ProofAccepted { acceptance: ProofAcceptanceAck },
    ProofRejected { rejection: ProofRejectionAck },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofOrderState {
    Submitted,
    ReservationPending,
    Assigned,
    ProofDelivered,
    ProofAccepted,
    ProofRejected,
    Expired,
    ComplaintVerified,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOrderResponse {
    pub order_id: OrderId,
    pub state: ProofOrderState,
    pub version: u64,
    pub proof_expires_at_ms: i64,
}

impl ProofOrderState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use ProofOrderState::*;
        matches!(
            (self, next),
            (Submitted, ReservationPending | Expired | Closed)
                | (ReservationPending, Assigned | Expired | Closed)
                | (Assigned, ProofDelivered | Expired | Closed)
                | (
                    ProofDelivered,
                    ProofAccepted | ProofRejected | Expired | Closed
                )
                | (ProofAccepted, Expired | Closed)
                | (ProofRejected, Expired | Closed)
                | (Expired, ComplaintVerified | Closed)
                | (ComplaintVerified, Closed)
        )
    }

    pub fn is_terminal(self) -> bool {
        self == Self::Closed
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplaintEvidenceKind {
    NoResponseAfterDisclosure,
    AcceptedNotSettled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplaintLifecycleStatus {
    Submitted,
    Verified,
    Rejected,
    Resolved,
}

fn append_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
