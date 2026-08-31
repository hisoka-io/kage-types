use alloy_primitives::{Address, B256, U256, keccak256};
use kage_types::{
    identifiers::OrderId,
    orders::TradeTerms,
    proof_orders::{
        ASSIGNMENT_TICKET_DOMAIN, AssignmentTicket, AssignmentTicketClaims,
        PROOF_ACCEPTANCE_ACK_DOMAIN, PROOF_REJECTION_ACK_DOMAIN, ProofAcceptanceAck,
        ProofAcceptanceClaims, ProofOrderBindings, ProofOrderState, ProofRejectionClaims,
        ProofRejectionReason, RESERVATION_ACK_DOMAIN, RESERVATION_DECLINE_DOMAIN,
        RecipientSetError, ReservationAck, ReservationAckClaims, ReservationDeclineClaims,
        ReservationDeclineReason, assignment_ticket_digest, exact_terms_digest,
        proof_ciphertext_aad, proof_envelope_aad, proof_recipient_aad, settlement_commitment,
        validate_recipient_set,
    },
    routing::{MAX_PROOF_RECIPIENTS, MultiRecipientProof, PROOF_ENVELOPE_SUITE, RecipientKeyWrap},
};

type ReservationMutation = Box<dyn Fn(&mut ReservationAckClaims)>;
type AssignmentMutation = Box<dyn Fn(&mut AssignmentTicketClaims)>;

fn terms() -> TradeTerms {
    TradeTerms {
        chain_id: 31_337,
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        amount_in: U256::from(1_000_u64),
        amount_out: U256::from(2_000_u64),
        expires_at_ms: 1_800_000_030_000,
    }
}

fn bindings() -> ProofOrderBindings {
    ProofOrderBindings {
        order_id: OrderId::from_u128(1),
        preview_id: B256::repeat_byte(2),
        category_id: "major-50".to_owned(),
        solver_id: Address::repeat_byte(3),
        exact_terms_digest: exact_terms_digest(&terms(), B256::repeat_byte(4)),
        ciphertext_digest: B256::repeat_byte(5),
        proof_expires_at_secs: 1_800_000_030,
    }
}

fn recipient(solver: u8, key: u8) -> RecipientKeyWrap {
    RecipientKeyWrap {
        solver_id: Address::repeat_byte(solver),
        key_id: B256::repeat_byte(key),
        encapsulated_key: vec![6; 32],
        wrapped_key: vec![7; 48],
    }
}

fn proof(recipients: Vec<RecipientKeyWrap>) -> MultiRecipientProof {
    MultiRecipientProof {
        suite: PROOF_ENVELOPE_SUITE.to_owned(),
        nonce: vec![8; 24],
        ciphertext: vec![9; 64],
        ciphertext_digest: keccak256([9; 64]),
        recipients,
    }
}

#[test]
fn recipient_validation_supports_multiple_solvers_and_rejects_duplicates() {
    assert_eq!(MAX_PROOF_RECIPIENTS, 8);
    assert!(validate_recipient_set(&proof(vec![recipient(1, 2), recipient(3, 4)])).is_ok());
    assert_eq!(
        validate_recipient_set(&proof(vec![recipient(1, 2), recipient(1, 3)])),
        Err(RecipientSetError::DuplicateSolver)
    );
    assert_eq!(
        validate_recipient_set(&proof(vec![recipient(1, 2), recipient(1, 2)])),
        Err(RecipientSetError::DuplicateSolverKey)
    );
    assert_eq!(
        validate_recipient_set(&proof(Vec::new())),
        Err(RecipientSetError::Empty)
    );
}

#[test]
fn immutable_binding_mutations_change_signed_bytes() {
    let original = ReservationAckClaims {
        bindings: bindings(),
        attempt_nonce: B256::repeat_byte(6),
        accepted_at_ms: 1_800_000_001_000,
    };
    let original_bytes = original.signing_bytes();
    let mutations: Vec<ReservationMutation> = vec![
        Box::new(|value| value.bindings.order_id = OrderId::from_u128(2)),
        Box::new(|value| value.bindings.preview_id = B256::repeat_byte(3)),
        Box::new(|value| value.bindings.category_id.push('x')),
        Box::new(|value| value.bindings.solver_id = Address::repeat_byte(4)),
        Box::new(|value| value.bindings.exact_terms_digest = B256::repeat_byte(7)),
        Box::new(|value| value.bindings.ciphertext_digest = B256::repeat_byte(8)),
        Box::new(|value| value.bindings.proof_expires_at_secs += 1),
        Box::new(|value| value.attempt_nonce = B256::repeat_byte(9)),
        Box::new(|value| value.accepted_at_ms += 1),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_ne!(changed.signing_bytes(), original_bytes);
    }
}

#[test]
fn signed_evidence_domains_are_distinct() {
    let reservation = ReservationAckClaims {
        bindings: bindings(),
        attempt_nonce: B256::repeat_byte(6),
        accepted_at_ms: 1_800_000_001_000,
    };
    let decline = ReservationDeclineClaims {
        bindings: reservation.bindings.clone(),
        attempt_nonce: reservation.attempt_nonce,
        reason: ReservationDeclineReason::Busy,
        declined_at_ms: reservation.accepted_at_ms,
    };
    let acceptance = ProofAcceptanceClaims {
        bindings: reservation.bindings.clone(),
        assignment_ticket_digest: B256::repeat_byte(10),
        settlement_commitment: B256::repeat_byte(11),
        accepted_at_ms: reservation.accepted_at_ms,
    };
    let rejection = ProofRejectionClaims {
        bindings: reservation.bindings.clone(),
        assignment_ticket_digest: acceptance.assignment_ticket_digest,
        reason: ProofRejectionReason::InvalidProof,
        rejected_at_ms: acceptance.accepted_at_ms,
    };
    assert!(
        reservation
            .signing_bytes()
            .starts_with(RESERVATION_ACK_DOMAIN)
    );
    assert!(
        decline
            .signing_bytes()
            .starts_with(RESERVATION_DECLINE_DOMAIN)
    );
    assert!(
        acceptance
            .signing_bytes()
            .starts_with(PROOF_ACCEPTANCE_ACK_DOMAIN)
    );
    assert!(
        rejection
            .signing_bytes()
            .starts_with(PROOF_REJECTION_ACK_DOMAIN)
    );
    assert_ne!(reservation.signing_bytes(), decline.signing_bytes());
    assert_ne!(acceptance.signing_bytes(), rejection.signing_bytes());
}

#[test]
fn assignment_ticket_binds_every_required_field() {
    let original = AssignmentTicketClaims {
        bindings: bindings(),
        settlement_commitment: B256::repeat_byte(11),
        proof_encryption_key_id: B256::repeat_byte(12),
        issued_at_ms: 1_800_000_001_000,
        expires_at_ms: 1_800_000_020_000,
        nonce: B256::repeat_byte(13),
    };
    let original_bytes = original.signing_bytes();
    let mutations: Vec<AssignmentMutation> = vec![
        Box::new(|value| value.bindings.category_id.push('x')),
        Box::new(|value| value.bindings.exact_terms_digest = B256::repeat_byte(14)),
        Box::new(|value| value.bindings.ciphertext_digest = B256::repeat_byte(15)),
        Box::new(|value| value.bindings.proof_expires_at_secs += 1),
        Box::new(|value| value.settlement_commitment = B256::repeat_byte(16)),
        Box::new(|value| value.proof_encryption_key_id = B256::repeat_byte(17)),
        Box::new(|value| value.issued_at_ms += 1),
        Box::new(|value| value.expires_at_ms += 1),
        Box::new(|value| value.nonce = B256::repeat_byte(18)),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_ne!(changed.signing_bytes(), original_bytes);
    }
    assert!(original_bytes.starts_with(ASSIGNMENT_TICKET_DOMAIN));
    assert!(
        !original_bytes
            .windows("solver.test".len())
            .any(|value| value == b"solver.test")
    );
}

#[test]
fn proof_order_transition_table_is_monotonic_and_acceptance_is_irreversible() {
    use ProofOrderState::*;
    assert!(Submitted.can_transition_to(ReservationPending));
    assert!(ReservationPending.can_transition_to(Assigned));
    assert!(Assigned.can_transition_to(ProofDelivered));
    assert!(ProofDelivered.can_transition_to(ProofAccepted));
    assert!(ProofAccepted.can_transition_to(Expired));
    assert!(Expired.can_transition_to(ComplaintVerified));
    assert!(ComplaintVerified.can_transition_to(Closed));

    for forbidden in [
        Submitted,
        ReservationPending,
        Assigned,
        ProofDelivered,
        ProofRejected,
    ] {
        assert!(!ProofAccepted.can_transition_to(forbidden));
    }
    assert!(!ProofAccepted.can_transition_to(ProofAccepted));
    assert!(!Closed.can_transition_to(Submitted));
    assert!(Closed.is_terminal());
}

#[test]
fn exact_terms_and_envelope_have_stable_golden_vectors() {
    let digest = exact_terms_digest(&terms(), B256::repeat_byte(4));
    assert_eq!(
        digest,
        "0x1599775942ac5848da9914f3fb7d9ab21769c8965b32c869c10bfe3bd82d1119"
            .parse::<B256>()
            .unwrap()
    );
    let ciphertext_aad = proof_ciphertext_aad(
        OrderId::from_u128(1),
        B256::repeat_byte(2),
        "major-50",
        digest,
        1_800_000_030,
    );
    let aad = proof_envelope_aad(
        OrderId::from_u128(1),
        B256::repeat_byte(2),
        "major-50",
        digest,
        1_800_000_030,
        B256::repeat_byte(5),
    );
    assert_eq!(&aad[..ciphertext_aad.len()], ciphertext_aad);
    assert_eq!(
        keccak256(&aad),
        "0xdab7ed00057076792930e90fa3c922e21d9e4c12a427e71caaa4539802c49c34"
            .parse::<B256>()
            .unwrap()
    );
    let recipient_aad = proof_recipient_aad(
        OrderId::from_u128(1),
        B256::repeat_byte(2),
        "major-50",
        digest,
        1_800_000_030,
        B256::repeat_byte(5),
        Address::repeat_byte(6),
        B256::repeat_byte(7),
    );
    assert_eq!(&recipient_aad[..aad.len()], aad);

    let reservation = ReservationAck {
        claims: ReservationAckClaims {
            bindings: bindings(),
            attempt_nonce: B256::repeat_byte(6),
            accepted_at_ms: 1_800_000_001_000,
        },
        signature: vec![7; 65],
    };
    let ticket = AssignmentTicket {
        claims: AssignmentTicketClaims {
            bindings: bindings(),
            settlement_commitment: B256::repeat_byte(11),
            proof_encryption_key_id: B256::repeat_byte(12),
            issued_at_ms: 1_800_000_001_000,
            expires_at_ms: 1_800_000_020_000,
            nonce: B256::repeat_byte(13),
        },
        signature: vec![14; 65],
    };
    let acceptance = ProofAcceptanceAck {
        claims: ProofAcceptanceClaims {
            bindings: bindings(),
            assignment_ticket_digest: assignment_ticket_digest(&ticket),
            settlement_commitment: B256::repeat_byte(11),
            accepted_at_ms: 1_800_000_002_000,
        },
        signature: vec![15; 65],
    };
    let commitment = settlement_commitment(
        B256::repeat_byte(4),
        31_337,
        Address::repeat_byte(16),
        B256::repeat_byte(17),
        B256::repeat_byte(18),
    );
    assert_eq!(
        keccak256(reservation.claims.signing_bytes()),
        "0xd07b215a4097da613569f4600f375cd7710c4409554bbd9ddd4d8727a2872475"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        assignment_ticket_digest(&ticket),
        "0x0811a769381008b4dcb82f7a45d6ce826a36887eaf1e966856f5f09c902ec1f3"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        keccak256(acceptance.claims.signing_bytes()),
        "0x1a19f7ec1faa75ccd2d270330d617845ee3ee874e0b3e28630aa65c58ac41397"
            .parse::<B256>()
            .unwrap()
    );
    assert_eq!(
        commitment,
        "0x80639792542eb62e4e690c8ead38c7c6038eee29922438f0b7ad6082fd974992"
            .parse::<B256>()
            .unwrap()
    );

    let encoded = serde_json::to_vec(&reservation).unwrap();
    assert_eq!(
        serde_json::from_slice::<ReservationAck>(&encoded).unwrap(),
        reservation
    );
    let encoded = serde_json::to_vec(&ticket).unwrap();
    assert_eq!(
        serde_json::from_slice::<AssignmentTicket>(&encoded).unwrap(),
        ticket
    );
    let encoded = serde_json::to_vec(&acceptance).unwrap();
    assert_eq!(
        serde_json::from_slice::<ProofAcceptanceAck>(&encoded).unwrap(),
        acceptance
    );
}
