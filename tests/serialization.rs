use alloy_primitives::{Address, B256, U256};
use kage_types::api_types::{
    ApiErrorResponse, ComplaintResponse, ComplaintStatus, order_access_token_hash,
};
use kage_types::proof_orders::{
    AssignmentTicket, AssignmentTicketClaims, ComplaintEvidenceKind, CreateOrderRequest,
    PreviewCategory, ProofOrderBindings, ReservationOffer, ReservationRequest,
    ReservationRequestClaims,
};
use kage_types::routing::{
    MultiRecipientProof, PROOF_ENVELOPE_SUITE, PreviewResponse, PreviewRoute, RecipientKeyWrap,
    SolverProofDelivery,
};
use uuid::Uuid;

#[test]
fn order_access_token_verifier_has_a_stable_cross_sdk_vector() {
    assert_eq!(
        order_access_token_hash(B256::repeat_byte(0xa1)),
        "0xca33d5250f54387650fe1b53ad805883b083d1bb195da3668a447467e6602737"
            .parse::<B256>()
            .unwrap()
    );
}

#[test]
fn complaint_response_preserves_the_evidence_class() {
    let complaint = ComplaintResponse {
        order_id: Uuid::from_u128(9),
        status: ComplaintStatus::Verified,
        evidence_kind: ComplaintEvidenceKind::NoResponseAfterDisclosure,
        solver_id: Address::repeat_byte(0x33),
        proof_expires_at_secs: 1_800_000_000,
        nullifier_spent: false,
        reason: "solver did not respond".to_owned(),
        created_at_ms: 1_800_000_001_000,
        updated_at_ms: 1_800_000_001_000,
    };
    let encoded = serde_json::to_value(&complaint).unwrap();
    assert_eq!(encoded["evidence_kind"], "no_response_after_disclosure");
    assert_eq!(
        serde_json::from_value::<ComplaintResponse>(encoded).unwrap(),
        complaint
    );
}

#[test]
fn preview_and_multi_recipient_order_round_trip() {
    let route = PreviewRoute {
        solver_id: Address::repeat_byte(0x33),
        min_amount_in: U256::from(1_u64),
        max_amount_in: U256::from(1_000_000_u64),
        encryption_key_id: B256::repeat_byte(0x44),
        encryption_public_key: vec![0x55; 32],
        key_expires_at_ms: 1_800_000_060_000,
    };
    let preview = PreviewResponse {
        preview_id: B256::repeat_byte(0x11),
        chain_id: 31_337,
        token_in: Address::repeat_byte(0x12),
        token_out: Address::repeat_byte(0x13),
        token_in_decimals: 18,
        token_out_decimals: 6,
        amount_in: U256::from(10_u64.pow(18)),
        midpoint_amount_out: U256::from(3_200_000_000_u64),
        confidence_amount_out: U256::from(3_196_800_000_u64),
        oracle_adjustment_bps: 10,
        oracle_adjustment_amount: U256::from(3_200_000_u64),
        valid_until_ms: 1_800_000_010_000,
        recommended_proof_lifetime_seconds: 30,
        minimum_remaining_seconds: 15,
        categories: vec![PreviewCategory {
            id: "major-50".to_owned(),
            fee_bps: 50,
            exact_amount_out: U256::from(3_180_816_000_u64),
            fee_amount: U256::from(15_984_000_u64),
            routes: vec![route.clone()],
        }],
    };
    let recipient = RecipientKeyWrap {
        solver_id: route.solver_id,
        key_id: route.encryption_key_id,
        encapsulated_key: vec![0x66; 32],
        wrapped_key: vec![0x77; 48],
    };
    let request = CreateOrderRequest {
        client_order_id: Uuid::from_u128(9),
        access_token_hash: B256::repeat_byte(0xcc),
        preview_id: preview.preview_id,
        category_id: preview.categories[0].id.clone(),
        domain_hash: B256::repeat_byte(0xdd),
        terms: kage_types::orders::TradeTerms {
            chain_id: preview.chain_id,
            token_in: preview.token_in,
            token_out: preview.token_out,
            amount_in: U256::from(10_u64.pow(18)),
            amount_out: U256::from(3_193_600_000_u64),
            expires_at_ms: preview.valid_until_ms,
        },
        settlement_commitment: B256::repeat_byte(0xbb),
        encrypted_proof: MultiRecipientProof {
            suite: PROOF_ENVELOPE_SUITE.to_owned(),
            nonce: vec![0x88; 24],
            ciphertext: vec![0x99; 64],
            ciphertext_digest: B256::repeat_byte(0xaa),
            recipients: vec![recipient],
        },
    };

    for value in [
        serde_json::to_value(&preview).unwrap(),
        serde_json::to_value(&request).unwrap(),
    ] {
        assert!(value.is_object());
    }
    let encoded = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        serde_json::from_slice::<CreateOrderRequest>(&encoded).unwrap(),
        request
    );
}

#[test]
fn empty_api_error_omits_missing_dependencies() {
    let error = ApiErrorResponse {
        code: "invalid_order".to_owned(),
        message: "invalid order".to_owned(),
        missing: Vec::new(),
    };

    let encoded = serde_json::to_value(error).unwrap();
    assert!(encoded.get("missing").is_none());
}

#[test]
fn reservation_offer_and_delivery_round_trip_without_private_routing_hints() {
    let terms = kage_types::orders::TradeTerms {
        chain_id: 31_337,
        token_in: Address::repeat_byte(1),
        token_out: Address::repeat_byte(2),
        amount_in: U256::from(100),
        amount_out: U256::from(99),
        expires_at_ms: 30_000,
    };
    let bindings = ProofOrderBindings {
        order_id: Uuid::from_u128(10),
        preview_id: B256::repeat_byte(3),
        category_id: "major-50".to_owned(),
        solver_id: Address::repeat_byte(4),
        exact_terms_digest: B256::repeat_byte(5),
        ciphertext_digest: B256::repeat_byte(6),
        proof_expires_at_secs: 30,
    };
    let request = ReservationRequest {
        claims: ReservationRequestClaims {
            bindings: bindings.clone(),
            attempt_nonce: B256::repeat_byte(7),
            requested_at_ms: 1_000,
            attempt_expires_at_ms: 3_000,
        },
        signature: vec![8; 65],
    };
    let offer = ReservationOffer {
        request,
        terms,
        domain_hash: B256::repeat_byte(9),
        fee_bps: 50,
        settlement_commitment: B256::repeat_byte(10),
    };
    let offer_json = serde_json::to_value(&offer).unwrap();
    assert!(offer_json.get("ciphertext").is_none());
    assert!(offer_json.get("available_amount_out").is_none());
    assert_eq!(
        serde_json::from_value::<ReservationOffer>(offer_json).unwrap(),
        offer
    );

    let ticket = AssignmentTicket {
        claims: AssignmentTicketClaims {
            bindings,
            settlement_commitment: offer.settlement_commitment,
            proof_encryption_key_id: B256::repeat_byte(11),
            issued_at_ms: 2_000,
            expires_at_ms: 30_000,
            nonce: B256::repeat_byte(12),
        },
        signature: vec![13; 65],
    };
    let delivery = SolverProofDelivery {
        suite: PROOF_ENVELOPE_SUITE.to_owned(),
        order_id: offer.request.claims.bindings.order_id,
        preview_id: offer.request.claims.bindings.preview_id,
        category_id: offer.request.claims.bindings.category_id.clone(),
        terms,
        domain_hash: offer.domain_hash,
        fee_bps: offer.fee_bps,
        settlement_commitment: offer.settlement_commitment,
        assignment_ticket: ticket,
        nonce: vec![14; 24],
        ciphertext: vec![15; 64],
        ciphertext_digest: offer.request.claims.bindings.ciphertext_digest,
        recipient: RecipientKeyWrap {
            solver_id: offer.request.claims.bindings.solver_id,
            key_id: B256::repeat_byte(11),
            encapsulated_key: vec![16; 32],
            wrapped_key: vec![17; 48],
        },
    };
    let encoded = serde_json::to_vec(&delivery).unwrap();
    assert_eq!(
        serde_json::from_slice::<SolverProofDelivery>(&encoded).unwrap(),
        delivery
    );
}
