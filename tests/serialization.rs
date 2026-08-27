use alloy_primitives::{Address, B256, U256};
use kage_types::api_types::{
    ApiErrorResponse, CreateOrderRequest, DirectProofRequestV1, DirectProofResponseV1,
    DirectProofStatusV1,
};
use kage_types::assignment::{
    ASSIGNMENT_TICKET_V1_DOMAIN, AssignmentTicketClaimsV1, AssignmentTicketV1, SolverAssignmentV1,
    assignment_order_digest,
};
use kage_types::orders::{OrderState, OrderV1, SolverJobV1};
use uuid::Uuid;

type AssignmentMutation = Box<dyn Fn(&mut AssignmentTicketClaimsV1)>;
type TradeTermsMutation = Box<dyn Fn(&mut kage_types::orders::TradeTerms)>;

#[test]
fn order_snapshot_round_trips_without_losing_wire_fields() {
    let order = OrderV1 {
        id: Uuid::from_u128(1),
        state: OrderState::AwaitingUserProof,
        version: 5,
        chain_id: 31_337,
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        amount_in: U256::from(10_u64.pow(18)),
        amount_out: U256::from(2_000_000_000_u64),
        expires_at_ms: Some(1_800_000_000_000),
        solver: Some(Address::repeat_byte(0x33)),
        solver_noise_public_key: Some(vec![0x44; 32]),
    };

    let encoded = serde_json::to_string(&order).unwrap();
    assert_eq!(serde_json::from_str::<OrderV1>(&encoded).unwrap(), order);
}

#[test]
fn solver_job_contains_only_terms_needed_for_reservation() {
    let job = SolverJobV1 {
        id: Uuid::from_u128(2),
        chain_id: 31_337,
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        amount_in: U256::from(1_000_u64),
        amount_out: U256::from(2_000_u64),
        expires_at_ms: Some(1_800_000_000_000),
    };

    let encoded = serde_json::to_value(&job).unwrap();
    assert!(encoded.get("state").is_none());
    assert!(encoded.get("version").is_none());
    assert!(encoded.get("solver").is_none());
    assert!(encoded.get("solver_noise_public_key").is_none());
    assert_eq!(serde_json::from_value::<SolverJobV1>(encoded).unwrap(), job);
}

#[test]
fn create_order_message_round_trips() {
    let request = CreateOrderRequest {
        order_commitment: B256::repeat_byte(0x55),
        chain_id: 31_337,
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        amount_in: U256::from(1_000_u64),
        amount_out: U256::from(2_000_u64),
        ttl_seconds: Some(60),
    };
    let request = serde_json::to_value(request).unwrap();
    assert_eq!(request["chain_id"], 31_337);
    assert_eq!(request["ttl_seconds"], 60);
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

fn assignment_claims() -> AssignmentTicketClaimsV1 {
    AssignmentTicketClaimsV1 {
        order_id: Uuid::from_u128(3),
        order_version: 7,
        solver_id: Address::repeat_byte(0x33),
        chain_id: 31_337,
        order_digest: B256::repeat_byte(0x55),
        solver_endpoint: "https://solver.kage.test/v1".to_owned(),
        solver_noise_public_key: B256::repeat_byte(0x44),
        issued_at_ms: 1_800_000_000_000,
        expires_at_ms: 1_800_000_060_000,
        nonce: B256::repeat_byte(0x66),
    }
}

#[test]
fn assignment_and_direct_proof_messages_round_trip() {
    let claims = assignment_claims();
    let order_id = claims.order_id;
    let ticket = AssignmentTicketV1 {
        claims,
        signature: vec![0x77; 65],
    };
    let assignment = SolverAssignmentV1 {
        ticket: ticket.clone(),
    };
    let request = DirectProofRequestV1 {
        ticket,
        ciphertext: vec![1, 2, 3],
    };
    let response = DirectProofResponseV1 {
        order_id,
        status: DirectProofStatusV1::Queued,
    };

    let assignment_json = serde_json::to_string(&assignment).unwrap();
    let request_json = serde_json::to_string(&request).unwrap();
    let response_json = serde_json::to_string(&response).unwrap();

    assert_eq!(
        serde_json::from_str::<SolverAssignmentV1>(&assignment_json).unwrap(),
        assignment
    );
    assert_eq!(
        serde_json::from_str::<DirectProofRequestV1>(&request_json).unwrap(),
        request
    );
    assert_eq!(
        serde_json::from_str::<DirectProofResponseV1>(&response_json).unwrap(),
        response
    );
}

#[test]
fn assignment_signing_bytes_are_domain_separated_and_bind_every_claim() {
    let claims = assignment_claims();
    let original = claims.signing_bytes();
    assert!(original.starts_with(ASSIGNMENT_TICKET_V1_DOMAIN));

    let mutations: Vec<AssignmentMutation> = vec![
        Box::new(|value| value.order_id = Uuid::from_u128(4)),
        Box::new(|value| value.order_version += 1),
        Box::new(|value| value.solver_id = Address::repeat_byte(0x34)),
        Box::new(|value| value.chain_id += 1),
        Box::new(|value| value.order_digest = B256::repeat_byte(0x56)),
        Box::new(|value| value.solver_endpoint.push_str("/changed")),
        Box::new(|value| value.solver_noise_public_key = B256::repeat_byte(0x45)),
        Box::new(|value| value.issued_at_ms += 1),
        Box::new(|value| value.expires_at_ms += 1),
        Box::new(|value| value.nonce = B256::repeat_byte(0x67)),
    ];

    for mutate in mutations {
        let mut changed = claims.clone();
        mutate(&mut changed);
        assert_ne!(changed.signing_bytes(), original);
    }
}

#[test]
fn assignment_order_digest_binds_every_trade_term_without_the_user_capability() {
    let terms = kage_types::orders::TradeTerms {
        chain_id: 31_337,
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        amount_in: U256::from(1_000_u64),
        amount_out: U256::from(2_000_u64),
        expires_at_ms: 1_800_000_000_000,
    };
    let original = assignment_order_digest(&terms);
    assert_eq!(
        original,
        "0x6f03445ca575fc649ae64ce85e362455b7de75c19418d8da613e7776b72f26d6"
            .parse::<B256>()
            .unwrap()
    );
    let mutations: Vec<TradeTermsMutation> = vec![
        Box::new(|value| value.chain_id += 1),
        Box::new(|value| value.token_in = Address::repeat_byte(0x12)),
        Box::new(|value| value.token_out = Address::repeat_byte(0x23)),
        Box::new(|value| value.amount_in += U256::from(1_u64)),
        Box::new(|value| value.amount_out += U256::from(1_u64)),
        Box::new(|value| value.expires_at_ms += 1),
    ];
    for mutate in mutations {
        let mut changed = terms;
        mutate(&mut changed);
        assert_ne!(assignment_order_digest(&changed), original);
    }
}
