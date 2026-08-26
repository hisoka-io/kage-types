use alloy_primitives::{Address, B256, U256};
use kage_types::api_types::{
    ApiErrorResponse, CreateOrderRequest, EncryptedProofRequest, SolverProofDeliveryV1,
    UserEventServerMessage,
};
use kage_types::events::OrderEvent;
use kage_types::orders::{OrderState, OrderV1};
use uuid::Uuid;

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
        tx_hash: None,
    };

    let encoded = serde_json::to_string(&order).unwrap();
    assert_eq!(serde_json::from_str::<OrderV1>(&encoded).unwrap(), order);
}

#[test]
fn api_and_event_messages_round_trip() {
    let order_id = Uuid::from_u128(2);
    let request = CreateOrderRequest {
        order_commitment: B256::repeat_byte(0x55),
        chain_id: 31_337,
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        amount_in: U256::from(1_000_u64),
        amount_out: U256::from(2_000_u64),
        ttl_seconds: Some(60),
    };
    let delivery = SolverProofDeliveryV1 {
        order_id,
        ciphertext: vec![1, 2, 3],
    };
    let encrypted = EncryptedProofRequest {
        ciphertext: vec![4, 5, 6],
        settlement_binding: B256::repeat_byte(0x66),
    };
    let event = UserEventServerMessage::Event {
        event: OrderEvent::ProofRelayed {
            order_id,
            solver_id: Address::repeat_byte(0x33),
        },
    };

    let request = serde_json::to_value(request).unwrap();
    assert_eq!(request["chain_id"], 31_337);
    assert_eq!(request["ttl_seconds"], 60);

    let delivery = serde_json::to_value(delivery).unwrap();
    assert_eq!(delivery["order_id"], order_id.to_string());
    assert_eq!(delivery["ciphertext"], serde_json::json!([1, 2, 3]));

    let encrypted = serde_json::to_value(encrypted).unwrap();
    assert_eq!(encrypted["ciphertext"], serde_json::json!([4, 5, 6]));
    assert_eq!(
        encrypted["settlement_binding"],
        B256::repeat_byte(0x66).to_string()
    );

    let event = serde_json::to_value(event).unwrap();
    assert_eq!(event["type"], "event");
    assert_eq!(
        event["event"]["ProofRelayed"]["order_id"],
        order_id.to_string()
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
