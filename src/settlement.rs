use crate::identifiers::{OrderId, SettlementBinding};
use alloy_primitives::{Address, B256, keccak256};

pub const INTENT_TAKER_NULLIFIER_INDEX: usize = 0;
pub const SETTLEMENT_TAKER_NULLIFIER_INDEX: usize = 3;
pub const SETTLEMENT_PUBLIC_INPUTS: usize = 42;

const SETTLEMENT_BINDING_DOMAIN: &[u8] = b"kage-settlement/v1";

/// Binds an off-chain order to the taker nullifier revealed by its settlement proof.
pub fn settlement_binding(
    chain_id: u64,
    darkpool: Address,
    order_id: OrderId,
    taker_nullifier: B256,
) -> SettlementBinding {
    let mut preimage = Vec::with_capacity(SETTLEMENT_BINDING_DOMAIN.len() + 8 + 20 + 16 + 32);
    preimage.extend_from_slice(SETTLEMENT_BINDING_DOMAIN);
    preimage.extend_from_slice(&chain_id.to_be_bytes());
    preimage.extend_from_slice(darkpool.as_slice());
    preimage.extend_from_slice(order_id.as_bytes());
    preimage.extend_from_slice(taker_nullifier.as_slice());
    keccak256(preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_is_domain_separated_by_every_context_field() {
        let order_id = uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
        let pool = Address::repeat_byte(0x33);
        let nullifier = B256::repeat_byte(0x44);
        let binding = settlement_binding(31_337, pool, order_id, nullifier);

        assert_eq!(
            binding,
            "0xf229315fc1f19bb9a67e246d960ad45f792bff24243744803ca0c2670a986bff"
                .parse::<B256>()
                .unwrap()
        );

        assert_ne!(
            binding,
            settlement_binding(31_338, pool, order_id, nullifier)
        );
        assert_ne!(
            binding,
            settlement_binding(31_337, Address::repeat_byte(0x34), order_id, nullifier)
        );
        assert_ne!(
            binding,
            settlement_binding(31_337, pool, uuid::Uuid::nil(), nullifier)
        );
        assert_ne!(
            binding,
            settlement_binding(31_337, pool, order_id, B256::repeat_byte(0x45))
        );
    }
}
