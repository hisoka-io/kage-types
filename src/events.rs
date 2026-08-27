use serde::{Deserialize, Serialize};

use crate::identifiers::{OrderId, SolverId};
use crate::orders::TradeTerms;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OrderEvent {
    OrderCreated {
        order_id: OrderId,
        terms: TradeTerms,
    },
    OrderValidated {
        order_id: OrderId,
    },
    SolverReservationRequested {
        order_id: OrderId,
        terms: TradeTerms,
    },
    SolverAssigned {
        order_id: OrderId,
        solver_id: SolverId,
    },
    SolverSessionReady {
        order_id: OrderId,
        solver_id: SolverId,
        noise_public_key: Vec<u8>,
    },
    OrderExpired {
        order_id: OrderId,
    },
}

impl OrderEvent {
    pub fn order_id(&self) -> OrderId {
        match self {
            Self::OrderCreated { order_id, .. }
            | Self::OrderValidated { order_id }
            | Self::SolverReservationRequested { order_id, .. }
            | Self::SolverAssigned { order_id, .. }
            | Self::SolverSessionReady { order_id, .. }
            | Self::OrderExpired { order_id } => *order_id,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::OrderCreated { .. } => "OrderCreated",
            Self::OrderValidated { .. } => "OrderValidated",
            Self::SolverReservationRequested { .. } => "SolverReservationRequested",
            Self::SolverAssigned { .. } => "SolverAssigned",
            Self::SolverSessionReady { .. } => "SolverSessionReady",
            Self::OrderExpired { .. } => "OrderExpired",
        }
    }
}
