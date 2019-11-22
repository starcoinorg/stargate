use crate::vertex::Type;
use libra_types::account_address::AccountAddress;

/// Represents a uniquely identifiable key to an edge.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Edge {
    /// The id of the outbound vertex.
    pub outbound_id: AccountAddress,

    /// The type of the edge.
    pub t: Type,

    /// The id of the inbound vertex.
    pub inbound_id: AccountAddress,
}

impl Edge {
    pub fn new(outbound_id: AccountAddress, t: Type, inbound_id: AccountAddress) -> Self {
        Self {
            outbound_id,
            t,
            inbound_id,
        }
    }
}
