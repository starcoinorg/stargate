use crate::vertex::{Type, Vertex};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// Represents a uniquely identifiable key to an edge.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Edge {
    /// The id of the outbound vertex.
    pub outbound_id: Vertex,

    /// The type of the edge.
    pub t: Type,

    /// The id of the inbound vertex.
    pub inbound_id: Vertex,
}

impl Edge {
    pub fn new(outbound_id: Vertex, t: Type, inbound_id: Vertex) -> Self {
        Self {
            outbound_id,
            t,
            inbound_id,
        }
    }

    pub fn from_vertexes(mut ids: Vec<Vertex>) -> Result<Self> {
        ensure!(ids.len() == 2, "balances len should be 2");
        let t = Type("BI".to_string());

        Ok(Self {
            outbound_id: ids.remove(0),
            t,
            inbound_id: ids.remove(0),
        })
    }
}
