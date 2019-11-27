use libra_types::account_address::AccountAddress;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Type(pub String);

/// A vertex.
///
/// Vertices are how you would represent nouns in the datastore. An example
/// might be a user, or a movie. All vertices have a unique ID and a type.
#[derive(Clone, Debug, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Vertex {
    /// The id of the vertex.
    pub id: AccountAddress,

    /// The type of the vertex.
    pub t: Type,
}

impl Vertex {
    /// Creates a new vertex with an ID generated via UUIDv1. These vertex IDs
    /// are trivially guessable and consequently less secure, but likely index
    /// better depending on the datastore. This method is suggested unless you
    /// need vertex IDs to not be trivially guessable.
    ///
    /// # Arguments
    ///
    /// * `t` - The type of the vertex.
    pub fn new(id: AccountAddress, t: Type) -> Self {
        Self { id, t }
    }
}

impl PartialEq for Vertex {
    fn eq(&self, other: &Vertex) -> bool {
        self.id == other.id
    }
}

impl Eq for Vertex {}
