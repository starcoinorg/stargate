use nextgen_crypto::test_utils::KeyPair;
use serde::{Deserialize, Serialize};
use types::account_address::AccountAddress;
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use nextgen_crypto::ValidKeyStringExt;

pub mod commands;
pub mod client_proxy;
mod node_commands;

/// Struct used to store data for each created account.  We track the sequence number
/// so we can create new transactions easily
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AccountData {
    /// Address of the account.
    pub address: AccountAddress,
    /// (private_key, public_key) pair if the account is not managed by wallet.
    pub key_pair: Option<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    /// Latest sequence number maintained by client, it can be different from validator.
    pub sequence_number: u64,
    /// Whether the account is initialized on chain, cached local only, or status unknown.
    pub status: AccountStatus,
}

/// Enum used to represent account status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AccountStatus {
    /// Account exists only in loacal cache, it is not persisted on chain.
    Local,
    /// Account is persisted on chain.
    Persisted,
    /// Not able to check account status, probably because client is not able to talk to the
    /// validator.
    Unknown,
}

impl AccountData {
    /// Serialize account keypair if exists.
    pub fn keypair_as_string(&self) -> Option<(String, String)> {
        match &self.key_pair {
            Some(key_pair) => Some((
                key_pair.private_key.to_encoded_string().unwrap(),
                key_pair.public_key.to_encoded_string().unwrap(),
            )),
            None => None,
        }
    }
}
