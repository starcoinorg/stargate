use super::SCOPED_JELLYFISH_MERKLE_NODE_CF_NAME;
use failure::prelude::*;
use jellyfish_merkle::node_type::{Node, NodeKey};
use libra_types::account_address::{AccountAddress, ADDRESS_LENGTH};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::convert::TryFrom;

/// scoped in a specified channel
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ScopedNodeKey(AccountAddress, NodeKey);
impl ScopedNodeKey {
    pub fn new(address: AccountAddress, node_key: NodeKey) -> Self {
        Self(address, node_key)
    }
}

define_schema!(
    ScopedJellyfishMerkleNodeSchema,
    ScopedNodeKey,
    Node,
    SCOPED_JELLYFISH_MERKLE_NODE_CF_NAME
);

impl KeyCodec<ScopedJellyfishMerkleNodeSchema> for ScopedNodeKey {
    fn encode_key(&self) -> Result<Vec<u8>> {
        self.1.encode()
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() >= 32,
            "cannot decode account address from data, data length too short"
        );
        let address = AccountAddress::try_from(&data[0..ADDRESS_LENGTH])?;
        let node_key = NodeKey::decode(&data[ADDRESS_LENGTH..])?;
        Ok(ScopedNodeKey(address, node_key))
    }
}

impl ValueCodec<ScopedJellyfishMerkleNodeSchema> for Node {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(self.encode()?)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(Self::decode(&data[..])?)
    }
}
