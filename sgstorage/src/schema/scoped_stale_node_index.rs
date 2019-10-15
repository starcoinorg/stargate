use super::SCOPED_STALE_NODE_INDEX_CF_NAME;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::prelude::*;
use jellyfish_merkle::{node_type::NodeKey, StaleNodeIndex};
use libra_types::account_address::{AccountAddress, ADDRESS_LENGTH};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::io::Read;
use std::io::Write;

/// Indicates a scoped stale node index.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopedStaleNodeIndex(AccountAddress, StaleNodeIndex);
impl ScopedStaleNodeIndex {
    pub fn new(address: AccountAddress, stale_node_index: StaleNodeIndex) -> Self {
        Self(address, stale_node_index)
    }
}
define_schema!(
    ScopedStaleNodeIndexSchema,
    ScopedStaleNodeIndex,
    (),
    SCOPED_STALE_NODE_INDEX_CF_NAME
);

impl KeyCodec<ScopedStaleNodeIndexSchema> for ScopedStaleNodeIndex {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_all(self.0.as_ref())?;
        encoded.write_u64::<BigEndian>(self.1.stale_since_version)?;
        encoded.write_all(&self.1.node_key.encode()?)?;
        Ok(encoded)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        let mut data = &data[0..];

        let mut addr_data = [0; ADDRESS_LENGTH];
        data.read_exact(&mut addr_data)?;
        let account_address = AccountAddress::new(addr_data);

        let stale_since_version = data.read_u64::<BigEndian>()?;
        let node_key = NodeKey::decode(data)?;

        Ok(ScopedStaleNodeIndex(
            account_address,
            StaleNodeIndex {
                stale_since_version,
                node_key,
            },
        ))
    }
}

impl ValueCodec<ScopedStaleNodeIndexSchema> for () {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() == 0,
            "Unexpected data len {}, expected {}.",
            data.len(),
            0,
        );
        Ok(())
    }
}

//impl SeekKeyCodec<StaleNodeIndexSchema> for Version {
//    fn encode_seek_key(&self) -> Result<Vec<u8>> {
//        Ok(self.to_be_bytes().to_vec())
//    }
//}
