// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines physical storage schema for ChannelTransactionInfo structure.
//!
//! Serialized signed transaction bytes identified by version.
//! ```text
//! |<--key-->|<-----value---->|
//! | version | txn_info bytes |
//! ```
//!
//! `Version` is serialized in big endian so that records in RocksDB will be in order of it's
//! numeric value.
use crate::schema::CHANNEL_TRANSACTION_INFO_CF_NAME;
use byteorder::{BigEndian, ReadBytesExt};
use canonical_serialization::{SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use libra_types::transaction::Version;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use sgtypes::channel_transaction_info::ChannelTransactionInfo;
use std::mem::size_of;

define_schema!(
    ChannelTransactionInfoSchema,
    Version,
    ChannelTransactionInfo,
    CHANNEL_TRANSACTION_INFO_CF_NAME
);

impl KeyCodec<ChannelTransactionInfoSchema> for Version {
    fn encode_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() == size_of::<Version>(),
            "Bad num of bytes: {}",
            data.len()
        );
        Ok((&data[..]).read_u64::<BigEndian>()?)
    }
}

impl ValueCodec<ChannelTransactionInfoSchema> for ChannelTransactionInfo {
    fn encode_value(&self) -> Result<Vec<u8>> {
        SimpleSerializer::serialize(self)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        SimpleDeserializer::deserialize(data)
    }
}

#[cfg(test)]
mod test;
