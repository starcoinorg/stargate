// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The SG Core Contributors

//! This module defines physical storage schema for signed channel transactions.
//!
//! Serialized signed transaction bytes identified by channel_receiver_address+version.
//! ```text
//! |<------key------->|<--value-->|
//! | receiver+version | txn bytes |
//! ```
//!
//! `Version` is serialized in big endian so that records in RocksDB will be in order of it's
//! numeric value.

use crate::schema::CHANNEL_TRANSACTION_CF_NAME;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use canonical_serialization::{SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use libra_types::account_address::{AccountAddress, ADDRESS_LENGTH};
use libra_types::transaction::{Transaction, Version};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChannelTransactionVersion(pub AccountAddress, pub Version);

define_schema!(
    ChannelTransactionSchema,
    ChannelTransactionVersion,
    Transaction,
    CHANNEL_TRANSACTION_CF_NAME
);

impl KeyCodec<ChannelTransactionSchema> for ChannelTransactionVersion {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_all(self.0.as_ref())?;
        encoded.write_u64::<BigEndian>(self.1)?;
        Ok(encoded)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        let mut data = &data[0..];

        let mut addr_data = [0; ADDRESS_LENGTH];
        data.read_exact(&mut addr_data)?;
        let account_address = AccountAddress::new(addr_data);
        let version = data.read_u64::<BigEndian>()?;

        Ok(ChannelTransactionVersion(account_address, version))
    }
}

impl ValueCodec<ChannelTransactionSchema> for Transaction {
    fn encode_value(&self) -> Result<Vec<u8>> {
        SimpleSerializer::<Vec<u8>>::serialize(self)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        SimpleDeserializer::deserialize(data)
    }
}
