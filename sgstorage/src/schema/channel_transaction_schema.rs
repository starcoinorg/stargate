// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines physical storage schema for signed channel transactions.
//!
//! Serialized signed transaction bytes identified by version.
//! ```text
//! |<--key-->|<--value-->|
//! | version | txn bytes |
//! ```
//!
//! `Version` is serialized in big endian so that records in RocksDB will be in order of it's
//! numeric value.

use crate::schema::{ensure_slice_len_eq, SIGNED_CHANNEL_TRANSACTION_CF_NAME};
use byteorder::{BigEndian, ReadBytesExt};
use canonical_serialization::{SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use libra_types::transaction::Version;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use std::mem::size_of;

define_schema!(
    SignedChannelTransactionSchema,
    Version,
    SignedChannelTransaction,
    SIGNED_CHANNEL_TRANSACTION_CF_NAME
);

impl KeyCodec<SignedChannelTransactionSchema> for Version {
    fn encode_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Version>())?;
        Ok((&data[..]).read_u64::<BigEndian>()?)
    }
}

impl ValueCodec<SignedChannelTransactionSchema> for SignedChannelTransaction {
    fn encode_value(&self) -> Result<Vec<u8>> {
        SimpleSerializer::<Vec<u8>>::serialize(self)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        SimpleDeserializer::deserialize(data)
    }
}
