// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines physical storage schema for `PendingTransaction` structure.
//!
//! Serialized signed transaction bytes identified by version.
//! ```text
//! |<--key-->|<-----value---->|
//! | pending | txn bytes |
//! ```
//!
//! `Version` is serialized in big endian so that records in RocksDB will be in order of it's
//! numeric value.
use crate::schema::PENDING_CHANNEL_TRANSACTION_CF_NAME;
use failure::prelude::*;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use sgtypes::pending_txn::PendingTransaction;

define_schema!(
    PendingTransactionSchema,
    Key,
    PendingTransaction,
    PENDING_CHANNEL_TRANSACTION_CF_NAME
);
pub type Key = String;
impl KeyCodec<PendingTransactionSchema> for Key {
    fn encode_key(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}

impl ValueCodec<PendingTransactionSchema> for PendingTransaction {
    fn encode_value(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}

#[cfg(test)]
mod test;
