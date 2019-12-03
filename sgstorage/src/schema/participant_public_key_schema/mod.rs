// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines physical storage schema for channel participant public key structure.
//!
//! Serialized signed transaction bytes identified by version.
//! ```text
//! |<--key-->|<-----value---->|
//! | participant address | public key |
//! ```
//!
//! `Version` is serialized in big endian so that records in RocksDB will be in order of it's
//! numeric value.
use crate::schema::PARTICIPANT_PUBLIC_KEY_CF_NAME;
use failure::prelude::*;
use libra_crypto::ed25519::Ed25519PublicKey;
use libra_types::account_address::AccountAddress;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};

define_schema!(
    ParticipantPublicKeySchema,
    AccountAddress,
    Ed25519PublicKey,
    PARTICIPANT_PUBLIC_KEY_CF_NAME
);

impl KeyCodec<ParticipantPublicKeySchema> for AccountAddress {
    fn encode_key(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}

impl ValueCodec<ParticipantPublicKeySchema> for Ed25519PublicKey {
    fn encode_value(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}
