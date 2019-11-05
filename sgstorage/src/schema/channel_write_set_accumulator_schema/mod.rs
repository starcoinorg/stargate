// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::schema::{ensure_slice_len_eq, CHANNEL_WRITE_SET_ACCUMULATOR_CF_NAME};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::prelude::*;
use libra_crypto::hash::HashValue;
use libra_types::proof::position::Position;
use libra_types::transaction::Version;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::mem::size_of;

define_schema!(
    ChannelWriteSetAccumulatorSchema,
    Key,
    HashValue,
    CHANNEL_WRITE_SET_ACCUMULATOR_CF_NAME
);

pub type Key = (Version, Position);

impl KeyCodec<ChannelWriteSetAccumulatorSchema> for Key {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let (version, position) = self;

        let mut encoded_key = Vec::with_capacity(size_of::<Version>() + size_of::<u64>());
        encoded_key.write_u64::<BigEndian>(*version)?;
        encoded_key.write_u64::<BigEndian>(position.to_inorder_index())?;
        Ok(encoded_key)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;

        let version_size = size_of::<Version>();

        let version = (&data[..version_size]).read_u64::<BigEndian>()?;
        let position = (&data[version_size..]).read_u64::<BigEndian>()?;
        Ok((version, Position::from_inorder_index(position)))
    }
}

impl ValueCodec<ChannelWriteSetAccumulatorSchema> for HashValue {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Self::from_slice(data)
    }
}
