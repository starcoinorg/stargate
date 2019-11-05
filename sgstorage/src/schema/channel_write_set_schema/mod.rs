// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::schema::{ensure_slice_len_eq, CHANNEL_WRITE_SET_CF_NAME};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::prelude::*;
use libra_types::transaction::Version;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use sgtypes::write_set_item::WriteSetItem;
use std::mem::size_of;

define_schema!(
    ChannelWriteSetSchema,
    Key,
    WriteSetItem,
    CHANNEL_WRITE_SET_CF_NAME
);

type Index = u64;
pub type Key = (Version, Index);

impl KeyCodec<ChannelWriteSetSchema> for Key {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let (version, index) = *self;

        let mut encoded_key = Vec::with_capacity(size_of::<Version>() + size_of::<Index>());
        encoded_key.write_u64::<BigEndian>(version)?;
        encoded_key.write_u64::<BigEndian>(index)?;
        Ok(encoded_key)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;

        let version_size = size_of::<Version>();

        let version = (&data[..version_size]).read_u64::<BigEndian>()?;
        let index = (&data[version_size..]).read_u64::<BigEndian>()?;
        Ok((version, index))
    }
}

impl ValueCodec<ChannelWriteSetSchema> for WriteSetItem {
    fn encode_value(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}
