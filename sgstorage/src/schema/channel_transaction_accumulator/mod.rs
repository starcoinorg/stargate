// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines physical storage schema for the channel transaction accumulator.
//!
//! A hash value is stored on each position.
//! See `libra/storage/accumulator/lib.rs` for details.
//! ```text
//! |<----------key--------->|<-value->|
//! | position in post order |   hash  |
//! ```

use crate::schema::{ensure_slice_len_eq, CHANNEL_TRANSACTION_ACCUMULATOR_CF_NAME};
use byteorder::{BigEndian, ReadBytesExt};
use crypto::HashValue;
use failure::prelude::*;
use libra_types::proof::position::Position;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::mem::size_of;

define_schema!(
    ChannelTransactionAccumulatorSchema,
    Position,
    HashValue,
    CHANNEL_TRANSACTION_ACCUMULATOR_CF_NAME
);

impl KeyCodec<ChannelTransactionAccumulatorSchema> for Position {
    fn encode_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_postorder_index().to_be_bytes().to_vec())
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<u64>())?;
        Ok(Position::from_postorder_index(
            (&data[..]).read_u64::<BigEndian>()?,
        ))
    }
}

impl ValueCodec<ChannelTransactionAccumulatorSchema> for HashValue {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Self::from_slice(data)
    }
}

#[cfg(test)]
mod test;
