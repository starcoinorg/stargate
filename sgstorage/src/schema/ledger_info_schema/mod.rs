// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::schema::ensure_slice_len_eq;
use byteorder::{BigEndian, ReadBytesExt};
use failure::prelude::*;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
    DEFAULT_CF_NAME,
};
use sgtypes::ledger_info::LedgerInfo;
use std::mem::size_of;

define_schema!(
    LedgerInfoSchema,
    u64, /* epoch num */
    LedgerInfo,
    DEFAULT_CF_NAME
);

impl KeyCodec<LedgerInfoSchema> for u64 {
    fn encode_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;
        Ok((&data[..]).read_u64::<BigEndian>()?)
    }
}

impl ValueCodec<LedgerInfoSchema> for LedgerInfo {
    fn encode_value(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(|e| Error::from_boxed_compat(Box::new(e)))
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(|e| Error::from_boxed_compat(Box::new(e)))
    }
}
