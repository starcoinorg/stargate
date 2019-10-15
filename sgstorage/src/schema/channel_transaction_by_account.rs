// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The SG Core Contributors

//! This module defines physical storage schema for a transaction index via which the version of a
//! transaction sent by `account_address` with `channel_sequence_number` can be found. With the version one
//! can resort to `ChannelTransactionSchema` for the transaction content.
//!
//! ```text
//! |<------key------->|<-value->|
//! | sender | seq_num | txn_ver |
//! ```

use crate::schema::{ensure_slice_len_eq, CHANNEL_TRANSACTION_BY_ACCOUNT_CF_NAME};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::prelude::*;
use libra_types::{
    account_address::{AccountAddress, ADDRESS_LENGTH},
    transaction::Version,
};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::io::{Read, Write};
use std::mem::size_of;

define_schema!(
    ChannelTransactionByAccountSchema,
    Key,
    Version,
    CHANNEL_TRANSACTION_BY_ACCOUNT_CF_NAME
);

type SeqNum = u64;

/// participant_address, tx_sender_address, sender_channel_seq_number
pub type Key = (AccountAddress, AccountAddress, SeqNum);

impl KeyCodec<ChannelTransactionByAccountSchema> for Key {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let (ref participant_address, ref tx_sender_address, seq_num) = *self;

        let mut encoded = participant_address.to_vec();
        encoded.write_all(tx_sender_address.as_ref())?;
        encoded.write_u64::<BigEndian>(seq_num)?;

        Ok(encoded)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;
        let mut data = &data[0..];

        let mut participant_address = [0; ADDRESS_LENGTH];
        data.read_exact(&mut participant_address)?;
        let owner_address = AccountAddress::new(participant_address);

        let mut tx_sender_address = [0; ADDRESS_LENGTH];
        data.read_exact(&mut tx_sender_address)?;
        let tx_sender_address = AccountAddress::new(tx_sender_address);

        let seq_num = data.read_u64::<BigEndian>()?;

        Ok((owner_address, tx_sender_address, seq_num))
    }
}

impl ValueCodec<ChannelTransactionByAccountSchema> for Version {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;

        Ok((&data[..]).read_u64::<BigEndian>()?)
    }
}
