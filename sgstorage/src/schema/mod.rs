// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod channel_transaction_accumulator;
pub mod channel_transaction_info;
pub mod channel_transaction_schema;
pub mod channel_write_set_accumulator_schema;
pub mod channel_write_set_schema;
use failure::prelude::*;
use schemadb::ColumnFamilyName;

//pub const EVENT_ACCUMULATOR_CF_NAME: ColumnFamilyName = "event_accumulator";
//pub const EVENT_BY_KEY_CF_NAME: ColumnFamilyName = "event_by_key";
//pub const EVENT_CF_NAME: ColumnFamilyName = "event";
//pub const LEDGER_COUNTERS_CF_NAME: ColumnFamilyName = "ledger_counters";

pub const SIGNED_CHANNEL_TRANSACTION_CF_NAME: ColumnFamilyName = "signed_channel_transaction";
pub const CHANNEL_TRANSACTION_ACCUMULATOR_CF_NAME: ColumnFamilyName =
    "channel_transaction_accumulator";
pub const CHANNEL_TRANSACTION_INFO_CF_NAME: ColumnFamilyName = "channel_transaction_info";

pub const CHANNEL_WRITE_SET_CF_NAME: ColumnFamilyName = "channel_write_set";
pub const CHANNEL_WRITE_SET_ACCUMULATOR_CF_NAME: ColumnFamilyName = "channel_write_set_accumulator";

pub fn ensure_slice_len_eq(data: &[u8], len: usize) -> Result<()> {
    ensure!(
        data.len() == len,
        "Unexpected data len {}, expected {}.",
        data.len(),
        len,
    );
    Ok(())
}
