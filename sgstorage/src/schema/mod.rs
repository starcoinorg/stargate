pub mod channel_transaction;
pub mod channel_transaction_by_account;
pub mod scoped_node_key;
pub mod scoped_stale_node_index;

use failure::prelude::*;
use schemadb::ColumnFamilyName;

pub const SCOPED_STALE_NODE_INDEX_CF_NAME: ColumnFamilyName = "scoped_stale_node_index";
pub const SCOPED_JELLYFISH_MERKLE_NODE_CF_NAME: ColumnFamilyName = "scoped_jellyfish_merkle_node";

//pub(super) const EVENT_ACCUMULATOR_CF_NAME: ColumnFamilyName = "event_accumulator";
//pub(super) const EVENT_BY_KEY_CF_NAME: ColumnFamilyName = "event_by_key";
//pub(super) const EVENT_CF_NAME: ColumnFamilyName = "event";
//pub(super) const JELLYFISH_MERKLE_NODE_CF_NAME: ColumnFamilyName = "jellyfish_merkle_node";
//pub(super) const LEDGER_COUNTERS_CF_NAME: ColumnFamilyName = "ledger_counters";
//pub(super) const STALE_NODE_INDEX_CF_NAME: ColumnFamilyName = "stale_node_index";
pub const CHANNEL_TRANSACTION_CF_NAME: ColumnFamilyName = "channel_transaction";
//pub(super) const TRANSACTION_ACCUMULATOR_CF_NAME: ColumnFamilyName = "transaction_accumulator";
pub const CHANNEL_TRANSACTION_BY_ACCOUNT_CF_NAME: ColumnFamilyName =
    "channel_transaction_by_account";
//pub(super) const TRANSACTION_INFO_CF_NAME: ColumnFamilyName = "transaction_info";
//pub(super) const VALIDATOR_CF_NAME: ColumnFamilyName = "validator";

pub fn ensure_slice_len_eq(data: &[u8], len: usize) -> Result<()> {
    ensure!(
        data.len() == len,
        "Unexpected data len {}, expected {}.",
        data.len(),
        len,
    );
    Ok(())
}
