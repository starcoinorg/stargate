// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_db::ChannelDB;
use crate::channel_store::ChannelStore;
use crate::storage::SgStorage;
use libra_types::account_address::AccountAddress;
use std::collections::BTreeSet;
use std::sync::Arc;

pub mod channel_db;
pub mod channel_store;
pub mod channel_transaction_store;
pub mod channel_write_set_store;
pub mod error;
pub mod ledger_info_store;
pub mod pending_txn_store;
pub mod rocksdb_utils;
pub mod schema;
pub mod schema_db;
pub mod storage;
pub mod utils;

pub fn generate_random_channel_store() -> ChannelStore<ChannelDB> {
    let owner = AccountAddress::random();
    let storage = SgStorage::new(owner, libra_tools::tempdir::TempPath::new());
    let participant1 = AccountAddress::random();
    let participant2 = AccountAddress::random();
    let ps = {
        let mut t = BTreeSet::new();
        t.insert(participant1);
        t.insert(participant2);
        t
    };
    let channel_db = ChannelDB::new(AccountAddress::from(&ps), Arc::new(storage));
    let channel_store = ChannelStore::new(ps, channel_db).unwrap();
    channel_store
}

#[cfg(test)]
mod tests;
