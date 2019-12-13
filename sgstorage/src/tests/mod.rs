// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_db::{ChannelAddressProvider, ChannelDB};
use crate::channel_state_store::ChannelState;
use crate::channel_store::ChannelStore;
use crate::schema_db::SchemaDB;
use crate::storage::SgStorage;
use anyhow::Result;
use libra_crypto::hash::CryptoHash;
use libra_crypto::HashValue;
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::transaction::Version;
use schemadb::SchemaBatch;
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn test_db_get_and_put() -> Result<()> {
    libra_logger::try_init_for_testing();
    let tmp_dir = TempPath::new();
    let sender_address = AccountAddress::random();
    let sg_db = Arc::new(SgStorage::new(sender_address, &tmp_dir));

    let receiver_address = AccountAddress::random();
    let channel_db = ChannelDB::new(receiver_address, sg_db);
    let channel_store = ChannelStore::new(channel_db);

    let channel_state_store = channel_store.state_store();
    assert!(channel_state_store
        .get_state_with_proof_by_version(0)
        .is_err());

    let new_root_hash = put_state(
        channel_store.clone(),
        0,
        None,
        Some(AccountStateBlob::from(vec![])),
    )?;

    let channel_state = channel_state_store
        .get_state_with_proof_by_version(0)
        .unwrap();
    assert!(channel_state.sender_state.is_none());
    assert!(channel_state.receiver_state.is_some());

    let verify_result = verify_state(
        new_root_hash,
        sender_address,
        receiver_address,
        &channel_state,
    );
    assert!(verify_result.is_ok());

    let new_root_hash = put_state(
        channel_store.clone(),
        0,
        Some(AccountStateBlob::from(vec![0, 1, 2, 3])),
        Some(AccountStateBlob::from(vec![1, 2, 3, 4])),
    )?;

    let channel_state = channel_state_store
        .get_state_with_proof_by_version(0)
        .unwrap();
    let verify_result = verify_state(
        new_root_hash,
        sender_address,
        receiver_address,
        &channel_state,
    );
    assert!(verify_result.is_ok());

    assert_eq!(
        channel_state.sender_state,
        Some(AccountStateBlob::from(vec![0, 1, 2, 3]))
    );
    assert_eq!(
        channel_state.receiver_state,
        Some(AccountStateBlob::from(vec![1, 2, 3, 4]))
    );

    Ok(())
}

fn put_state(
    channel_store: ChannelStore<ChannelDB>,
    version: Version,
    sender_state_blob: Option<AccountStateBlob>,
    receiver_state_blob: Option<AccountStateBlob>,
) -> Result<HashValue> {
    let sender_address = channel_store.db().owner_address();
    let receiver_address = channel_store.db().participant_address();

    let mut state_set = BTreeMap::new();
    if let Some(blob) = sender_state_blob {
        state_set.insert(sender_address, blob);
    }
    if let Some(blob) = receiver_state_blob {
        state_set.insert(receiver_address, blob);
    }
    let mut schema_batch = SchemaBatch::default();

    let channel_state_store = channel_store.state_store();
    let new_root_hash =
        channel_state_store.put_channel_state_set(state_set, version, &mut schema_batch)?;

    channel_store.db().write_schemas(schema_batch)?;
    Ok(new_root_hash)
}

fn verify_state(
    root_hash: HashValue,
    sender_address: AccountAddress,
    receiver_address: AccountAddress,
    channel_state: &ChannelState,
) -> Result<()> {
    channel_state.sender_state_proof.verify(
        root_hash,
        sender_address.hash(),
        channel_state.sender_state.as_ref(),
    )?;
    channel_state.receiver_state_proof.verify(
        root_hash,
        receiver_address.hash(),
        channel_state.receiver_state.as_ref(),
    )?;
    Ok(())
}

mod rocksdb_prefix_seek_test;
