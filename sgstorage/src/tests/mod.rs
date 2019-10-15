use crate::channel_state_store::{ChannelState, ChannelStateStore};
use crate::SgDB;
use crypto::hash::CryptoHash;
use crypto::HashValue;
use failure::Result;
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::transaction::Version;
use schemadb::SchemaBatch;
use sgtypes::account_state::AccountState;
use std::collections::HashMap;
use std::sync::Arc;

#[test]
fn test_db_get_and_put() -> Result<()> {
    logger::try_init_for_testing();
    let tmp_dir = TempPath::new();
    let sender_address = AccountAddress::random();
    let sg_db = Arc::new(SgDB::new(&tmp_dir, sender_address));

    let receiver_address = AccountAddress::random();
    let channel_state_store = ChannelStateStore::new(sg_db.clone(), receiver_address);
    assert!(channel_state_store
        .get_state_with_proof_by_version(0)
        .is_err());

    let new_root_hash = put_state(
        sg_db.clone(),
        0,
        sender_address,
        None,
        receiver_address,
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
        sg_db.clone(),
        0,
        sender_address,
        Some(AccountStateBlob::from(vec![0, 1, 2, 3])),
        receiver_address,
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
    sg_db: Arc<SgDB>,
    version: Version,
    sender_address: AccountAddress,
    sender_state_blob: Option<AccountStateBlob>,
    receiver_address: AccountAddress,
    receiver_state_blob: Option<AccountStateBlob>,
) -> Result<HashValue> {
    let mut state_set = HashMap::new();
    if let Some(blob) = sender_state_blob {
        state_set.insert(sender_address, blob);
    }
    if let Some(blob) = receiver_state_blob {
        state_set.insert(receiver_address, blob);
    }
    let mut schema_batch = SchemaBatch::default();

    let channel_state_store = ChannelStateStore::new(sg_db.clone(), receiver_address);

    let new_root_hash =
        channel_state_store.put_channel_state_set(state_set, version, &mut schema_batch)?;

    sg_db.write_schemas(schema_batch)?;
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
