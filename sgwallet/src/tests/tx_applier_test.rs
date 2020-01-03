// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::tx_applier::TxApplier;
use libra_crypto::hash::CryptoHash;
use sgstorage::{channel_db::ChannelAddressProvider, generate_random_channel_store};

#[test]
fn test_tx_applier() {
    libra_logger::try_init_for_testing();
    let store = generate_random_channel_store();
    let mut tx_applier = TxApplier::new(store.clone());

    let txn_to_apply = super::generate_txn_to_apply(
        store.db().owner_address(),
        store.db().participant_address(),
        0,
    );
    let txn_hash = txn_to_apply.signed_channel_txn.hash();
    let apply_result = tx_applier.apply(txn_to_apply);
    assert!(
        apply_result.is_ok(),
        format!("err: {:?}", apply_result.unwrap_err())
    );
    let ws = store.get_latest_witness();
    assert!(ws.is_some());
    assert!(ws.unwrap().write_set().len() > 0);

    let txn = store.get_transaction_by_channel_seq_number(0, false);
    assert!(txn.is_ok(), format!("err: {:?}", txn.unwrap_err()));
    let txn = txn.unwrap();
    assert_eq!(txn_hash, txn.signed_transaction.hash());
}
