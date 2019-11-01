// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel::Channel;
use sgstorage::channel_db::ChannelAddressProvider;
use sgstorage::generate_random_channel_store;

#[test]
fn test_channel_get_txn() {
    logger::try_init_for_testing();
    let store = generate_random_channel_store();
    let _channel = Channel::new(
        store.db().owner_address(),
        store.db().participant_address(),
        store,
    );
}
