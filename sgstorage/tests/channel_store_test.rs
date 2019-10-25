// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use sgstorage::generate_random_channel_store;

#[test]
fn test_channel_store_startup() {
    let channel_store = generate_random_channel_store();
    let startup_info = channel_store.get_startup_info();
    assert!(startup_info.is_ok());
    assert!(startup_info.unwrap().is_none());
}
