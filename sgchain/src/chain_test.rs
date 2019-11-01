// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::star_chain_client::{faucet_sync, ChainClient, MockChainClient};
use libra_types::account_address::AccountAddress;
use std::thread::spawn;

#[test]
fn test_mock_chain_client_faucet() {
    ::libra_logger::try_init_for_testing();
    let (client, _handle) = MockChainClient::new();
    for _i in 1..2 {
        let addr = AccountAddress::random();
        faucet_sync(client.clone(), addr, 1000).unwrap();
        faucet_sync(client.clone(), addr, 1000).unwrap();
        faucet_sync(client.clone(), addr, 1000).unwrap();
        assert_eq!(client.account_exist(&addr, None), true);
    }
    drop(client);
}

#[test]
fn test_multi_mock_chain_client() {
    for _i in 1..3 {
        let (client, _handle) = MockChainClient::new();

        spawn(move || {
            for _i in 1..2 {
                let addr = AccountAddress::random();
                faucet_sync(client.clone(), addr, 1000).unwrap();
                faucet_sync(client.clone(), addr, 1000).unwrap();
                faucet_sync(client.clone(), addr, 1000).unwrap();
                assert_eq!(client.account_exist(&addr, None), true);
            }
            drop(client);
        });
    }
}
