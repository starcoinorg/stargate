use crate::star_chain_client::{faucet_sync, stop_mock_chain, ChainClient, MockChainClient};
use std::{
    thread::{sleep, spawn},
    time::Duration,
};
use types::account_address::AccountAddress;

#[test]
fn test_mock_chain_client_faucet() {
    ::logger::init_for_e2e_testing();
    let (client, _handle) = MockChainClient::new();
    for _i in 1..2 {
        let addr = AccountAddress::random();
        faucet_sync(client.clone(), addr, 1000).unwrap();
        faucet_sync(client.clone(), addr, 1000).unwrap();
        faucet_sync(client.clone(), addr, 1000).unwrap();
        assert_eq!(client.account_exist(&addr, None), true);
    }
    stop_mock_chain(&client);
    drop(client);
}

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
            stop_mock_chain(&client);
            drop(client);
        });
    }
}
