use types::account_address::AccountAddress;
use std::thread::sleep;
use std::time::Duration;
use crate::star_chain_client::{MockChainClient, ChainClient, stop_mock_chain};

#[test]
fn test_mock_chain_client_faucet() {
    ::logger::init_for_e2e_testing();
    let (client, _handle) = MockChainClient::new();
    for _i in 1..3 {
        let addr = AccountAddress::random();
        client.faucet(addr, 1000);
        client.faucet(addr, 1000);
        client.faucet(addr, 1000);
        assert_eq!(client.account_exist(&addr, None), true);
    }
    sleep(Duration::from_secs(5));
    stop_mock_chain(&client);
}