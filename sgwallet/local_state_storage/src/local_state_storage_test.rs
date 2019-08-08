use super::*;
use mock_chain_client::MockChainClient;
use types::account_config::account_resource_path;

#[test]
fn test_local_state_storage() {
    let client = Arc::new(MockChainClient::new());
    let account_address = AccountAddress::random();
    client.faucet(account_address, 1_000_000);
    let storage = LocalStateStorage::new(account_address, client).unwrap();
    debug_assert!(storage.get_by_path(&account_resource_path()).is_some());
}
