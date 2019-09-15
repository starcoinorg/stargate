use super::*;
use mock_chain_client::MockChainClient;
use types::account_config::account_resource_path;
use tokio::runtime::{Runtime, TaskExecutor};

#[test]
fn test_local_state_storage() {
    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (mock_chain_service, db_shutdown_receiver) = MockChainClient::new(executor);
    let client = Arc::new(mock_chain_service);
    let account_address = AccountAddress::random();
    client.faucet(account_address, 1_000_000);
    let storage = LocalStateStorage::new(account_address, client).unwrap();
    debug_assert!(storage.get_by_path(&account_resource_path()).is_some());
}
