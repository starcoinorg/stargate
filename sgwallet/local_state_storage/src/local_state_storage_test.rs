use super::*;
use mock_chain_client::{MockChainClient, mock_star_client::MockStarClient};
use types::account_config::account_resource_path;
use tokio::runtime::{Runtime, TaskExecutor};

#[test]
fn test_local_state_storage() {
    let rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (mock_chain_service , handle)= MockStarClient::new();
    let client = Arc::new(mock_chain_service);
    let account_address = AccountAddress::random();
    client.faucet(account_address, 1_000_000).unwrap();
    let storage = LocalStateStorage::new(account_address, client).unwrap();
    let state_view = storage.new_state_view(None, &account_address).unwrap();
    let account_resource = state_view.get(&AccessPath::new_for_account(account_address)).unwrap();
    debug_assert!(account_resource.is_some())
    //debug_assert!(storage.get_by_path(&account_resource_path()).is_some());
}
