use super::*;
use sgchain::star_chain_client::{MockChainClient};
use types::account_config::account_resource_path;
use logger::init_for_e2e_testing;

#[test]
fn test_local_state_storage() -> Result<()> {
    init_for_e2e_testing();
    let (mock_chain_service, _handle)  = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let account_address = AccountAddress::random();
    client.faucet(account_address, 1_000_000)?;
    debug!("faucet finish");
    let storage = LocalStateStorage::new(account_address, client)?;
    let state_view = storage.new_state_view(None)?;
    let account_resource = state_view.get(&AccessPath::new_for_account(account_address))?;
    debug_assert!(account_resource.is_some());
    debug!("test finish");
    Ok(())
}
