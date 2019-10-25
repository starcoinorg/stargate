// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::*;
use libra_tools::tempdir::TempPath;
use logger::try_init_for_testing;
use sgchain::star_chain_client::{faucet_sync, MockChainClient};
use state_view::StateView;
#[test]
fn test_local_state_storage() -> Result<()> {
    try_init_for_testing();
    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service.clone());
    let account_address = AccountAddress::random();
    faucet_sync(mock_chain_service, account_address, 1_000_000)?;
    debug!("faucet finish");

    let storage = LocalStateStorage::new(account_address, TempPath::new(), client)?;
    let state_view = storage.new_state_view(None)?;
    let account_resource = state_view.get(&AccessPath::new_for_account(account_address))?;
    debug_assert!(account_resource.is_some());
    debug!("test finish");
    Ok(())
}
