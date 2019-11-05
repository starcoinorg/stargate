// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::*;
use libra_logger::try_init_for_testing;
use libra_state_view::StateView;
use libra_tools::tempdir::TempPath;
use libra_types::access_path::AccessPath;
use sgchain::client_state_view::ClientStateView;
use sgchain::star_chain_client::{faucet_sync, MockChainClient};

#[test]
fn test_channel_manager() -> Result<()> {
    try_init_for_testing();
    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service.clone());
    let account_address = AccountAddress::random();
    faucet_sync(mock_chain_service, account_address, 1_000_000)?;
    debug!("faucet finish");

    let _channel_manager = ChannelManager::new(account_address, TempPath::new(), client.clone())?;

    //    let state_view = storage.new_state_view(None)?;
    let state_view = ClientStateView::new(None, &*client);

    let account_resource = state_view.get(&AccessPath::new_for_account(account_address))?;
    debug_assert!(account_resource.is_some());
    debug!("test finish");
    Ok(())
}
