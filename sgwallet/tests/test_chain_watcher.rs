// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use futures::StreamExt;
use libra_logger::{debug, error};
use libra_types::access_path::DataPath;
use libra_types::account_address::AccountAddress;
use libra_types::account_config::{account_struct_tag, AccountResource};
use sgchain::star_chain_client::{ChainClient, MockChainClient};
use sgwallet::chain_state_access::{AccessState, ChainStateAccessor};
use sgwallet::chain_watcher::*;
use std::sync::Arc;

pub fn run_with_mock_client<F, T>(mut f: F) -> T
where
    F: FnMut(Arc<dyn ChainClient>) -> T,
{
    libra_logger::try_init_for_testing();
    let (mock_chain_service, _handle) = MockChainClient::new();
    //    std::thread::sleep(Duration::from_millis(1500));
    let chain_client = Arc::new(mock_chain_service);
    f(chain_client.clone())
}

#[test]
pub fn test_chain_watcher() {
    if let Err(e) = run_with_mock_client(|chain_client| run_test_chain_watcher(chain_client)) {
        error!("test_chain_watcher fail, error: {:#?}", e);
        assert!(false);
    }
}

fn run_test_chain_watcher(chain_client: Arc<dyn ChainClient>) -> Result<()> {
    let chain_watcher = ChainWatcher::new(chain_client.clone());
    let mut rt = tokio::runtime::Runtime::new().expect("create tokio runtime should ok");
    let rt_handle = rt.handle().clone();
    let chain_watcher_handle = chain_watcher
        .start(rt_handle, 0, 100)
        .expect("spawn chain watcher should ok");
    let chain_state_accessor = ChainStateAccessor::new(chain_client.clone());
    let chain_state_accessor_actor_ref =
        rt.block_on(async move { coerce_rt::actor::new_actor(chain_state_accessor).await })?;
    let mut actor_ref = chain_state_accessor_actor_ref.clone();
    rt.block_on(async move {
        let mut receiver = chain_watcher_handle
            .add_interest("test".to_string().into_bytes(), Box::new(|_txn| true))
            .await?;
        let account_address = AccountAddress::random();
        chain_client.faucet(account_address, 10000).await?;
        let txn: Option<TransactionWithInfo> = receiver.next().await;
        assert!(txn.is_some());
        let txn = txn.unwrap();
        let signed_txn = txn.txn.as_signed_user_txn()?;
        debug!("watched txn: {:#?}", signed_txn);

        let state_receiver = actor_ref
            .send(AccessState {
                version: Some(txn.version),
                account: account_address,
                data_path: DataPath::onchain_resource_path(account_struct_tag()),
            })
            .await?;
        let state = state_receiver.await??;
        assert!(state.is_some());
        let state: Vec<u8> = state.unwrap();
        let account_resource: AccountResource = lcs::from_bytes::<AccountResource>(&state).unwrap();
        assert_eq!(10000, account_resource.balance());
        Ok::<_, Error>(())
    })?;
    Ok(())
}
