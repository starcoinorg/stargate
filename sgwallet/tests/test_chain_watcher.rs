// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use coerce_rt::actor::context::ActorContext;
use futures::StreamExt;
use libra_logger::{debug, error};
use libra_types::{
    access_path::DataPath,
    account_address::AccountAddress,
    account_config::{account_struct_tag, AccountResource},
};
use mock_chain_test_helper::run_with_mock_client;
use sgchain::star_chain_client::ChainClient;
use sgwallet::{
    chain_state_access::{AccessState, ChainStateAccessor},
    chain_watcher::*,
};
use std::sync::Arc;

mod mock_chain_test_helper;

#[test]
pub fn test_chain_watcher() {
    if let Err(e) = run_with_mock_client(|chain_client| run_test_chain_watcher(chain_client)) {
        error!("test_chain_watcher fail, error: {:#?}", e);
        assert!(false);
    }
}

fn run_test_chain_watcher(chain_client: Arc<dyn ChainClient>) -> Result<()> {
    let mut rt = tokio::runtime::Runtime::new().expect("create tokio runtime should ok");
    rt.block_on(async move {
        let mut actor_context = ActorContext::new();
        let chain_watcher = ChainWatcher::new(chain_client.clone(), 0, 100);
        let chain_watcher_handle = chain_watcher
            .start(actor_context.clone())
            .await
            .expect("spawn chain watcher should ok");

        let chain_state_accessor = ChainStateAccessor::new(chain_client.clone());
        let mut actor_ref = actor_context.new_actor(chain_state_accessor).await?;

        let mut receiver = chain_watcher_handle
            .add_interest(Box::new(|_txn| true))
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

        let _ = actor_ref.stop().await;
        chain_watcher_handle.stop().await;
        Ok::<_, Error>(())
    })?;
    Ok(())
}
