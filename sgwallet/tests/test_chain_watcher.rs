// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Error;
use futures::StreamExt;
use libra_logger::{debug, error};
use libra_types::account_address::AccountAddress;
use libra_types::transaction::Transaction;
use sgchain::star_chain_client::{ChainClient, MockChainClient};
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
    run_with_mock_client(|chain_client| run_test_chain_watcher(chain_client));
}

fn run_test_chain_watcher(chain_client: Arc<dyn ChainClient>) {
    let chain_watcher = ChainWatcher::new(chain_client.clone());
    let mut rt = tokio::runtime::Runtime::new().expect("create tokio runtime should ok");
    let rt_handle = rt.handle().clone();
    let chain_watcher_handle = chain_watcher
        .start(rt_handle, 0, 100)
        .expect("spawn chain watcher should ok");

    let res = rt.block_on(async move {
        let mut receiver = chain_watcher_handle
            .add_interest("test".to_string().into_bytes(), Box::new(|_txn| true))
            .await?;
        chain_client.faucet(AccountAddress::random(), 10000).await?;
        let txn: Option<Transaction> = receiver.next().await;
        assert!(txn.is_some());
        let txn = txn.unwrap();
        let signed_txn = txn.as_signed_user_txn()?;
        debug!("watched txn: {:#?}", signed_txn);
        Ok::<_, Error>(())
    });
    if let Err(e) = res {
        error!("test_chain_watcher fail, error: {:#?}", e);
        assert!(false);
    }
}
