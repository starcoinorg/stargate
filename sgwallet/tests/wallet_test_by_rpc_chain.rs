use anyhow::{Error, Result};
use common::setup_wallet;
use libra_logger::prelude::*;
use rpc_chain_test_helper::run_with_rpc_client;
use sgchain::star_chain_client::ChainClient;
use std::sync::Arc;
use wallet_test_helper::{
    test_channel_event_watcher_async, test_deploy_custom_module, test_wallet_async,
};

mod common;
mod rpc_chain_test_helper;
mod transfer;
mod wallet_test_helper;

#[test]
fn wallet_test_by_rpc_chain() -> Result<()> {
    let result = run_with_rpc_client(|chain_client| {
        let mut rt = tokio::runtime::Runtime::new()?;
        //        rt.block_on(test_all_parallel(chain_client))
        rt.block_on(test_all_sequential(chain_client))
    });
    dbg!(result)
}

#[allow(dead_code)]
async fn test_all_sequential(chain_client: Arc<dyn ChainClient>) -> Result<()> {
    dbg!(common::with_init_wallet_async(chain_client.clone(), transfer::transfer_htlc).await)?;
    dbg!(common::with_init_wallet_async(chain_client.clone(), test_wallet_async).await)?;
    dbg!(
        common::with_init_wallet_async(chain_client.clone(), test_channel_event_watcher_async)
            .await
    )?;
    dbg!(common::with_init_wallet_async(chain_client.clone(), test_deploy_custom_module).await)?;
    Ok::<_, Error>(())
}

#[allow(dead_code)]
async fn test_all_parallel(chain_client: Arc<dyn ChainClient>) -> Result<()> {
    let init_amount = 10_000_000;

    let sender_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let receiver_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let h1 = tokio::task::spawn(async move {
        transfer::transfer_htlc(sender_wallet.clone(), receiver_wallet.clone()).await?;
        sender_wallet.stop().await?;
        receiver_wallet.stop().await?;
        debug!("h1 stopped");
        Ok::<_, Error>(())
    });

    let sender_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let receiver_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let h2 = tokio::task::spawn(async move {
        test_wallet_async(sender_wallet.clone(), receiver_wallet.clone()).await?;
        sender_wallet.stop().await?;
        receiver_wallet.stop().await?;
        debug!("h1 stopped");
        Ok::<_, Error>(())
    });

    let sender_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let receiver_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let h3 = tokio::task::spawn(async move {
        test_channel_event_watcher_async(sender_wallet.clone(), receiver_wallet.clone()).await?;
        sender_wallet.stop().await?;
        receiver_wallet.stop().await?;
        debug!("h1 stopped");
        Ok::<_, Error>(())
    });

    let sender_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let receiver_wallet = Arc::new(setup_wallet(chain_client.clone(), init_amount).await?);
    let h4 = tokio::task::spawn(async move {
        test_deploy_custom_module(sender_wallet.clone(), receiver_wallet.clone()).await?;
        sender_wallet.stop().await?;
        receiver_wallet.stop().await?;
        debug!("h1 stopped");
        Ok::<_, Error>(())
    });
    h1.await??;
    h2.await??;
    h3.await??;
    h4.await??;
    Ok::<_, Error>(())
}
