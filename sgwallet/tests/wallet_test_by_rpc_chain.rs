#[macro_use]
extern crate rusty_fork;
use common::with_wallet;
use libra_logger::prelude::*;
use rpc_chain_test_helper::run_with_rpc_client;

use wallet_test_helper::{
    test_channel_event_watcher_async, test_deploy_custom_module, test_wallet_async,
};

mod common;
mod rpc_chain_test_helper;
mod transfer;
mod wallet_test_helper;

rusty_fork_test! {

    #[test]
    fn test_wallet_with_rpc_client() {
        run_test_wallet_with_rpc_client();
    }

    #[test]
    fn test_deploy_custom_module_by_rpc_client() {
        run_deploy_custom_module_by_rpc_client();
    }

    #[test]
    fn test_wallet_transfer_htlc() {
        run_test_wallet_transfer_htlc();
    }

    #[test]
    fn test_channel_event_watcher() {
        run_test_channel_event_watcher();
    }
}

#[test]
#[ignore]
fn run_test_wallet_transfer_htlc() {
    let result = run_with_rpc_client(|chain_client| {
        with_wallet(chain_client, |rt, sender, receiver| {
            rt.block_on(transfer::transfer_htlc(sender.clone(), receiver.clone()))
        })
    });
    if let Err(e) = result {
        error!("err: {:#?}", e);
        assert!(false);
    }
}

#[test]
#[ignore]
fn run_test_wallet_with_rpc_client() {
    if let Err(e) = run_with_rpc_client(|chain_client| {
        with_wallet(chain_client, |rt, sender, receiver| {
            rt.block_on(test_wallet_async(sender.clone(), receiver.clone()))
        })
    }) {
        error!("err: {:#?}", e);
        assert!(false);
    }
}

#[test]
#[ignore]
fn run_deploy_custom_module_by_rpc_client() {
    if let Err(e) = run_with_rpc_client(|chain_client| test_deploy_custom_module(chain_client)) {
        error!("err: {:#?}", e);
        assert!(false);
    }
}

#[test]
#[ignore]
fn run_test_channel_event_watcher() {
    if let Err(e) = run_with_rpc_client(|chain_client| {
        common::with_wallet(chain_client, |rt, sender, receiver| {
            // the double async block is need, because channel event stream use `block_in_place`.
            // see https://github.com/tokio-rs/tokio/issues/1838
            rt.block_on(async move {
                tokio::spawn(
                    async move { test_channel_event_watcher_async(sender, receiver).await },
                )
                .await
            })?
        })
    }) {
        error!("err: {:#?}", e);
        assert!(false);
    }
}
