#[macro_use]
extern crate rusty_fork;
use crate::wallet_test_helper::{
    test_channel_event_watcher_async, test_deploy_custom_module, test_wallet_async,
};
use common::with_wallet;
use libra_logger::prelude::*;
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use std::sync::Arc;
pub mod common;
mod transfer;
pub mod wallet_test_helper;

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
            rt.block_on(test_channel_event_watcher_async(sender, receiver))
        })
    }) {
        error!("err: {:#?}", e);
        assert!(false);
    }
}

fn run_with_rpc_client<F, T>(mut f: F) -> T
where
    F: FnMut(Arc<dyn ChainClient>) -> T,
{
    let (config, _logger, _handler) = sgchain::main_node::run_node(None, false, true);
    info!("node is running.");
    let ac_port = config.admission_control.admission_control_service_port;
    let rpc_client = StarChainClient::new("127.0.0.1", ac_port as u32);
    f(Arc::new(rpc_client))
}
