#[macro_use]
extern crate rusty_fork;

use std::sync::Arc;

use failure::prelude::*;
use libra_logger::prelude::*;

use sgchain::star_chain_client::StarChainClient;

use crate::wallet_test_helper::{test_deploy_custom_module, test_wallet};

mod wallet_test_helper;

rusty_fork_test! {

    #[test]
    fn test_wallet_with_rpc_client() {
        run_test_wallet_with_rpc_client().unwrap();
    }

    #[test]
    fn test_deploy_custom_module_by_rpc_client() {
        run_deploy_custom_module_by_rpc_client().unwrap();
    }
}

#[test]
// just for manual execute
fn test_wallet_with_rpc_client_manual() {
    run_test_wallet_with_rpc_client().unwrap();
}

fn run_test_wallet_with_rpc_client() -> Result<()> {
    let (_config, _logger, _handler) = sgchain::main_node::run_node(None, false);
    info!("note is running.");
    //TODO use a random port and check port available for port conflict.
    let rpc_client = StarChainClient::new("127.0.0.1", 8000);
    let chain_client = Arc::new(rpc_client);
    test_wallet(chain_client)?;
    Ok(())
}

fn run_deploy_custom_module_by_rpc_client() -> Result<()> {
    let (_config, _logger, _handler) = sgchain::main_node::run_node(None, false);
    info!("note is running.");
    let rpc_client = StarChainClient::new("127.0.0.1", 8000);
    let chain_client = Arc::new(rpc_client);
    test_deploy_custom_module(chain_client)?;
    Ok(())
}
