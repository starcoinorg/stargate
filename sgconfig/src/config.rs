// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::*;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    pub rpc_config: RpcConfig,
    pub net_config: NetworkConfig,
    pub wallet: WalletConfig,
    pub rest_config: RestConfig,
    //pub log_collector: LoggerConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletConfig {
    pub chain_address: String,
    pub chain_port: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub listen: String,
    pub seeds: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RpcConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RestConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoggerConfig {
    pub http_endpoint: Option<String>,
    pub is_async: bool,
    pub chan_size: Option<usize>,
    pub use_std_output: bool,
}

pub fn load_from(config_file: &str) -> Result<NodeConfig> {
    let content = fs::read_to_string(config_file)?;
    let node_config = toml::from_str(&content)?;
    Ok(node_config)
}

pub fn get_test_config(addr: String, port: u16, rest_port: u16) -> (NodeConfig) {
    let network = RpcConfig {
        address: addr.clone(),
        port,
    };
    let rest = RestConfig {
        address: addr.clone(),
        port: rest_port,
    };
    let node_network = NetworkConfig {
        listen: String::from("/ip4/127.0.0.1/tcp/8000"),
        seeds: vec![],
    };
    let wallet_config = WalletConfig {
        chain_address: addr,
        chain_port: port,
    };
    NodeConfig {
        rpc_config: network,
        net_config: node_network,
        wallet: wallet_config,
        rest_config: rest,
    }
}
