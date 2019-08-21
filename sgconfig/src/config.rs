use serde::{Deserialize, Serialize};
use std::fs;
use failure::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub node_net_work: NodeNetworkConfig,
    pub wallet: WalletConfig,
    //pub log_collector: LoggerConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletConfig {
    pub chain_address: String,
    pub chain_port: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NodeNetworkConfig {
    pub addr: String,
    pub max_sockets: u64,
    pub in_memory: bool,
    pub seeds: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkConfig {
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

pub fn load_from(config_file:&str)->Result<NodeConfig>{
    let content=fs::read_to_string(config_file)?;
    let node_config=toml::from_str(&content)?;
    Ok(node_config)
}

pub fn get_test_config(addr: String, port: u16) -> (NodeConfig) {
    let network = NetworkConfig {
        address: addr.clone(),
        port,
    };
    let node_network = NodeNetworkConfig {
        addr: String::from("127.0.0.1:8000"),
        max_sockets: 0,
        in_memory: false,
        seeds: vec![String::from("127.0.0.1:8001")],
    };
    let wallet_config = WalletConfig{
        chain_address:addr,
        chain_port:port,
    };
    NodeConfig {
        network,
        node_net_work: node_network,
        wallet:wallet_config,
    }
}
