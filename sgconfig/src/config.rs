use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub node_net_work: NodeNetworkConfig,
    //pub log_collector: LoggerConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NodeNetworkConfig {
    pub addr: String,
    pub max_sockets: u64,
    pub memory_stream: bool,
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

pub fn get_test_config(addr: String, port: u16) -> (NodeConfig) {
    let network = NetworkConfig {
        address: addr,
        port,
    };
    let node_network = NodeNetworkConfig {
        addr: String::from("127.0.0.1:8000"),
        max_sockets: 0,
        memory_stream: false,
        seeds: vec![String::from("127.0.0.1:8001")],
    };
    NodeConfig {
        network,
        node_net_work: node_network,
    }
}
