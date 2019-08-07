use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    //pub log_collector: LoggerConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub addr: String,
    pub max_sockets: u64,
    pub memory_stream: bool,
    pub seeds: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoggerConfig {
    pub http_endpoint: Option<String>,
    pub is_async: bool,
    pub chan_size: Option<usize>,
    pub use_std_output: bool,
}

pub fn get_test_config(addr: String, seeds: Vec<String>) -> (NodeConfig) {
    let network = NetworkConfig {
        addr,
        max_sockets: 10,
        memory_stream: true,
        seeds,
    };
    NodeConfig {
        network
    }
}
