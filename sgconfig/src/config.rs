use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    //pub log_collector: LoggerConfig,
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

pub fn get_test_config(addr:String,port:u16) -> (NodeConfig) {
    let network = NetworkConfig{
        address:addr,
        port:port,
    };
    NodeConfig{
        network
    }
}
