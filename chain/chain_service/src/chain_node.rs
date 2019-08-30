use grpc_helpers::spawn_service_thread;
use super::chain_service::ChainService;
use tokio::{runtime::{Runtime}};
use futures::future::Future;

pub struct ServiceConfig {
    pub service_name: String,
    pub address: String,
    pub port: u16,
}

pub struct ChainNode {
    config: ServiceConfig,
}

impl ChainNode {
    pub fn new(config: ServiceConfig) -> ChainNode {
        ChainNode { config }
    }

    pub fn run(&self) -> () {
        println!("{}", "Starting chain Service");
        let rt = Runtime::new().unwrap();
        let chain_service = ChainService::new(&rt.executor());
        let service = star_types::proto::chain_grpc::create_chain(chain_service);
        let _chain_handle = spawn_service_thread(
            service,
            self.config.address.clone(),
            self.config.port.clone(),
            self.config.service_name.clone(),
        );

        println!("{}", "Started chain Service");
        rt.shutdown_on_idle().wait().unwrap();
    }
}