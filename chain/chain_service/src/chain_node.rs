extern crate grpc_helpers;
extern crate types;

use grpc_helpers::spawn_service_thread;
use super::chain_service::ChainService;
use std::thread;

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

    pub fn run(&self) -> Result<(), ()> {
        println!("{}", "Starting chain Service");
        let chain_service = ChainService::new();
        let service = chain_proto::proto::chain_grpc::create_chain(chain_service);
        let _chain_handle = spawn_service_thread(
            service,
            self.config.address.clone(),
            self.config.port.clone(),
            self.config.service_name.clone(),
        );

        println!("{}", "Started chain Service");
        loop {
            thread::park();
        }
    }
}