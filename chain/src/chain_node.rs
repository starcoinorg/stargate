extern crate grpcio;
extern crate grpc_helpers;

use grpcio::Service;
use grpc_helpers::spawn_service_thread;
use crate::proto;
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
        let chain_service = proto::chain_grpc::create_chain(ChainService::new());
        let chain_handle = spawn_service_thread(
            chain_service,
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