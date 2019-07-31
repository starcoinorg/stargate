extern crate grpcio;
extern crate grpc_helpers;

use grpcio::Service;
use grpc_helpers::spawn_service_thread;
use crate::proto;
use super::chain_service::ChainService;
use std::thread;

pub struct ServiceConfig {
    service_name: String,
    address: String,
    port: u16,
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

fn main() {
    let service_name = String::from("chain_service");
    let address = String::from("127.0.0.1");
    let port:u16 = 8080;
    let conf = ServiceConfig { service_name, address, port };
    let node = ChainNode::new(conf);
    node.run().unwrap();
}