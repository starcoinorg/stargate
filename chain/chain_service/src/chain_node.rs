extern crate grpcio;
extern crate grpc_helpers;
extern crate types;

use grpcio::Service;
use grpc_helpers::spawn_service_thread;
use super::chain_service::ChainService;
use std::{thread, fs::File, io::prelude::*, path::PathBuf};
use types::{transaction::{SignedTransaction, TransactionPayload}, write_set::WriteSet};
use protobuf::parse_from_bytes;
use proto_conv::FromProto;
use chain_proto::proto::chain_grpc::Chain;

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
        //self.genesis();
        let chain_handle = spawn_service_thread(
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

//    fn genesis(&self) {
//        let txn = genesis_transaction();
//        let wr = genesis_write_set(txn.clone());
//        self.chain_service.submit_transaction_inner(txn.clone());
//    }
}


pub fn genesis_transaction() -> SignedTransaction {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("chain_service/genesis.blob");

    let mut f = File::open(&path).unwrap();
    let mut bytes = vec![];
    f.read_to_end(&mut bytes).unwrap();
    let txn = SignedTransaction::from_proto(parse_from_bytes(&bytes).unwrap()).unwrap();
    println!("{:?}", txn);
    txn
}

pub fn genesis_write_set(txn: SignedTransaction) -> WriteSet {
    let GENESIS_WRITE_SET: WriteSet = {
        match txn.payload() {
            TransactionPayload::WriteSet(ws) => ws.clone(),
            _ => panic!("Expected writeset txn in genesis txn"),
        }
    };

    GENESIS_WRITE_SET
}

#[cfg(test)]
mod tests {
    use crate::chain_node::genesis_transaction;

    #[test]
    fn testGenesis() {
        genesis_transaction();
    }
}