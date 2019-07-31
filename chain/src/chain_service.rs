use crate::proto::chain_grpc::Chain;
use crate::proto::chain::{WatchTransactionRequest, WatchTransactionResponse};

#[derive(Clone)]
pub struct ChainService;

impl ChainService {
    pub fn new() -> Self {
        ChainService {}
    }
}

impl Chain for ChainService {
    fn watch_transaction(&mut self, ctx: ::grpcio::RpcContext,
                         req: WatchTransactionRequest,
                         sink: ::grpcio::ServerStreamingSink<WatchTransactionResponse>) {
        unimplemented!()
    }
}

