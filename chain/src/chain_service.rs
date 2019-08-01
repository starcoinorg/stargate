extern crate types;

use crate::proto::chain_grpc::Chain;
use crate::proto::chain::{FaucetRequest, FaucetResponse,
                          GetAccountStateWithProofByStateRootRequest, GetAccountStateWithProofByStateRootResponse,
                          WatchTransactionRequest, WatchTransactionResponse,
                          SubmitTransactionRequest, SubmitTransactionResponse,
                          StateByAccessPathResponse};
use types::proto::{access_path::AccessPath};
use types::transaction::SignedTransaction;
use proto_conv::{FromProto};

#[derive(Clone)]
pub struct ChainService;

impl ChainService {
    pub fn new() -> Self {
        ChainService {}
    }

    pub fn submit_transaction_inner(&self, sign_tx: SignedTransaction) {
        unimplemented!()
    }
}

impl Chain for ChainService {
    fn faucet(&mut self, ctx: ::grpcio::RpcContext,
              req: FaucetRequest,
              sink: ::grpcio::UnarySink<FaucetResponse>) {
        unimplemented!()
    }

    fn get_account_state_with_proof_by_state_root(&mut self, ctx: ::grpcio::RpcContext,
                                                  req: GetAccountStateWithProofByStateRootRequest,
                                                  sink: ::grpcio::UnarySink<GetAccountStateWithProofByStateRootResponse>) {
        unimplemented!()
    }

    fn submit_transaction(&mut self, ctx: ::grpcio::RpcContext,
                          req: SubmitTransactionRequest,
                          sink: ::grpcio::UnarySink<SubmitTransactionResponse>) {
        self.submit_transaction_inner(SignedTransaction::from_proto(req.signed_txn.unwrap()).unwrap());
    }

    fn watch_transaction(&mut self, ctx: ::grpcio::RpcContext,
                         req: WatchTransactionRequest,
                         sink: ::grpcio::ServerStreamingSink<WatchTransactionResponse>) {
        unimplemented!()
    }

    fn state_by_access_path(&mut self, ctx: ::grpcio::RpcContext,
                            req: AccessPath,
                            sink: ::grpcio::UnarySink<StateByAccessPathResponse>) {
        unimplemented!()
    }
}

