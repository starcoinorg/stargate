extern crate types;

use chain_proto::proto::chain_grpc::Chain;
use chain_proto::proto::chain::{LeastRootRequest, LeastRootResponse,
                                FaucetRequest, FaucetResponse,
                                GetAccountStateWithProofByStateRootRequest, GetAccountStateWithProofByStateRootResponse,
                                WatchTransactionRequest, WatchTransactionResponse,
                                SubmitTransactionRequest, SubmitTransactionResponse,
                                StateByAccessPathResponse};
use types::proto::{access_path::AccessPath};
use types::{transaction::SignedTransaction, account_address::AccountAddress};
use proto_conv::FromProto;
use futures::sync::mpsc::{unbounded, UnboundedSender, UnboundedReceiver, SendError};
use super::pub_sub;
use hex;
use futures::MapErr;
use futures::future::Future;
use futures::stream::Stream;
use futures::*;
use grpcio::WriteFlags;

#[derive(Clone)]
pub struct ChainService {
//    merkle:
}

impl ChainService {
    pub fn new() -> Self {
        ChainService {}
    }

    pub fn submit_transaction_inner(&self, sign_tx: SignedTransaction) {
        unimplemented!()
    }

    pub fn watch_transaction_inner(&self, address:Vec<u8>) -> UnboundedReceiver<WatchTransactionResponse> {
        let (mut sender, receiver) = unbounded::<WatchTransactionResponse>();
        let id = hex::encode(address);
        println!("{}:{:?}", "---------0000-------", id);
        pub_sub::subscribe(id, sender.clone());

        receiver
    }
}

impl Chain for ChainService {
    fn least_state_root(&mut self, ctx: ::grpcio::RpcContext, req: LeastRootRequest, sink: ::grpcio::UnarySink<LeastRootResponse>) {
        unimplemented!()
    }
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
        let signed_txn = req.signed_txn.clone().unwrap();
        let mut wt_resp = WatchTransactionResponse::new();
        wt_resp.set_signed_txn(signed_txn);
        pub_sub::send(wt_resp).unwrap();

        self.submit_transaction_inner(SignedTransaction::from_proto(req.signed_txn.unwrap()).unwrap());
    }

    fn watch_transaction(&mut self, ctx: ::grpcio::RpcContext,
                         req: WatchTransactionRequest,
                         mut sink: ::grpcio::ServerStreamingSink<WatchTransactionResponse>) {
        let receiver = self.watch_transaction_inner(req.address);
        let stream = receiver
            .map(|e| (e, WriteFlags::default()))
            .map_err(|_| grpcio::Error::RemoteStopped);

        ctx.spawn(
            sink
                .send_all(stream)
                .map(|_| println!("completed"))
                .map_err(|e| println!("failed to reply: {:?}", e)),
        );
    }

    fn state_by_access_path(&mut self, ctx: ::grpcio::RpcContext,
                            req: AccessPath,
                            sink: ::grpcio::UnarySink<StateByAccessPathResponse>) {
        unimplemented!()
    }
}

