use failure::prelude::*;
use types::{account_address::AccountAddress, access_path::AccessPath, transaction::SignedTransaction};
use types::proto::{transaction::SignedTransaction as SignedTransactionProto, access_path::AccessPath as AccessPathProto};
use core::borrow::Borrow;
use std::str::FromStr;
use crypto::HashValue;
use star_types::{watch_tx_data::WatchTxData, proto::{chain::WatchData, channel_transaction::ChannelTransaction as ChannelTransactionProto, star_account::AccountState, chain::{GetTransactionByVersionRequest, GetTransactionBySeqNumRequest, WatchEventRequest, EventKey as EventKeyProto}}, channel_transaction::ChannelTransaction, channel::SgChannelStream};
use types::transaction::Version;
use star_types::{proto::{chain_grpc, chain::{FaucetRequest, LatestRootRequest, GetAccountStateWithProofRequest, SubmitTransactionRequest, WatchTransactionRequest}}, resource::Resource};
use grpcio::{EnvBuilder, ChannelBuilder};
use std::{sync::Arc, thread};
use proto_conv::IntoProto;
use futures::{Future, Stream};
use watch_stream::WatchStream;
use protobuf::RepeatedField;
use types::event::EventKey;
use proto_conv::FromProto;
use types::contract_event::ContractEvent;
use types::proof::SparseMerkleProof;

pub mod watch_stream;

pub trait ChainClient {
    type WatchResp: Stream<Item=WatchData, Error=grpcio::Error>;

    fn get_account_state_with_proof(&self, address: &AccountAddress, version: Option<Version>) -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)>;
    fn faucet(&self, address: AccountAddress, amount: u64) -> Result<()>;
    fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<()>;
    fn watch_transaction(&self, address: &AccountAddress, ver: Version) -> Result<WatchStream<Self::WatchResp>>;
//    fn get_transaction_by_seq_num(&self, address: &AccountAddress, seq_num: u64) -> Result<SignedTransaction>;
}

#[derive(Clone)]
pub struct RpcChainClient {
    conn_addr: String,
    client: chain_grpc::ChainClient,
}

impl RpcChainClient {
    pub fn new(host: &str, port: u32) -> RpcChainClient {
        let conn_addr = format!("{}:{}", host, port);

        // Create a GRPC client
        let env = Arc::new(EnvBuilder::new().name_prefix("grpc-client-").build());
        let ch = ChannelBuilder::new(env).connect(&conn_addr);
        Self {
            conn_addr,
            client: chain_grpc::ChainClient::new(ch),
        }
    }

}

impl ChainClient for RpcChainClient {
    type WatchResp = grpcio::ClientSStreamReceiver<WatchData>;

    fn get_account_state_with_proof(&self, address: &AccountAddress, version: Option<Version>) -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)>{
        let mut req = GetAccountStateWithProofRequest::new();
        req.set_address(address.to_vec());
        if version.is_some() {
            req.set_ver(version.unwrap());
        }
        let mut resp = self.client.get_account_state_with_proof(&req)?;
        let version = resp.get_version();
        let proof = SparseMerkleProof::from_proto(resp.take_sparse_merkle_proof())?;
        let account_state = if resp.has_account_state_blob() {
            Some(resp.get_account_state_blob().get_blob().to_vec())
        } else {
            None
        };
        Ok((version, account_state, proof))
    }

    fn faucet(&self, address: AccountAddress, amount: u64) -> Result<()> {
        let mut req = FaucetRequest::new();
        req.set_address(address.to_vec());
        req.set_amount(amount);
        let resp = self.client.faucet(&req)?;
        Ok(())
    }

    fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<()> {
        let mut req = SubmitTransactionRequest::new();
        req.set_signed_txn(signed_transaction.into_proto());
        let _resp = self.client.submit_transaction(&req)?;
        Ok(())
    }

    fn watch_transaction(&self, address: &AccountAddress, ver: Version) -> Result<WatchStream<Self::WatchResp>> {
        //        let print_data = move || {
        let mut req = WatchTransactionRequest::new();
        req.set_address(address.to_vec());
        let items_stream = self.client.watch_transaction(&req).unwrap();
        Ok(WatchStream::new(items_stream))
        //            let f = items_stream.for_each(|item| {
        //                println!("received sign {:?}", item);
        //                Ok(())
        //            });
        //            f.wait().unwrap();
        //        };

        //thread::spawn(print_data);
    }

//    fn get_transaction_by_seq_num(&self, address: &AccountAddress, seq_num: u64) -> Result<SignedTransaction> {
//        let mut req = GetTransactionBySeqNumRequest::new();
//        req.set_address(address.to_vec());
//        req.set_seq_num(seq_num);
//        let resp = self.client.get_transaction_by_seq_num(&req);
//        match resp {
//            Ok(tx) => { Ok(SignedTransaction::from_proto(tx.get_signed_tx().clone()).unwrap()) }
//            Err(err) => { bail_err!(err) }
//        }
//    }
}
