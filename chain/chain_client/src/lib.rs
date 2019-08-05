use failure::prelude::*;
use chain_proto::proto::{chain_grpc, chain::{FaucetRequest, LeastRootRequest, GetAccountStateWithProofByStateRootRequest, SubmitTransactionRequest, WatchTransactionRequest}};
use types::{account_address::AccountAddress, access_path::AccessPath, transaction::SignedTransaction};
use types::proto::{transaction::SignedTransaction as SignedTransactionProto, access_path::AccessPath as AccessPathProto};
use core::borrow::Borrow;
use std::str::FromStr;
use crypto::HashValue;
use star_types::{proto::star_account::AccountState, channel::SgChannelStream};
use types::transaction::Version;
use star_types::resource::Resource;
use grpcio::{Channel, EnvBuilder, ChannelBuilder};
use std::{sync::Arc, thread};
use proto_conv::IntoProto;
use futures::{Future, Stream};

pub struct ChainClientFacade {
    conn_addr:String,
    client: chain_grpc::ChainClient,
}

impl ChainClientFacade {
    pub fn new(host: &str, port: u32) -> ChainClientFacade {
        let conn_addr = format!("{}:{}", host, port);

        // Create a GRPC client
        let env = Arc::new(EnvBuilder::new().name_prefix("grpc-client-").build());
        let ch = ChannelBuilder::new(env).connect(&conn_addr);
        Self {
            conn_addr,
            client: chain_grpc::ChainClient::new(ch)
        }
    }

    pub fn least_state_root(&self) -> HashValue {
        let req = LeastRootRequest::new();
        let resp = self.client.least_state_root(&req);
        HashValue::from_slice(resp.unwrap().state_root_hash.as_slice()).unwrap()
    }

    pub fn faucet(&self, addr_str: String, amount: u64) -> Result<()> {
        let address = AccountAddress::from_str(&addr_str)?;
        let mut req = FaucetRequest::new();
        req.set_address(address.to_vec());
        req.set_amount(amount);
        let resp = self.client.faucet(&req);
        Ok(())
    }

    pub fn get_account_state_with_proof_by_state_root(&self, address: &AccountAddress, state_root_hash: HashValue) -> Result<Option<Vec<u8>>> {
        self.get_account_state(address)
    }

    pub fn get_account_state(&self, address: &AccountAddress) -> Result<Option<Vec<u8>>> {
        let mut req = GetAccountStateWithProofByStateRootRequest::new();
        req.set_address(address.to_vec());
        let resp = self.client.get_account_state_with_proof_by_state_root(&req);
        let result = resp.unwrap().account_state_blob;
        Ok(Some(result))
    }

    pub fn submit_transaction(&mut self, signed_transaction: SignedTransaction) -> Result<()> {
        let mut req = SubmitTransactionRequest::new();
        req.set_signed_txn(signed_transaction.into_proto());
        let resp = self.client.submit_transaction(&req);
        Ok(())
    }

    //TODO
    pub fn watch_transaction(&self, address: &AccountAddress, ver: Version) -> SgChannelStream {
        let watch_channel = ChannelBuilder::new(Arc::new(EnvBuilder::new().build())).connect(&self.conn_addr);
        let watch_client = chain_grpc::ChainClient::new(watch_channel);

        let print_data = move || {
            let mut req = WatchTransactionRequest::new();
            req.set_address(address.to_vec());
            let items_stream = watch_client.watch_transaction(&req).unwrap();
            let f = items_stream.for_each(|item| {
                println!("received sign {:?}", item);
                Ok(())
            });
            f.wait().unwrap();
        };

        //thread::spawn(print_data);
        unimplemented!()
    }

    pub fn get_state_by_access_path(&self, path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let mut req = AccessPathProto::new();
        req.set_address(path.address.to_vec());
        req.set_path(path.path.to_vec());
        let resp = self.client.state_by_access_path(&req);
        let resource = resp.unwrap().resource;
        Ok(Some(resource))
    }
}