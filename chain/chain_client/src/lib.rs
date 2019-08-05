use failure::prelude::*;
use chain_proto::proto::{chain_grpc, chain::FaucetRequest};
use types::{account_address::AccountAddress, access_path::AccessPath, transaction::SignedTransaction};
use core::borrow::Borrow;
use std::str::FromStr;
use crypto::HashValue;
use star_types::{proto::star_account::AccountState, channel::SgChannelStream};
use types::transaction::Version;
use star_types::resource::Resource;
use grpcio::{Channel, EnvBuilder, ChannelBuilder};
use std::sync::Arc;

pub struct ChainClientFacade {
    client: chain_grpc::ChainClient,
}

impl ChainClientFacade {

    pub fn new(host:&str, port: u32) -> ChainClientFacade {
        let conn_addr = format!("{}:{}", host, port);

        // Create a GRPC client
        let env = Arc::new(EnvBuilder::new().name_prefix("grpc-client-").build());
        let ch = ChannelBuilder::new(env).connect(&conn_addr);
        Self{
            client: chain_grpc::ChainClient::new(ch)
        }
    }

    pub fn least_state_root(&self) -> HashValue {
        unimplemented!()
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
        unimplemented!()
    }

    pub fn get_account_state(&self, address: &AccountAddress) -> Result<Option<Vec<u8>>> {
        unimplemented!()
    }

    pub fn submit_transaction(&mut self, signed_transaction:SignedTransaction) -> Result<()> {
        unimplemented!()
    }

    pub fn watch_transaction(&self, address:&AccountAddress, ver:Version) -> SgChannelStream {
        unimplemented!()
    }

    pub fn get_state_by_access_path(&self, path:&AccessPath) -> Result<Option<Vec<u8>>> {
        unimplemented!()
    }
}