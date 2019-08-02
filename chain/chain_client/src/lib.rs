use chain_proto::proto::{chain_grpc, chain::FaucetRequest};
use types::{account_address::AccountAddress, access_path::AccessPath, transaction::SignedTransaction};
use core::borrow::Borrow;
use std::str::FromStr;
use crypto::HashValue;
use star_types::{proto::star_account::AccountState, channel::SgChannelStream};
use types::transaction::Version;
use star_types::resource::Resource;

pub struct ChainClientFacade {
    client: chain_grpc::ChainClient,
}

impl ChainClientFacade {
    fn least_state_root(&mut self) -> HashValue {
        unimplemented!()
    }

    pub fn faucet(&self, addr_str: String, amount: u64) -> Result<(), Box<std::error::Error>> {
        let address = AccountAddress::from_str(&addr_str)?;
        let mut req = FaucetRequest::new();
        req.set_address(address.to_vec());
        req.set_amount(amount);
        let resp = self.client.faucet(&req);
        Ok(())
    }

    fn get_account_state_with_proof_by_state_root(&mut self, address: AccountAddress, state_root_hash: HashValue) -> Vec<u8> {
        unimplemented!()
    }

    fn submit_transaction(&mut self, signedTransaction:SignedTransaction) {
        unimplemented!()
    }

    fn watch_transaction(&mut self, address:AccountAddress, ver:Version) -> SgChannelStream {
        unimplemented!()
    }

    fn state_by_access_path(&mut self, path:AccessPath) -> Vec<u8> {
        unimplemented!()
    }
}