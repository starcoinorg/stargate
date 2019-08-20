use failure::prelude::*;
use node_client::NodeClient;
use grpcio::EnvBuilder;
use cli_wallet::cli_wallet::WalletLibrary;
use types::{
    account_address::AccountAddress,
};
use chain_client::{RpcChainClient, ChainClient};
use node_proto::{
    OpenChannelRequest,OpenChannelResponse,PayRequest,PayResponse
};
use std::{
    sync::Arc,
};

pub struct ClientProxy {
    node_client: NodeClient,
    wallet: WalletLibrary,
    chain_client: RpcChainClient,
}

impl ClientProxy {
    /// Construct a new TestClient.
    pub fn new(
        host: &str,
        port: u16,
        chain_host: &str,
        chain_port: u16,
        faucet_account_file: &str,
    ) -> Result<Self> {
        let env_builder_arc = Arc::new(EnvBuilder::new().build());
        let node_client = NodeClient::new(env_builder_arc, host, port);
        let chain_client = RpcChainClient::new(chain_host, chain_port as u32);
        Ok(ClientProxy {
            node_client,
            wallet: WalletLibrary::new(faucet_account_file),
            chain_client,
        })
    }

    pub fn get_account(&mut self) -> Result<AccountAddress> {
        Ok(self.wallet.get_address())
    }

    pub fn faucet(&mut self, amount: u64) -> Result<()> {
        self.chain_client.faucet(self.wallet.get_address(), amount)
    }

    pub fn open_channel(&mut self,space_delim_strings: &[&str], is_blocking: bool) -> Result<OpenChannelResponse>{
         unimplemented!();
    }

    pub fn off_chain_pay(&mut self,space_delim_strings: &[&str], is_blocking: bool) -> Result<PayResponse>{
         unimplemented!();
    }

    pub fn account_state(&mut self,) -> Result<Option<Vec<u8>>>{
        match self.chain_client.least_state_root() {
            Ok(hash_value)=>{
                self.chain_client.get_account_state_with_proof_by_state_root(&self.wallet.get_address(),hash_value)
            },
            Err(e)=>{
                bail_err!(e)
            }
        }
    }

}
