use failure::prelude::*;
use node_client::NodeClient;
use grpcio::EnvBuilder;
use std::sync::Arc;
use cli_wallet::cli_wallet::WalletLibrary;
use types::{
    account_address::AccountAddress,
};
use chain_client::{RpcChainClient, ChainClient};
use node_proto::{
    OpenChannelRequest,OpenChannelResponse,PayRequest,PayResponse
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
            wallet: WalletLibrary::new(),
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

}
