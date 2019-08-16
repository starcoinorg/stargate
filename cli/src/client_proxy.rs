use failure::prelude::*;
use node_client::{NodeClient};
use grpcio::EnvBuilder;
use std::sync::Arc;
use cli_wallet::cli_wallet::WalletLibrary;
use types::{
    account_address::AccountAddress,
};

pub struct ClientProxy {
    node_client:NodeClient,
    wallet:WalletLibrary,
}

impl ClientProxy {
    /// Construct a new TestClient.
    pub fn new(
        host: &str,
        port: u16,
        faucet_account_file: &str,
    ) -> Result<Self> {
        let env_builder_arc=Arc::new(EnvBuilder::new().build());
        let node_client = NodeClient::new(env_builder_arc, host, port);
        Ok(ClientProxy {
            node_client,
            wallet:WalletLibrary::new(),
        })
    }

    pub fn get_account(&mut self,) -> Result<AccountAddress> {
        Ok(self.wallet.get_address())
    }

}
