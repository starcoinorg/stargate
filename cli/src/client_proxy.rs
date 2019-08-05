use failure::prelude::*;
use node_client::{NodeClient};
use grpcio::EnvBuilder;
use std::sync::Arc;

pub struct ClientProxy {
    node_client:NodeClient,
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
        })
    }
}
