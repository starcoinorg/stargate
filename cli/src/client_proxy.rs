use failure::prelude::*;

pub struct ClientProxy {
}

impl ClientProxy {
    /// Construct a new TestClient.
    pub fn new(
        host: &str,
        ac_port: &str,
        faucet_account_file: &str,
    ) -> Result<Self> {
        
        Ok(ClientProxy {})
    }
}
