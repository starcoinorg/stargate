use failure::prelude::*;
use chain_service::chain_service::ChainService;
use chain_client::ChainClient;
use types::account_address::AccountAddress;
use types::access_path::AccessPath;
use crypto::HashValue;
use tokio::runtime::Runtime;
use logger::prelude::*;

pub struct MockChainClient {
    rt: Runtime,
    chain_service: Option<ChainService>,
}

impl MockChainClient {
    pub fn new() -> Self {
        let mut client = Self {
            rt: Runtime::new().unwrap(),
            chain_service: None,
        };
        client.init();
        client
    }

    fn init(&mut self){
        self.chain_service = Some(ChainService::new(&mut self.rt))
    }
}

impl ChainClient for MockChainClient {

    fn least_state_root(&self) -> Result<HashValue> {
        Ok(self.chain_service.as_ref().unwrap().least_state_root_inner())
    }

    fn get_account_state(&self, address: &AccountAddress) -> Result<Option<Vec<u8>>> {
        Ok(self.chain_service.as_ref().unwrap().get_account_state_with_proof_by_state_root_inner(*address))
    }

    fn get_state_by_access_path(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        debug!("get_state_by_access_path:{}", access_path);
        Ok(self.chain_service.as_ref().unwrap().state_by_access_path_inner(access_path.address, access_path.path.clone()))
    }

    fn faucet(&self, address: AccountAddress, amount: u64) -> Result<()> {
        self.chain_service.as_ref().unwrap().faucet_inner(address, amount).map(|_|())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client() {
        let mut rt = Runtime::new().unwrap();;
        let client = MockChainClient::new();
        let state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state)
    }
}
