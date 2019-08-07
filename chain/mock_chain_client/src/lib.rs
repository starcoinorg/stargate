use failure::prelude::*;
use chain_service::chain_service::ChainService;
use chain_client::ChainClient;
use types::account_address::AccountAddress;
use types::access_path::AccessPath;
use crypto::HashValue;
use tokio::runtime::Runtime;

pub struct MockChainClient {
    chain_service: ChainService,
}

impl MockChainClient {
    pub fn new(rt: &mut Runtime) -> Self {
        Self {
            chain_service: ChainService::new(rt)
        }
    }
}

impl ChainClient for MockChainClient {

    fn least_state_root(&self) -> Result<HashValue> {
        Ok(self.chain_service.least_state_root_inner())
    }

    fn get_account_state(&self, address: &AccountAddress) -> Result<Option<Vec<u8>>> {
        Ok(self.chain_service.get_account_state_with_proof_by_state_root_inner(*address))
    }

    fn get_state_by_access_path(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        Ok(self.chain_service.state_by_access_path_inner(access_path.address, access_path.path.clone()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_mock_client() {
        let mut rt = Runtime::new().unwrap();;
        let client = MockChainClient::new(&mut rt);
        let state = client.get_account_state(&AccountAddress::default()).unwrap().unwrap();
        println!("state: {:#?}", state)
    }
}
