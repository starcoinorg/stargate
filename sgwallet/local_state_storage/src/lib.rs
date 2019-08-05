use chain_client::ChainClientFacade;
use failure::prelude::*;
use state_storage::AccountState;
use state_view::StateView;
use types::access_path::AccessPath;
use types::account_address::AccountAddress;
use std::sync::Arc;

pub struct LocalStateStorage {
    account: AccountAddress,
    state: AccountState,
    client: Arc<ChainClientFacade>,
}

impl LocalStateStorage {
    pub fn new(account: AccountAddress, client: Arc<ChainClientFacade>) -> Result<Self> {
        let state_blob = client.get_account_state(&account).and_then(|state|state.ok_or(bail!("can not find account by address:{}", account)))?;
        let state = AccountState::from_account_state_blob(state_blob)?;
        Ok(Self {
            account,
            state,
            client,
        })
    }
}

impl StateView for LocalStateStorage {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let AccessPath { address, path } = access_path;
        if address == &self.account {
            Ok(self.state.get(path))
        } else {
            //TODO cache
            self.client.get_state_by_access_path(access_path)
        }
    }

    fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut vec = vec![];
        for path in access_paths {
            vec.push(self.get(path)?);
        }
        Ok(vec)
    }

    fn is_genesis(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod local_state_storage_test;