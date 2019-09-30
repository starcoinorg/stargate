use std::collections::HashMap;

use atomic_refcell::AtomicRefCell;

use super::star_chain_client::ChainClient;
use failure::prelude::*;
use state_view::StateView;
use types::{access_path::AccessPath, account_address::AccountAddress, transaction::Version};

use star_types::account_state::AccountState;

/// A state_view directly fetch remote chain, but lock version.
pub struct ClientStateView<'a> {
    version: Option<Version>,
    client: &'a dyn ChainClient,
    cache: AtomicRefCell<HashMap<AccountAddress, AccountState>>,
}

impl<'a> ClientStateView<'a> {
    pub fn new(version: Option<Version>, client: &'a dyn ChainClient) -> Self {
        Self {
            version,
            client,
            cache: AtomicRefCell::new(HashMap::new()),
        }
    }

    pub fn new_with_account_state(
        account: AccountAddress,
        account_state: AccountState,
        client: &'a dyn ChainClient,
    ) -> Self {
        let version = account_state.version();
        let mut cache = HashMap::new();
        cache.insert(account, account_state);
        Self {
            version: Some(version),
            client,
            cache: AtomicRefCell::new(cache),
        }
    }

    pub fn version(&self) -> Option<Version> {
        self.version
    }
}

impl<'a> StateView for ClientStateView<'a> {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let AccessPath { address, path } = access_path;
        let mut cache = self.cache.borrow_mut();
        let account_state = cache
            .entry(*address)
            .or_insert(self.client.get_account_state(*address, self.version)?);
        Ok(account_state.get(path))
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
