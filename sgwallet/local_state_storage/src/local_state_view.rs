use std::collections::HashMap;
use std::sync::Arc;

use atomic_refcell::AtomicRefCell;

use chain_client::ChainClient;
use failure::prelude::*;
use logger::prelude::*;
use star_types::resource_type::resource_def::{ResourceDef, StructDefResolve};
use state_store::StateViewPlus;
use state_view::StateView;
use types::access_path::AccessPath;
use types::account_address::AccountAddress;
use types::language_storage::StructTag;
use types::transaction::Version;

use crate::{AccountState, Channel, LocalStateStorage};

pub struct LocalStateView<'txn, C> where C: ChainClient {
    version: Version,
    storage: &'txn LocalStateStorage<C>,
    cache: AtomicRefCell<HashMap<AccountAddress, AccountState>>,
}

impl<'txn, C> LocalStateView<'txn, C> where C: ChainClient {
    pub fn new(account: AccountState, storage: &'txn LocalStateStorage<C>) -> Self {
        let version = account.version();
        let mut cache = HashMap::new();
        cache.insert(storage.account, account);
        Self {
            version,
            storage,
            cache: AtomicRefCell::new(cache),
        }
    }

    pub fn version(&self) -> Version {
        self.version
    }
}

impl<'txn, C> StateViewPlus for LocalStateView<'txn, C> where C: ChainClient {}

impl<'txn, C> StateView for LocalStateView<'txn, C> where C: ChainClient {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        if access_path.is_channel_resource() {
            let AccessPath { address, path } = access_path;
            let participant = access_path.data_path().expect("data path must exist").participant().expect("participant must exist");
            let channel_key = if address == &self.storage.account { &participant } else { address };
            Ok(self.storage.channels.get(channel_key).and_then(|channel| channel.get(access_path)))
        } else {
            let AccessPath { address, path } = access_path;
            let mut cache = self.cache.borrow_mut();
            let account_state = cache.entry(*address).
                or_insert(LocalStateStorage::get_account_state_by_client(self.storage.client.clone(), *address, Some(self.version))?);
            Ok(account_state.get(path))
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

impl<'txn, C> StructDefResolve for LocalStateView<'txn, C> where C: ChainClient {
    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.storage.struct_cache.find_struct(tag, self)
    }
}