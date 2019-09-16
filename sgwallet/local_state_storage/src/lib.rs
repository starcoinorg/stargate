use chain_client::{ChainClient, RpcChainClient};
use failure::prelude::*;
use logger::prelude::*;
use star_types::channel_transaction::ChannelTransaction;
use state_cache::state_cache::{AccountState};
use state_view::StateView;
use std::collections::HashMap;
use std::sync::Arc;
use types::access_path::{Access, AccessPath};
use types::account_address::AccountAddress;
use types::write_set::{WriteOp, WriteSet};
use star_types::change_set::{ChangeSet, Changes, ChangeSetMut, StructDefResolve};
use star_types::resource::Resource;
use atomic_refcell::AtomicRefCell;
use struct_cache::StructCache;
use types::language_storage::{StructTag};
use vm_runtime_types::loaded_data::struct_def::StructDef;
use state_store::{StateViewPlus, StateStore};
use star_types::resource_type::resource_def::ResourceDef;

pub struct LocalStateStorage<C>
where
    C: ChainClient,
{
    account: AccountAddress,
    state: AtomicRefCell<AccountState>,
    client: Arc<C>,
    channels: AtomicRefCell<HashMap<AccountAddress, AccountState>>,
    struct_cache: Arc<StructCache>,
}

impl<C> LocalStateStorage<C>
where
    C: ChainClient,
{
    pub fn new(account: AccountAddress, client: Arc<C>) -> Result<Self> {
        let state_blob = client.get_account_state_with_proof(&account, None).and_then(|(version, state, proof)| {
            state.ok_or(format_err!("can not find account by address:{}", account))
        })?;
        let state = AtomicRefCell::new(AccountState::from_account_state_blob(state_blob)?);
        Ok(Self {
            account,
            state,
            client,
            channels: AtomicRefCell::new(HashMap::new()),
            struct_cache: Arc::new(StructCache::new()),
        })
    }

    pub fn get_by_path(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.state.borrow().get(path)
    }

    pub fn get_account_state(&self) -> Vec<u8> {
        (&*self.state.borrow()).into()
    }

}

impl<C> StateStore for LocalStateStorage<C>
    where
        C: ChainClient,
{
    fn update(&self, access_path: &AccessPath, value: Vec<u8>) -> Result<()> {
        if self.account == access_path.address {
            self.state.borrow().update(access_path.path.clone(), value.clone());
        } else {
            //TODO check channel
            let mut channels = self.channels.borrow_mut();
            match channels.get_mut(&access_path.address) {
                Some(channel_state) => {
                    channel_state.update(access_path.path.clone(), value.clone());
                }
                None => {
                    let mut channel_state = AccountState::new();
                    channel_state.update(access_path.path.clone(), value.clone());
                    channels.insert(access_path.address, channel_state);
                }
            }
        }
        Ok(())
    }

    fn delete(&self, access_path: &AccessPath) -> Result<()> {
        if self.account == access_path.address {
            self.state.borrow().delete(&access_path.path);
        } else {
            //TODO check channel
            match self.channels.borrow_mut().get_mut(&access_path.address) {
                Some(channel_state) => {
                    channel_state.delete(&access_path.path);
                }
                None => {
                    //no nothing
                }
            }
        }
        Ok(())
    }
}

impl<C> StateViewPlus for LocalStateStorage<C>
    where
        C: ChainClient,
{

}

impl<C> StateView for LocalStateStorage<C>
where
    C: ChainClient,
{
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let AccessPath { address, path } = access_path;
        if address == &self.account {
            Ok(self.state.borrow().get(path))
        } else {
            let mut channels = self.channels.borrow_mut();
            match channels.get(address) {
                Some(channel_state) => Ok(channel_state.get(path)),
                None => {
                    let result = self.client.get_account_state(&access_path.address)?;//get_state_by_access_path(access_path)?;
                    if let Some(state) = &result {
                        debug!("Sync {} channel_state from chain.", access_path.address);
                        let mut channel_state = AccountState::from_account_state_blob(state.clone())?;
                        let resource_state = channel_state.get(path);
                        channels.insert(access_path.address, channel_state);
                        Ok(resource_state)
                    }else{
                        Ok(None)
                    }
                }
            }
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

impl<C>  StructDefResolve for LocalStateStorage<C>
    where
        C: ChainClient,
{

    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.struct_cache.find_struct(tag, self)
    }
}

#[cfg(test)]
mod local_state_storage_test;
