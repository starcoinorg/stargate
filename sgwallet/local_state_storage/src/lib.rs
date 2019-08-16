use chain_client::{ChainClient, RpcChainClient};
use failure::prelude::*;
use logger::prelude::*;
use star_types::offchain_transaction::OffChainTransaction;
use state_storage::{AccountState, StaticStructDefResolve};
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
        let state_blob = client.get_account_state(&account).and_then(|state| {
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

    pub fn apply_txn(&self, txn: &OffChainTransaction) {
        let output = txn.output();
        let change_set = output.change_set();
        self.apply_change_set(change_set);
    }

    pub fn get_by_path(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.state.borrow().get(path)
    }

    fn update(&self, access_path: &AccessPath, value: &Vec<u8>) {
        if self.account == access_path.address {
            self.state.borrow().update(access_path.path.clone(), value.clone());
        } else {
            //TODO check channel
            match self.channels.borrow_mut().get_mut(&access_path.address) {
                Some(channel_state) => {
                    channel_state.update(access_path.path.clone(), value.clone());
                }
                None => {
                    let mut channel_state = AccountState::new();
                    channel_state.update(access_path.path.clone(), value.clone());
                    self.channels.borrow_mut().insert(access_path.address, channel_state);
                }
            }
        }
    }

    fn apply_changes(&self, access_path: &AccessPath, changes: &Changes) {
        //TODO fix unwrap
        let data_path = &access_path.data_path().unwrap();
        debug!("apply {:?} changes:{:#?}", access_path, changes);
        if self.account == access_path.address {
            self.state.borrow().apply_changes(&data_path, changes, self);
        } else {
            //TODO check channel
            let mut channels = self.channels.borrow_mut();
            match channels.get_mut(&access_path.address) {
                Some(channel_state) => {
                    channel_state.apply_changes(&data_path, changes, self);
                }
                None => {
                    debug!("init new channel_state with address:{}", access_path.address);
                    let mut channel_state = AccountState::new();
                    channel_state.apply_changes(&data_path, changes, self);
                    channels.insert(access_path.address, channel_state);
                }
            }
        }
    }

    fn delete(&self, access_path: &AccessPath) {
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
    }

    pub fn apply_write_set(&self, write_set: &WriteSet) {
        self.apply_change_set(&self.write_set_to_change_set(write_set).unwrap())
    }

    //TODO fix dup code.
    pub fn write_set_to_change_set(&self, write_set: &WriteSet) -> Result<ChangeSet> {
        let change_set:Result<Vec<(AccessPath, Changes)>> = write_set.iter().map(|(ap,write_op)|{
            let changes = match write_op {
                WriteOp::Deletion => Changes::Deletion,
                WriteOp::Value(value) => if ap.is_code(){
                    Changes::Value(value.clone())
                }else{
                    let old_resource = self.get_resource(ap)?;
                    let new_resource = Resource::decode(self.resolve(&ap.resource_tag().ok_or(format_err!("get resource tag fail"))?)?, value.as_slice())?;

                    let field_changes = match old_resource {
                        Some(old_resource) => old_resource.diff(&new_resource)?,
                        None => new_resource.to_changes()
                    };
                    Changes::Fields(field_changes)
                }
            };
            Ok((ap.clone(), changes))
        }).collect();
        ChangeSetMut::new(change_set?).freeze()
    }

    pub fn get_resource(&self, access_path: &AccessPath) -> Result<Option<Resource>> {
        let state = self.get(&access_path)?;
        match state {
            None => Ok(None),
            Some(state) => {
                //TODO fix unwrap
                let tag = access_path.resource_tag().unwrap();
                let def = self.resolve(&tag)?;
                Ok(Some(Resource::decode(def, state.as_slice())?))
            }
        }
    }

    pub fn apply_change_set(&self, change_set: &ChangeSet){
        {
            for (access_path, changes) in change_set {
                self.apply_changes(access_path, changes);
            }
        }
    }


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

    fn resolve(&self, tag: &StructTag) -> Result<StructDef> {
        match state_storage::STATIC_STRUCT_DEF_RESOLVE.resolve(tag){
            Ok(result) => Ok(result),
            Err(_) => self.struct_cache.find_struct(tag, self)
        }
    }
}

#[cfg(test)]
mod local_state_storage_test;
