use chain_client::{RpcChainClient, ChainClient};
use failure::prelude::*;
use state_storage::AccountState;
use state_view::StateView;
use types::access_path::{AccessPath, Access};
use types::account_address::AccountAddress;
use std::sync::Arc;
use std::collections::HashMap;
use star_types::offchain_transaction::OffChainTransaction;
use types::write_set::{WriteSet, WriteOp};

pub struct LocalStateStorage<C> where C:ChainClient {
    account: AccountAddress,
    state: AccountState,
    client: Arc<C>,
    channels: HashMap<AccountAddress, AccountState>
}

impl <C> LocalStateStorage<C> where C:ChainClient {
    pub fn new(account: AccountAddress, client: Arc<C>) -> Result<Self> {
        let state_blob = client.get_account_state(&account).and_then(|state|state.ok_or(bail!("can not find account by address:{}", account)))?;
        let state = AccountState::from_account_state_blob(state_blob)?;
        Ok(Self {
            account,
            state,
            client,
            channels: HashMap::new(),
        })
    }

    pub fn apply_txn(&mut self, txn: &OffChainTransaction) {
        let output = txn.output();
        let write_set = output.write_set();
        self.apply_write_set(write_set);
    }

    fn update(&mut self, access_path: &AccessPath, value: &Vec<u8>){
        if self.account == access_path.address {
            self.state.update(access_path.path.clone(), value.clone());
        }else{
            //TODO check channel
            match self.channels.get_mut(&access_path.address){
                Some(channel_state) => {
                    channel_state.update(access_path.path.clone(), value.clone());
                },
                None => {
                    let mut channel_state = AccountState::new();
                    channel_state.update(access_path.path.clone(), value.clone());
                    self.channels.insert(access_path.address, channel_state);
                }
            }
        }
    }

    fn delete(&mut self, access_path: &AccessPath){
        if self.account == access_path.address {
            self.state.delete(&access_path.path);
        }else{
            //TODO check channel
            match self.channels.get_mut(&access_path.address){
                Some(channel_state) => {
                    channel_state.delete(&access_path.path);
                },
                None => {
                    //no nothing
                }
            }
        }
    }

    pub fn apply_write_set(&mut self, write_set: &WriteSet) {
        for (access_path, op) in write_set {
            match op {
                WriteOp::Value(value) => {
                    self.update(access_path, value);
                },
                WriteOp::Deletion => {
                    self.delete(access_path);
                }
            };
        }
    }
}

impl <C> StateView for LocalStateStorage<C> where C:ChainClient {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let AccessPath { address, path } = access_path;
        if address == &self.account {
            Ok(self.state.get(path))
        } else {
            match self.channels.get(address){
                Some(channel_state) =>  {
                    Ok(channel_state.get(path))
                },
                //TODO chache
                None => self.client.get_state_by_access_path(access_path)
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

#[cfg(test)]
mod local_state_storage_test;