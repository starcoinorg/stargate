use std::collections::HashMap;
use std::sync::Arc;

use atomic_refcell::AtomicRefCell;

use chain_client::{ChainClient, RpcChainClient};
use crypto::ed25519::Ed25519Signature;
use failure::prelude::*;
use logger::prelude::*;
use star_types::channel_transaction::ChannelTransaction;
use star_types::resource::Resource;
use star_types::resource_type::resource_def::{ResourceDef, StructDefResolve};
use state_store::{StateStore, StateViewPlus};
use state_view::StateView;
use struct_cache::StructCache;
use types::access_path::{Access, AccessPath};
use types::account_address::AccountAddress;
use types::language_storage::StructTag;
use types::write_set::{WriteOp, WriteSet};
use vm_runtime_types::loaded_data::struct_def::StructDef;

pub use crate::account_state::AccountState;
pub use crate::channel_state::{ChannelState, WitnessData};

pub struct LocalStateStorage<C>
    where
        C: ChainClient,
{
    account: AccountAddress,
    client: Arc<C>,
    channels: AtomicRefCell<HashMap<AccountAddress, ChannelState>>,
    struct_cache: Arc<StructCache>,
}

impl<C> LocalStateStorage<C>
    where
        C: ChainClient,
{
    pub fn new(account: AccountAddress, client: Arc<C>) -> Result<Self> {
        //just check account exist, TODO keep local state cache.
        let _state = Self::get_account_state_by_client(account, client.clone())?;
        Ok(Self {
            account,
            client,
            channels: AtomicRefCell::new(HashMap::new()),
            struct_cache: Arc::new(StructCache::new()),
        })
    }

    fn get_account_state_by_client(account: AccountAddress, client: Arc<C>) -> Result<AccountState> {
        let (version, state_blob, proof) = client.get_account_state_with_proof(&account, None).and_then(|(version, state, proof)| {
            Ok((version, state.ok_or(format_err!("can not find account by address:{}", account))?, proof))
        })?;
        AccountState::from_account_state_blob(version, state_blob, proof)
    }

    pub fn update_witness_data(&self, participant: AccountAddress, channel_sequence_number: u64, write_set: WriteSet, signature: Ed25519Signature) -> Result<()> {
        //TODO check balance.
        self.channels.borrow_mut().entry(participant).and_modify(|state|{
            state.update_witness_data(channel_sequence_number, write_set.clone(), signature.clone());
        }).or_insert(ChannelState::new(participant, WitnessData::new(channel_sequence_number, write_set, signature)));
        Ok(())
    }

    pub fn reset_witness_data(&self, participant: AccountAddress, channel_sequence_number: u64) -> Result<()> {
        self.channels.borrow_mut().get_mut(&participant).and_then(|state|{
            state.reset_witness_data(channel_sequence_number);
            Some(())
        });
        Ok(())
    }

    pub fn get_witness_data(&self, participant: AccountAddress) -> Result<WitnessData> {
        Ok(self.channels.borrow().get(&participant).map(|state|state.witness_data().clone()).unwrap_or(WitnessData::default()))
    }

    pub fn exist_channel(&self, participant: &AccountAddress) -> bool {
        self.channels.borrow().contains_key(participant)
    }

}

impl<C> StateViewPlus for LocalStateStorage<C>
    where
        C: ChainClient,
{}

impl<C> StateView for LocalStateStorage<C>
    where
        C: ChainClient,
{
    //TODO add local cache.
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        if access_path.is_channel_resource() {
            let AccessPath { address, path } = access_path;
            let participant = access_path.data_path().expect("data path must exist").participant().expect("participant must exist");
            let channel_key = if address == &self.account { &participant } else { address };
            match self.channels.borrow().get(channel_key) {
                Some(channel_state) => {
                    match channel_state.get(access_path) {
                        Some(op) => match op {
                            WriteOp::Value(value) => Ok(Some(value.clone())),
                            WriteOp::Deletion => Ok(None)
                        }
                        None => self.client.get_state_by_access_path(access_path)
                    }
                }
                None => self.client.get_state_by_access_path(access_path)
            }
        } else {
            // code and onchain resource directly get remote.

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

impl<C> StructDefResolve for LocalStateStorage<C>
    where
        C: ChainClient,
{
    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.struct_cache.find_struct(tag, self)
    }
}

mod account_state;
mod channel_state;
#[cfg(test)]
mod local_state_storage_test;
