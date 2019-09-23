use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use atomic_refcell::AtomicRefCell;

use chain_client::{ChainClient, RpcChainClient};
use crypto::ed25519::Ed25519Signature;
use failure::prelude::*;
use logger::prelude::*;
use star_types::message::SgError;
use star_types::resource::Resource;
use star_types::resource_type::resource_def::{ResourceDef, StructDefResolve};
use state_store::{StateStore, StateViewPlus};
use state_view::StateView;
use struct_cache::StructCache;
use types::access_path::{Access, AccessPath, DataPath};
use types::account_address::AccountAddress;
use types::language_storage::StructTag;
use types::transaction::{ChannelWriteSetPayload, TransactionOutput, Version};
use types::write_set::{WriteOp, WriteSet};
use vm_runtime_types::loaded_data::struct_def::StructDef;

pub use crate::account_state::AccountState;
pub use crate::channel::{Channel, WitnessData};
use crate::channel::ChannelState;
pub use crate::channel_state_view::ChannelStateView;
use crate::client_state_view::ClientStateView;

pub struct LocalStateStorage<C>
    where
        C: ChainClient,
{
    account: AccountAddress,
    client: Arc<C>,
    channels: HashMap<AccountAddress, Channel>,
    struct_cache: StructCache,
}

impl<C> LocalStateStorage<C>
    where
        C: ChainClient,
{
    pub fn new(account: AccountAddress, client: Arc<C>) -> Result<Self> {
        let mut storage = Self {
            account,
            client,
            channels: HashMap::new(),
            struct_cache: StructCache::new(),
        };
        storage.refresh_channels()?;
        Ok(storage)
    }

    fn refresh_channels(&mut self) -> Result<()> {
        let account_state = Self::get_account_state_by_client(self.client.clone(), self.account, None)?;
        let my_channel_states = account_state.filter_channel_state();
        let version = account_state.version();
        for (participant, my_channel_state) in my_channel_states {
            if !self.channels.contains_key(&participant) {
                let participant_account_state = Self::get_account_state_by_client(self.client.clone(), participant, Some(version))?;
                let mut participant_channel_states = participant_account_state.filter_channel_state();
                let participant_channel_state = participant_channel_states.remove(&self.account).ok_or(format_err!("Can not find channel {} in {}", self.account, participant))?;
                let channel = Channel::new_with_state(my_channel_state, participant_channel_state);
                info!("Init new channel with: {}", participant);
                self.channels.insert(participant, channel);
            }
        }
        Ok(())
    }

    fn get_account_state_by_client(client: Arc<C>, account: AccountAddress, version: Option<Version>) -> Result<AccountState> {
        let (version, state_blob, proof) = client.get_account_state_with_proof(&account, version).and_then(|(version, state, proof)| {
            Ok((version, state.ok_or(format_err!("can not find account by address:{}", account))?, proof))
        })?;
        AccountState::from_account_state_blob(version, state_blob, proof)
    }

    pub fn get_account_state(&self, account: AccountAddress, version: Option<Version>) -> Result<AccountState> {
        Self::get_account_state_by_client(self.client.clone(), account, version)
    }

    pub fn get_witness_data(&self, participant: AccountAddress) -> Result<WitnessData> {
        Ok(self.channels.get(&participant).map(|state| state.witness_data()).unwrap_or(WitnessData::default()))
    }

    pub fn exist_channel(&self, participant: &AccountAddress) -> bool {
        self.channels.contains_key(participant)
    }

    pub fn new_channel(&mut self, participant: AccountAddress) {
        let channel = Channel::new(self.account, participant);
        self.channels.insert(participant, channel);
    }

    pub fn get_channel(&self, participant: &AccountAddress) -> Result<&Channel> {
        self.channels.get(participant).ok_or(SgError::new_channel_not_exist_error(participant).into())
    }

    pub fn new_state_view(&self, version: Option<Version>, participant: &AccountAddress) -> Result<ChannelStateView<C>> {
        let channel = self.get_channel(participant)?;
        ChannelStateView::new(channel, self.client.clone())
    }

    pub fn get(&self, path: &DataPath) -> Result<Option<Vec<u8>>> {
        if path.is_channel_resource() {
            let participant = path.participant().expect("participant must exist");
            Ok(self.channels.get(&participant).and_then(|channel| channel.get(&AccessPath::new_for_data_path(self.account, path.clone()))))
        } else {
            let account_state = Self::get_account_state_by_client(self.client.clone(), self.account, None)?;
            Ok(account_state.get(&path.to_vec()))
        }
    }

    pub fn get_resource(&self, path: &DataPath) -> Result<Option<Resource>> {
        let state = self.get(path)?;
        let client_state_view = ClientStateView::new(None,self.client.clone());
        match state {
            None => Ok(None),
            Some(state) => {
                let tag = path.resource_tag().ok_or(format_err!("path {:?} is not a resource path.", path))?;
                let def = self.struct_cache.find_struct(&tag, &client_state_view)?;
                Ok(Some(Resource::decode(tag.clone(), def, state.as_slice())?))
            }
        }
    }

}

mod account_state;
mod channel;
mod client_state_view;
mod channel_state_view;
#[cfg(test)]
mod local_state_storage_test;
