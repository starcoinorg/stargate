use std::collections::{HashMap, BTreeMap};
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
pub use crate::local_state_view::LocalStateView;

use types::transaction::{Version, TransactionOutput, ChannelWriteSetPayload};

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
        let storage = Self {
            account,
            client,
            channels: AtomicRefCell::new(HashMap::new()),
            struct_cache: Arc::new(StructCache::new()),
        };
        storage.refresh_channels()?;
        Ok(storage)
    }

    fn refresh_channels(&self) -> Result<()>{
        let account_state = Self::get_account_state_by_client( self.client.clone(), self.account, None)?;
        let mut channels = self.channels.borrow_mut();
        let my_channel_states = account_state.filter_channel_state();
        let version = account_state.version();
        for (participant,my_channel_state) in my_channel_states{
            if !channels.contains_key(&participant) {
                let participant_account_state = Self::get_account_state_by_client(self.client.clone(), participant, Some(version))?;
                let mut participant_channel_states = participant_account_state.filter_channel_state();
                let participant_channel_state = participant_channel_states.remove(&self.account).ok_or(format_err!("Can not find channel {} in {}", self.account, participant))?;
                let channel = ChannelState::new(self.account, participant, my_channel_state, participant_channel_state);
                info!("Init new channel with: {}", participant);
                channels.insert(participant, channel);
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

    pub fn get_witness_data(&self, participant: AccountAddress) -> Result<WitnessData> {
        Ok(self.channels.borrow().get(&participant).and_then(|state|state.witness_data().cloned()).unwrap_or(WitnessData::default()))
    }

    pub fn exist_channel(&self, participant: &AccountAddress) -> bool {
        self.channels.borrow().contains_key(participant)
    }

    pub fn apply_witness(&self, participant: AccountAddress, executed_onchain: bool, witness_payload: ChannelWriteSetPayload, signature: Ed25519Signature) -> Result<()>{
        let mut channels = self.channels.borrow_mut();
        let channel_state = channels.entry(participant).or_insert(ChannelState::new(self.account,participant, BTreeMap::new(), BTreeMap::new()));
        channel_state.apply_witness(executed_onchain, witness_payload, signature);
        Ok(())
    }

    pub fn new_state_view(&self, version: Option<Version>) -> Result<LocalStateView<C>>{
        let account_state = Self::get_account_state_by_client(self.client.clone(), self.account, version)?;
        Ok(LocalStateView::new(account_state,  &self))
    }
}

mod account_state;
mod channel_state;
mod local_state_view;
#[cfg(test)]
mod local_state_storage_test;
