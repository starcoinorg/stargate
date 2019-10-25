// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel::Channel;
pub use crate::channel_state_view::ChannelStateView;
use chashmap::{CHashMap, ReadGuard, WriteGuard};
use failure::prelude::*;
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    transaction::Version,
};
use logger::prelude::*;
use sgchain::client_state_view::ClientStateView;
use sgchain::star_chain_client::ChainClient;
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use sgstorage::storage::SgStorage;
use sgtypes::sg_error::SgError;
use std::path::Path;
use std::sync::Arc;

pub mod channel;
mod channel_state_view;
pub mod tx_applier;

pub struct LocalStateStorage<C>
where
    C: ChainClient,
{
    account: AccountAddress,
    client: Arc<C>,
    sgdb: Arc<SgStorage>,
    channels: CHashMap<AccountAddress, Channel>,
}

impl<C> LocalStateStorage<C>
where
    C: ChainClient,
{
    pub fn new<P: AsRef<Path>>(
        account: AccountAddress,
        store_dir: P,
        client: Arc<C>,
    ) -> Result<Self> {
        let sgdb = Arc::new(SgStorage::new(account, store_dir));
        let mut storage = Self {
            account,
            client,
            sgdb,
            channels: CHashMap::new(),
        };
        storage.refresh_channels()?;
        Ok(storage)
    }

    fn refresh_channels(&mut self) -> Result<()> {
        let account_state = self.client.get_account_state(self.account, None)?;
        let my_channel_states = account_state.filter_channel_state(self.account);
        let version = account_state.version();
        for (participant, my_channel_state) in my_channel_states {
            if !self.channels.contains_key(&participant) {
                let participant_account_state =
                    self.client.get_account_state(participant, Some(version))?;
                let mut participant_channel_states =
                    participant_account_state.filter_channel_state(participant);
                let participant_channel_state = participant_channel_states
                    .remove(&self.account)
                    .ok_or(format_err!(
                        "Can not find channel {} in {}",
                        self.account,
                        participant
                    ))?;
                let channel_store = self.get_channel_store(participant);
                let channel =
                    Channel::load(my_channel_state, participant_channel_state, channel_store)?;
                info!("Init new channel with: {}", participant);
                self.channels.insert(participant, channel);
            }
        }
        Ok(())
    }

    pub fn exist_channel(&self, participant: &AccountAddress) -> bool {
        self.channels.contains_key(participant)
    }

    pub fn new_channel(&self, participant: AccountAddress) {
        self.channels.upsert(
            participant,
            || {
                Channel::new(
                    self.account,
                    participant,
                    self.get_channel_store(participant),
                )
            },
            |_| {},
        );
    }

    pub fn get_channel(
        &self,
        participant: &AccountAddress,
    ) -> Result<ReadGuard<AccountAddress, Channel>> {
        self.channels
            .get(participant)
            .ok_or(SgError::new_channel_not_exist_error(participant).into())
        //        self.channels
        //            .get(participant)
        //            .ok_or(SgError::new_channel_not_exist_error(participant).into())
    }

    pub fn get_channel_mut(
        &self,
        participant: &AccountAddress,
    ) -> Result<WriteGuard<AccountAddress, Channel>> {
        self.channels
            .get_mut(participant)
            .ok_or(SgError::new_channel_not_exist_error(participant).into())
    }

    pub fn new_state_view(&self, version: Option<Version>) -> Result<ClientStateView> {
        Ok(ClientStateView::new(version, &*self.client))
    }

    pub fn get(&self, path: &DataPath) -> Result<Option<Vec<u8>>> {
        if path.is_channel_resource() {
            let participant = path.participant().expect("participant must exist");
            Ok(self.channels.get(&participant).and_then(|channel| {
                channel.get(&AccessPath::new_for_data_path(self.account, path.clone()))
            }))
        } else {
            let account_state = self.client.get_account_state(self.account, None)?;
            Ok(account_state.get(&path.to_vec()))
        }
    }
    //TODO(jole) supported generic resource
    //    pub fn get_resource(&self, path: &DataPath) -> Result<Option<Resource>> {
    //        let state = self.get(path)?;
    //        let state_view = self.new_state_view(None)?;
    //        match state {
    //            None => Ok(None),
    //            Some(state) => {
    //                let tag = path.resource_tag().ok_or(format_err!("path {:?} is not a resource
    // path.", path))?;                let def = self.struct_cache.find_struct(&tag,
    // &state_view)?;                Ok(Some(Resource::decode(tag.clone(), def,
    // state.as_slice())?))            }
    //        }
    //    }

    #[inline]
    fn get_channel_store(&self, participant_address: AccountAddress) -> ChannelStore<ChannelDB> {
        let channel_db = ChannelDB::new(participant_address, self.sgdb.clone());
        ChannelStore::new(channel_db)
    }
}

#[cfg(test)]
mod tests;
