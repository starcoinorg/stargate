// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub use crate::channel_state_view::ChannelStateView;
use failure::prelude::*;
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    transaction::Version,
};
use logger::prelude::*;
use sgchain::client_state_view::ClientStateView;
use sgchain::star_chain_client::ChainClient;
use sgtypes::sg_error::SgError;
use sgtypes::{
    account_state::AccountState,
    channel::{Channel, WitnessData},
};
use std::{collections::HashMap, sync::Arc};

pub struct LocalStateStorage<C>
where
    C: ChainClient,
{
    account: AccountAddress,
    client: Arc<C>,
    channels: HashMap<AccountAddress, Channel>,
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
        };
        storage.refresh_channels()?;
        Ok(storage)
    }

    fn refresh_channels(&mut self) -> Result<()> {
        let account_state = self.get_account_state(self.account, None)?;
        let my_channel_states = account_state.filter_channel_state(self.account);
        let version = account_state.version();
        for (participant, my_channel_state) in my_channel_states {
            if !self.channels.contains_key(&participant) {
                let participant_account_state =
                    self.get_account_state(participant, Some(version))?;
                let mut participant_channel_states =
                    participant_account_state.filter_channel_state(participant);
                let participant_channel_state = participant_channel_states
                    .remove(&self.account)
                    .ok_or(format_err!(
                        "Can not find channel {} in {}",
                        self.account,
                        participant
                    ))?;
                let channel = Channel::new_with_state(my_channel_state, participant_channel_state);
                info!("Init new channel with: {}", participant);
                self.channels.insert(participant, channel);
            }
        }
        Ok(())
    }

    pub fn get_account_state(
        &self,
        account: AccountAddress,
        version: Option<Version>,
    ) -> Result<AccountState> {
        self.client.get_account_state(account, version)
    }

    pub fn get_witness_data(&self, participant: AccountAddress) -> Result<WitnessData> {
        Ok(self
            .channels
            .get(&participant)
            .map(|state| state.witness_data())
            .unwrap_or(WitnessData::default()))
    }

    pub fn exist_channel(&self, participant: &AccountAddress) -> bool {
        self.channels.contains_key(participant)
    }

    pub fn new_channel(&mut self, participant: AccountAddress) {
        let channel = Channel::new(self.account, participant);
        self.channels.insert(participant, channel);
    }

    pub fn get_channel(&self, participant: &AccountAddress) -> Result<&Channel> {
        self.channels
            .get(participant)
            .ok_or(SgError::new_channel_not_exist_error(participant).into())
    }

    pub fn new_channel_view(
        &self,
        version: Option<Version>,
        participant: &AccountAddress,
    ) -> Result<ChannelStateView> {
        let channel = self.get_channel(participant)?;
        ChannelStateView::new(channel, version, &*self.client)
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
            let account_state = self.get_account_state(self.account, None)?;
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
}

mod channel_state_view;
#[cfg(test)]
mod local_state_storage_test;
