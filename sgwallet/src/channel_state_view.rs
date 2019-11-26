// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;
use libra_state_view::StateView;
use libra_types::write_set::{WriteSet};
use libra_types::{access_path::AccessPath, transaction::Version};
use sgchain::client_state_view::ClientStateView;
use sgchain::star_chain_client::ChainClient;

use libra_types::account_address::AccountAddress;
use sgtypes::channel::ChannelState;
use std::collections::BTreeMap;

pub struct ChannelStateView<'txn> {
    participant_states: &'txn BTreeMap<AccountAddress, ChannelState>,
    latest_write_set: &'txn WriteSet,
    client_state_view: ClientStateView<'txn>,
}

impl<'txn> ChannelStateView<'txn> {
    pub fn new(
        account_address: AccountAddress,
        participant_states: &'txn BTreeMap<AccountAddress, ChannelState>,
        latest_write_set: &'txn WriteSet,
        version: Option<Version>,
        client: &'txn dyn ChainClient,
    ) -> Result<Self> {
        // TODO: make it async
        let account_state = client.get_account_state(account_address, version)?;
        let client_state_view =
            ClientStateView::new_with_account_state(account_address, account_state, client);
        Ok(Self {
            participant_states,
            latest_write_set,
            client_state_view,
        })
    }

    pub fn version(&self) -> Version {
        self.client_state_view
            .version()
            .expect("client_state_view in ChannelStateView must lock version.")
    }

    pub fn get_local(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        super::channel::access_local(self.latest_write_set, self.participant_states, access_path)
    }
}

impl<'txn> StateView for ChannelStateView<'txn> {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        if access_path.is_channel_resource() {
            self.get_local(access_path)
        } else {
            self.client_state_view.get(access_path)
        }
    }

    fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        self.client_state_view.multi_get(access_paths)
    }

    fn is_genesis(&self) -> bool {
        self.client_state_view.is_genesis()
    }
}
