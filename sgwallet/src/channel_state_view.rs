// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use libra_state_view::StateView;
use libra_types::{access_path::AccessPath, transaction::Version, write_set::WriteSet};
use sgchain::{client_state_view::ClientStateView, star_chain_client::ChainClient};

use libra_types::account_address::AccountAddress;
use sgtypes::channel::ChannelState;

pub struct ChannelStateView<'txn> {
    channel_state: &'txn ChannelState,
    latest_write_set: &'txn WriteSet,
    client_state_view: ClientStateView<'txn>,
}

impl<'txn> ChannelStateView<'txn> {
    pub fn new(
        account_address: AccountAddress,
        channel_state: &'txn ChannelState,
        latest_write_set: &'txn WriteSet,
        version: Option<Version>,
        client: &'txn dyn ChainClient,
    ) -> Result<Self> {
        // TODO: make it async
        let client_state_view = match version {
            None => {
                let account_state = client.get_account_state(account_address, version)?;
                ClientStateView::new_with_account_state(account_address, account_state, client)
            }
            Some(v) => ClientStateView::new(Some(v), client),
        };

        Ok(Self {
            channel_state,
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
        let d =
            super::channel::access_local(self.latest_write_set, self.channel_state, access_path)?;
        Ok(d.map(|t| t.to_vec()))
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
