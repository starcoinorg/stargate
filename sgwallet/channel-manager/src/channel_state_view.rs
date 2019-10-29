// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;
use libra_types::{access_path::AccessPath, transaction::Version};

use crate::channel::Channel;
use sgchain::client_state_view::ClientStateView;
use sgchain::star_chain_client::ChainClient;
use state_view::StateView;

pub struct ChannelStateView<'txn> {
    channel: &'txn Channel,
    client_state_view: ClientStateView<'txn>,
}

impl<'txn> ChannelStateView<'txn> {
    pub fn new(
        channel: &'txn Channel,
        version: Option<Version>,
        client: &'txn dyn ChainClient,
    ) -> Result<Self> {
        let account_state = client.get_account_state(channel.account().address(), version)?;
        let client_state_view = ClientStateView::new_with_account_state(
            channel.account().address(),
            account_state,
            client,
        );
        Ok(Self {
            channel,
            client_state_view,
        })
    }

    pub fn version(&self) -> Version {
        self.client_state_view
            .version()
            .expect("client_state_view in ChannelStateView must lock version.")
    }
}

impl<'txn> StateView for ChannelStateView<'txn> {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        if access_path.is_channel_resource() {
            Ok(self.channel.get(access_path))
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
