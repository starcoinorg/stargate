// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;
use libra_state_view::StateView;
use libra_types::write_set::{WriteOp, WriteSet};
use libra_types::{access_path::AccessPath, transaction::Version};
use sgchain::client_state_view::ClientStateView;
use sgchain::star_chain_client::ChainClient;

use sgtypes::channel::ChannelState;

pub struct ChannelStateView<'txn> {
    account_channel_state: ChannelState,
    participant_channel_state: ChannelState,
    latest_write_set: WriteSet,
    client_state_view: ClientStateView<'txn>,
}

impl<'txn> ChannelStateView<'txn> {
    pub fn new(
        account_channel_state: ChannelState,
        participant_channel_state: ChannelState,
        latest_write_set: WriteSet,
        version: Option<Version>,
        client: &'txn dyn ChainClient,
    ) -> Result<Self> {
        // TODO: make it async
        let account_state = client.get_account_state(account_channel_state.address(), version)?;
        let client_state_view = ClientStateView::new_with_account_state(
            account_channel_state.address(),
            account_state,
            client,
        );
        Ok(Self {
            account_channel_state,
            participant_channel_state,
            latest_write_set,
            client_state_view,
        })
    }

    pub fn version(&self) -> Version {
        self.client_state_view
            .version()
            .expect("client_state_view in ChannelStateView must lock version.")
    }

    fn get_local(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        match self.latest_write_set.get(access_path) {
            Some(op) => match op {
                WriteOp::Value(value) => Some(value.clone()),
                WriteOp::Deletion => None,
            },
            None => {
                if access_path.address == self.participant_channel_state.address() {
                    self.participant_channel_state.get(&access_path.path)
                } else if access_path.address == self.account_channel_state.address() {
                    self.account_channel_state.get(&access_path.path)
                } else {
                    panic!(
                        "Unexpect access_path: {} for this channel: {:?}",
                        access_path,
                        self.participant_channel_state.address()
                    )
                }
            }
        }
    }
}

impl<'txn> StateView for ChannelStateView<'txn> {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        if access_path.is_channel_resource() {
            Ok(self.get_local(access_path))
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
