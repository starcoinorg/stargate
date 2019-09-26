use std::collections::HashMap;
use std::sync::Arc;

use atomic_refcell::AtomicRefCell;

use chain_client::ChainClient;
use failure::prelude::*;
use logger::prelude::*;
use star_types::channel::Channel;
use star_types::resource_type::resource_def::{ResourceDef, StructDefResolve};
use state_store::StateViewPlus;
use state_view::StateView;
use types::access_path::AccessPath;
use types::account_address::AccountAddress;
use types::language_storage::StructTag;
use types::transaction::Version;

use crate::LocalStateStorage;
use chain_client::client_state_view::ClientStateView;

pub struct ChannelStateView<'txn, C> where C: ChainClient {
    channel: &'txn Channel,
    client_state_view: ClientStateView<C>,
}

impl<'txn, C> ChannelStateView<'txn, C> where C: ChainClient {
    pub fn new(channel: &'txn Channel, client: Arc<C>) -> Result<Self> {
        let account_state = client.get_account_state(channel.account().address(), None)?;
        let client_state_view = ClientStateView::new_with_account_state(channel.account().address(), account_state, client.clone());
        Ok(Self {
            channel,
            client_state_view,
        })
    }

    pub fn version(&self) -> Version {
        self.client_state_view.version().expect("client_state_view in ChannelStateView must lock version.")
    }
}

impl<'txn, C> StateView for ChannelStateView<'txn, C> where C: ChainClient {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        if access_path.is_channel_resource() {
            let AccessPath { address, path } = access_path;
            let participant = access_path.data_path().expect("data path must exist").participant().expect("participant must exist");
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

