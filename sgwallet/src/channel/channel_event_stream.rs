// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::data_stream::{DataQuery, DataStream};
use anyhow::Result;
use async_trait::async_trait;
use libra_types::{
    access_path::AccessPath,
    account_address::AccountAddress,
    contract_event::EventWithProof,
    get_with_proof::{RequestItem, ResponseItem, UpdateToLatestLedgerRequest},
};
use sgchain::star_chain_client::ChainClient;
use std::{collections::BTreeMap, convert::TryInto, sync::Arc};

pub(super) type ChannelEventStream = DataStream<ChannelEventQurier, EventWithProof>;

impl ChannelEventStream {
    pub fn new_from_chain_client(
        chain_client: Arc<dyn ChainClient>,
        channel_address: AccountAddress,
        start_number: u64,
        limit: u64,
    ) -> Self {
        DataStream::new(
            ChannelEventQurier::new(chain_client, channel_address),
            start_number,
            limit,
        )
    }
}

pub(super) struct ChannelEventQurier {
    chain_client: Arc<dyn ChainClient>,
    access_path: AccessPath,
}

impl ChannelEventQurier {
    pub fn new(chain_client: Arc<dyn ChainClient>, channel_address: AccountAddress) -> Self {
        Self {
            chain_client,
            access_path: AccessPath::new_for_channel_event(channel_address),
        }
    }
}

#[async_trait]
impl DataQuery for ChannelEventQurier {
    type Item = EventWithProof;

    async fn query(&self, version: u64, limit: u64) -> Result<BTreeMap<u64, Self::Item>> {
        let ri = RequestItem::GetEventsByEventAccessPath {
            access_path: self.access_path.clone(),
            start_event_seq_num: version,
            ascending: true,
            limit,
        };
        let req = UpdateToLatestLedgerRequest::new(0, vec![ri]).into();
        let client = self.chain_client.clone();
        let mut resp = tokio::task::block_in_place(move || client.update_to_latest_ledger(&req))?;

        let resp: ResponseItem = resp.response_items.remove(0).try_into()?;
        let (events, _) = resp.into_get_events_by_access_path_response()?;
        let mut res = BTreeMap::new();
        for evt in events.into_iter() {
            res.insert(evt.event.sequence_number(), evt);
        }
        Ok(res)
    }
}
