// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::data_stream::{DataQuery, DataStream};
use anyhow::Result;
use async_trait::async_trait;
use libra_types::get_with_proof::RequestItem;
use libra_types::transaction::{Transaction, Version};
use sgchain::star_chain_client::ChainClient;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Arc;

pub type TxnStream = DataStream<Transaction>;

impl TxnStream {
    pub fn new_from_chain_client(
        chain_client: Arc<dyn ChainClient>,
        start_version: u64,
        limit: u64,
    ) -> Self {
        DataStream::new(Box::new(TxnQuerier(chain_client)), start_version, limit)
    }
}

pub(crate) fn build_request(
    req: RequestItem,
    ver: Option<Version>,
) -> libra_types::proto::types::UpdateToLatestLedgerRequest {
    libra_types::get_with_proof::UpdateToLatestLedgerRequest::new(ver.unwrap_or(0), vec![req])
        .into()
}

struct TxnQuerier(Arc<dyn ChainClient>);
#[async_trait]
impl DataQuery for TxnQuerier {
    type Item = Transaction;

    async fn query(&self, version: u64, limit: u64) -> Result<BTreeMap<u64, Self::Item>> {
        let ri = RequestItem::GetTransactions {
            start_version: version,
            limit,
            fetch_events: false,
        };
        let client = self.0.clone();

        let mut resp = tokio::task::block_in_place(move || {
            client.update_to_latest_ledger(&build_request(ri, None))
        })?;

        let resp: libra_types::get_with_proof::ResponseItem =
            resp.response_items.remove(0).try_into()?;
        let txns = resp.into_get_transactions_response()?;
        // FIXME: check proof
        match txns.first_transaction_version.as_ref() {
            None => Ok(BTreeMap::new()),
            Some(first_version) => {
                let mut c = BTreeMap::default();

                for (pos, t) in txns.transactions.into_iter().enumerate() {
                    c.insert(*first_version + (pos as u64), t);
                }
                Ok(c)
            }
        }
    }
}
