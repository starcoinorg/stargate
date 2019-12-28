// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::data_stream::{DataQuery, DataStream};
use anyhow::Result;
use async_trait::async_trait;

use libra_types::contract_event::ContractEvent;
use libra_types::get_with_proof::RequestItem;
use libra_types::transaction::{Transaction, TransactionInfo, TransactionListWithProof, Version};
use sgchain::star_chain_client::ChainClient;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionWithInfo {
    pub txn: Transaction,
    pub txn_info: TransactionInfo,
    pub version: u64,
    pub events: Vec<ContractEvent>,
    pub block_id: u64,
}

pub(super) type TxnStream = DataStream<TxnQuerier, TransactionWithInfo>;

impl TxnStream {
    pub fn new_from_chain_client(
        chain_client: Arc<dyn ChainClient>,
        start_version: u64,
        limit: u64,
    ) -> Self {
        DataStream::new(TxnQuerier(chain_client), start_version, limit)
    }
}

pub(crate) fn build_request(
    req: RequestItem,
    ver: Option<Version>,
) -> libra_types::proto::types::UpdateToLatestLedgerRequest {
    libra_types::get_with_proof::UpdateToLatestLedgerRequest::new(ver.unwrap_or(0), vec![req])
        .into()
}

pub(super) struct TxnQuerier(Arc<dyn ChainClient>);
#[async_trait]
impl DataQuery for TxnQuerier {
    type Item = TransactionWithInfo;

    async fn query(&self, version: u64, limit: u64) -> Result<BTreeMap<u64, Self::Item>> {
        let ri = RequestItem::GetTransactions {
            start_version: version,
            limit,
            fetch_events: true,
        };
        let client = self.0.clone();

        let mut resp = tokio::task::block_in_place(move || {
            client.update_to_latest_ledger(&build_request(ri, None))
        })?;

        let resp: libra_types::get_with_proof::ResponseItem =
            resp.response_items.remove(0).try_into()?;
        let txns = resp.into_get_transactions_response()?;
        // FIXME: check proof
        let TransactionListWithProof {
            transactions,
            events,
            first_transaction_version,
            proof,
        } = txns;
        match first_transaction_version.as_ref() {
            None => Ok(BTreeMap::new()),
            Some(first_version) => {
                let mut c = BTreeMap::default();
                for (pos, ((t, info), events)) in transactions
                    .into_iter()
                    .zip(proof.transaction_infos().to_vec().into_iter())
                    .zip(events.unwrap())
                    .enumerate()
                {
                    let version = *first_version + (pos as u64);
                    c.insert(
                        version,
                        TransactionWithInfo {
                            txn: t,
                            txn_info: info,
                            version,
                            events,
                            block_id: 0, // FIXME: implemnet me
                        },
                    );
                }
                Ok(c)
            }
        }
    }
}
