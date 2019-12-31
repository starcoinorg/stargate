// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::data_stream::{DataQuery, DataStream};
use anyhow::{format_err, Result};
use async_trait::async_trait;
use libra_types::{
    access_path::DataPath,
    account_config::association_address,
    account_state_blob::AccountStateWithProof,
    contract_event::ContractEvent,
    get_with_proof::RequestItem,
    libra_resource::LibraResource,
    system_config::BlockMetaResource,
    transaction::{Transaction, TransactionInfo, TransactionListWithProof, Version},
};
use sgchain::star_chain_client::ChainClient;
use sgtypes::account_state::AccountState;
use std::{collections::BTreeMap, convert::TryInto, sync::Arc};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionWithInfo {
    pub txn: Transaction,
    pub txn_info: TransactionInfo,
    pub version: u64,
    pub events: Vec<ContractEvent>,
    pub block_height: u64,
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

impl TxnQuerier {
    async fn get_block_hight(&self, start_version: u64) -> Result<u64> {
        let ri = RequestItem::GetAccountState {
            address: association_address(),
        };

        let resp: libra_types::get_with_proof::ResponseItem = self
            .0
            .update_to_latest_ledger_async(&build_request(ri, Some(start_version)))
            .await?
            .response_items
            .remove(0)
            .try_into()?;

        let AccountStateWithProof {
            blob,
            version,
            proof,
        } = resp.into_get_account_state_response()?;

        let blob = blob.ok_or(format_err!("association account not exists!"))?;
        let resp = AccountState::from_account_state_blob(
            version,
            blob.into(),
            proof.transaction_info_to_account_proof().clone(),
        )?;
        let block_meta = resp
            .get_resource::<BlockMetaResource>(&DataPath::onchain_resource_path(
                BlockMetaResource::struct_tag(),
            ))?
            .ok_or(format_err!("block meta resource should exists"))?;
        Ok(block_meta.height)
    }
}

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

                    // TODO: a better way to do it.
                    let block_height = self.get_block_hight(version).await?;
                    c.insert(
                        version,
                        TransactionWithInfo {
                            txn: t,
                            txn_info: info,
                            version,
                            events,
                            block_height,
                        },
                    );
                }
                Ok(c)
            }
        }
    }
}
