// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel::{AccessingResource, Channel, GetPendingTxn};
use anyhow::Result;
use coerce_rt::actor::ActorRef;
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    libra_resource::{make_resource, LibraResource},
};
use serde::de::DeserializeOwned;
use sgtypes::pending_txn::PendingTransaction;
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct ChannelHandle {
    channel_address: AccountAddress,
    account_address: AccountAddress,
    participant_addresses: BTreeSet<AccountAddress>,
    channel_ref: ActorRef<Channel>,
}

impl ChannelHandle {
    // constructor is private to
    pub(crate) fn new(
        channel_address: AccountAddress,
        account_address: AccountAddress,
        participant_addresses: BTreeSet<AccountAddress>,
        channel_ref: ActorRef<Channel>,
    ) -> Self {
        Self {
            channel_address,
            account_address,
            participant_addresses,
            channel_ref,
        }
    }
    pub fn account_address(&self) -> &AccountAddress {
        &self.account_address
    }

    pub fn channel_address(&self) -> &AccountAddress {
        &self.channel_address
    }
    pub fn participant_addresses(&self) -> &BTreeSet<AccountAddress> {
        &self.participant_addresses
    }

    pub fn channel_ref(&self) -> ActorRef<Channel> {
        self.channel_ref.clone()
    }

    #[allow(dead_code)]
    pub async fn stop(&self) -> Result<()> {
        self.channel_ref.clone().stop().await?;
        Ok(())
    }

    pub async fn get_pending_txn(&self) -> Result<Option<PendingTransaction>> {
        Ok(self.channel_ref.clone().send(GetPendingTxn).await?)
    }

    pub async fn get_channel_resource<R: LibraResource + DeserializeOwned>(
        &self,
        data_path: DataPath,
        //        address: AccountAddress,
        //        struct_tag: StructTag,
    ) -> Result<Option<R>> {
        //        let data_path = DataPath::channel_resource_path(address, struct_tag);
        let blob = self
            .channel_ref
            .clone()
            .send(AccessingResource {
                path: AccessPath::new_for_data_path(self.channel_address, data_path),
            })
            .await??;
        blob.map(|b| make_resource::<R>(&b)).transpose()
    }
}
