// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;
use libra_types::channel_account::ChannelAccountResource;
use libra_types::{access_path::DataPath, account_address::AccountAddress};
use std::collections::{BTreeMap, HashSet};
use std::ops::{Deref, DerefMut};

//TODO (jole) need maintain network state?
#[derive(Clone, Debug, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub enum ChannelStage {
    /// Channel is waiting to open operator finish.
    Opening,
    /// Channel is idle, can execute new txn.
    Idle,
    /// Channel is pending for some tx not finished.
    Pending,
    /// Channel is(or will start) applying some txn to local db.
    Syncing,
    /// Channel is closed.
    Closed,
}

#[derive(Clone, Debug)]
pub struct ChannelState {
    address: AccountAddress,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ChannelState {
    pub fn empty(address: AccountAddress) -> Self {
        Self {
            address,
            state: BTreeMap::new(),
        }
    }

    pub fn new(address: AccountAddress, state: BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        Self { address, state }
    }

    pub fn paths(&self) -> Result<HashSet<DataPath>> {
        let paths =
            self.state
                .keys()
                .map(|k| DataPath::from(k))
                .try_fold(HashSet::new(), |mut s, e| {
                    e.map(|dp| {
                        s.insert(dp);
                        s
                    })
                });

        paths
    }

    pub fn address(&self) -> &AccountAddress {
        &self.address
    }
}

impl Deref for ChannelState {
    type Target = BTreeMap<Vec<u8>, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for ChannelState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl AsRef<BTreeMap<Vec<u8>, Vec<u8>>> for ChannelState {
    fn as_ref(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.state
    }
}

impl AsMut<BTreeMap<Vec<u8>, Vec<u8>>> for ChannelState {
    fn as_mut(&mut self) -> &mut BTreeMap<Vec<u8>, Vec<u8>> {
        &mut self.state
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ChannelInfo {
    pub stage: ChannelStage,
    pub channel_account: ChannelAccountResource,
}

impl ChannelInfo {
    pub fn new(stage: ChannelStage, channel_account: ChannelAccountResource) -> Self {
        Self {
            stage,
            channel_account,
        }
    }
}
