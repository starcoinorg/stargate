// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use atomic_refcell::AtomicRefCell;
use failure::prelude::*;
use libra_crypto::ed25519::Ed25519Signature;
use libra_types::channel_account::ChannelAccountResource;
use libra_types::{access_path::DataPath, account_address::AccountAddress, write_set::WriteSet};
use std::collections::{BTreeMap, HashSet};

//TODO (jole) need maintain network state?
#[derive(Clone, Debug, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub enum ChannelStage {
    /// Channel is waiting to open operator finish.
    Opening,
    /// Channel is idle, can execute new txn.
    Idle,
    /// Channel is pending for some tx not finished.
    Pending,
    Closed,
}

#[derive(Clone, Debug)]
pub struct ChannelState {
    address: AccountAddress,
    state: AtomicRefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl ChannelState {
    pub fn empty(address: AccountAddress) -> Self {
        Self {
            address,
            state: AtomicRefCell::new(BTreeMap::new()),
        }
    }

    pub fn new(address: AccountAddress, state: BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            address,
            state: AtomicRefCell::new(state),
        }
    }

    pub fn paths(&self) -> Result<HashSet<DataPath>> {
        let paths = self
            .state
            .borrow()
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

    pub fn address(&self) -> AccountAddress {
        self.address
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.state.borrow().get(path).cloned()
    }

    pub fn len(&self) -> usize {
        self.state.borrow().len()
    }

    pub fn remove(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.state.borrow_mut().remove(path)
    }

    pub fn insert(&self, path: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.state.borrow_mut().insert(path, value)
    }

    pub fn update_state(&self, state: BTreeMap<Vec<u8>, Vec<u8>>) {
        *self.state.borrow_mut() = state;
    }

    pub fn state(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.state.borrow().clone()
    }
}

#[derive(Clone, Debug, Default)]
pub struct WitnessData {
    pub write_set: WriteSet,
    pub signature: Option<Ed25519Signature>,
}

impl WitnessData {
    pub fn new(write_set: WriteSet, signature: Ed25519Signature) -> Self {
        Self {
            write_set,
            signature: Some(signature),
        }
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
