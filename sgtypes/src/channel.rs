// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    channel_transaction::{ChannelOp, ChannelTransactionRequestAndOutput},
    sg_error::SgError,
};
use atomic_refcell::AtomicRefCell;
use crypto::ed25519::Ed25519Signature;
use failure::prelude::*;
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    channel_account::ChannelAccountResource,
    transaction::{ChannelWriteSetPayload, TransactionOutput},
    write_set::{WriteOp, WriteSet},
};
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

#[derive(Clone, Debug)]
pub struct Channel {
    /// The version of chain when this ChannelState init.
    //TODO need version?
    //version: Version,
    stage: AtomicRefCell<ChannelStage>,
    /// Current account state in this channel
    account: ChannelState,
    /// Participant state in this channel
    participant: ChannelState,
    witness_data: AtomicRefCell<Option<WitnessData>>,
    pending_txn_request: AtomicRefCell<Option<ChannelTransactionRequestAndOutput>>,
}

impl Channel {
    pub fn new(account: AccountAddress, participant: AccountAddress) -> Self {
        Self {
            stage: AtomicRefCell::new(ChannelStage::Opening),
            account: ChannelState::empty(account),
            participant: ChannelState::empty(participant),
            witness_data: AtomicRefCell::new(None),
            pending_txn_request: AtomicRefCell::new(None),
        }
    }

    pub fn new_with_state(account: ChannelState, participant: ChannelState) -> Self {
        Self {
            stage: AtomicRefCell::new(ChannelStage::Idle),
            account,
            participant,
            witness_data: AtomicRefCell::new(None),
            pending_txn_request: AtomicRefCell::new(None),
        }
    }

    pub fn stage(&self) -> ChannelStage {
        *self.stage.borrow()
    }

    fn check_stage(&self, expect_stages: Vec<ChannelStage>) -> Result<()> {
        let current_stage = self.stage();
        if !expect_stages.contains(&current_stage) {
            return Err(SgError::new_invalid_channel_stage_error(current_stage).into());
        }
        Ok(())
    }

    pub fn account(&self) -> &ChannelState {
        &self.account
    }

    pub fn participant(&self) -> &ChannelState {
        &self.participant
    }

    pub fn get(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        match self
            .witness_data
            .borrow()
            .as_ref()
            .and_then(|witness_data| witness_data.write_set.get(access_path))
        {
            Some(op) => match op {
                WriteOp::Value(value) => Some(value.clone()),
                WriteOp::Deletion => None,
            },
            None => {
                if access_path.address == self.participant.address {
                    self.participant.get(&access_path.path)
                } else if access_path.address == self.account.address {
                    self.account.get(&access_path.path)
                } else {
                    panic!(
                        "Unexpect access_path: {} for this channel: {:?}",
                        access_path, self
                    )
                }
            }
        }
    }

    fn update_witness_data(
        &self,
        witness_payload: ChannelWriteSetPayload,
        signature: Ed25519Signature,
    ) {
        let ChannelWriteSetPayload { write_set, .. } = witness_payload;
        let mut witness_data = self.witness_data.borrow_mut();
        *witness_data = Some(WitnessData {
            write_set,
            signature: Some(signature),
        })
    }

    fn reset_witness_data(&self) {
        *self.witness_data.borrow_mut() = None
    }

    fn reset_pending_txn_request(&self) {
        *self.pending_txn_request.borrow_mut() = None
    }

    pub fn apply_witness(
        &self,
        witness_payload: ChannelWriteSetPayload,
        signature: Ed25519Signature,
    ) -> Result<()> {
        self.check_stage(vec![ChannelStage::Opening, ChannelStage::Pending])?;
        self.update_witness_data(witness_payload, signature);
        self.reset_pending_txn_request();
        *self.stage.borrow_mut() = ChannelStage::Idle;
        Ok(())
    }

    pub fn apply_state(&self, account: ChannelState, participant: ChannelState) -> Result<()> {
        let _pending_txn = self
            .pending_txn_request
            .borrow()
            .as_ref()
            .expect("must exist");
        self.account.update_state(account.state.borrow().clone());
        self.participant
            .update_state(participant.state.borrow().clone());
        self.reset_witness_data();
        self.reset_pending_txn_request();
        *self.stage.borrow_mut() = ChannelStage::Idle;
        Ok(())
    }

    pub fn apply_output(&self, output: TransactionOutput) -> Result<()> {
        //TODO
        let _pending_txn = self
            .pending_txn_request
            .borrow()
            .as_ref()
            .expect("must exist");
        for (ap, op) in output.write_set() {
            if ap.is_channel_resource() {
                let state = if ap.address == self.account.address {
                    &self.account
                } else if ap.address == self.participant.address {
                    &self.participant
                } else {
                    bail!(
                        "Unexpect witness_payload access_path {:?} apply to channel state {:?}",
                        ap,
                        self.participant
                    );
                };
                match op {
                    WriteOp::Value(value) => state.insert(ap.path.clone(), value.clone()),
                    WriteOp::Deletion => state.remove(&ap.path),
                };
            }
        }
        self.reset_witness_data();
        self.reset_pending_txn_request();
        *self.stage.borrow_mut() = ChannelStage::Idle;
        Ok(())
    }

    pub fn witness_data(&self) -> WitnessData {
        match &*self.stage.borrow() {
            ChannelStage::Opening => WitnessData::default(),
            _ => self
                .witness_data
                .borrow()
                .as_ref()
                .cloned()
                .unwrap_or(WitnessData::default()),
        }
    }

    fn get_channel_account_resource(&self, access_path: &AccessPath) -> ChannelAccountResource {
        self.get(access_path)
            .and_then(|value| ChannelAccountResource::make_from(value).ok())
            .expect("channel must contains ChannelAccountResource")
    }

    pub fn account_resource(&self) -> ChannelAccountResource {
        let access_path = AccessPath::new_for_data_path(
            self.account.address,
            DataPath::channel_account_path(self.participant.address),
        );
        self.get_channel_account_resource(&access_path)
    }

    pub fn participant_account_resource(&self) -> ChannelAccountResource {
        let access_path = AccessPath::new_for_data_path(
            self.participant.address,
            DataPath::channel_account_path(self.account.address),
        );
        self.get_channel_account_resource(&access_path)
    }

    pub fn pending_txn_request(&self) -> Option<ChannelTransactionRequestAndOutput> {
        self.pending_txn_request.borrow().as_ref().cloned()
    }

    pub fn append_txn_request(&self, request: ChannelTransactionRequestAndOutput) -> Result<()> {
        let mut pending_txn_request = self.pending_txn_request.borrow_mut();
        if pending_txn_request.is_some() {
            bail!("exist a pending txn request.");
        }
        let operator = request.request.operator().clone();
        *pending_txn_request = Some(request);
        if operator != ChannelOp::Open {
            *self.stage.borrow_mut() = ChannelStage::Pending;
        }
        Ok(())
    }

    pub fn channel_sequence_number(&self) -> u64 {
        match &*self.stage.borrow() {
            ChannelStage::Opening => 0,
            _ => self.account_resource().channel_sequence_number(),
        }
    }
}
