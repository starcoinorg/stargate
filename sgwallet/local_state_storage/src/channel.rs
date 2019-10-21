// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use atomic_refcell::AtomicRefCell;
use canonical_serialization::SimpleDeserializer;
use crypto::ed25519::Ed25519Signature;
use failure::prelude::*;
use libra_types::transaction::{ChannelTransactionPayload, ChannelTransactionPayloadBody};
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    channel_account::ChannelAccountResource,
    transaction::{ChannelWriteSetBody, TransactionOutput},
    write_set::{WriteOp, WriteSet},
};

use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use sgtypes::channel::ChannelInfo;
use sgtypes::{
    channel::{ChannelStage, ChannelState, WitnessData},
    channel_transaction::{ChannelOp, ChannelTransactionRequestAndOutput},
    sg_error::SgError,
};
use std::collections::BTreeMap;
use std::convert::TryInto;

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
    store: ChannelStore<ChannelDB>,
}

impl Channel {
    /// create channel for participant, use `store` to store tx data.
    pub fn new(
        account: AccountAddress,
        participant: AccountAddress,
        store: ChannelStore<ChannelDB>,
    ) -> Self {
        Self {
            stage: AtomicRefCell::new(ChannelStage::Opening),
            account: ChannelState::empty(account),
            participant: ChannelState::empty(participant),
            witness_data: AtomicRefCell::new(None),
            pending_txn_request: AtomicRefCell::new(None),
            store,
        }
    }

    /// load channel from storage
    pub fn load(
        account: ChannelState,
        participant: ChannelState,
        store: ChannelStore<ChannelDB>,
    ) -> Result<Self> {
        let channel = Channel {
            store,
            account,
            participant,
            stage: AtomicRefCell::new(ChannelStage::Idle),
            witness_data: AtomicRefCell::new(None),
            pending_txn_request: AtomicRefCell::new(None),
        };

        let channel_info = channel.fetch_channel_info()?;
        let witness_data = channel.fetch_channel_witness_data(channel_info)?;
        *channel.witness_data.borrow_mut() = Some(witness_data);
        Ok(channel)
    }

    /// Fetch startup info for channel identified by `participant`
    fn fetch_channel_info(&self) -> Result<ChannelInfo> {
        let startup_info = self.store.get_startup_info()?;
        if let Some(info) = startup_info {
            Ok(ChannelInfo {
                num_leaves_in_accumulator: info.latest_version + 1,
                frozen_subtrees_in_accumulator: info.ledger_frozen_subtree_hashes,
                state_root_hash: info.account_state_root_hash,
            })
        } else {
            Ok(ChannelInfo::default())
        }
    }
    /// fetch channel witnsss data from storage
    fn fetch_channel_witness_data(&self, channel_info: ChannelInfo) -> Result<WitnessData> {
        // no data in storage
        if channel_info.num_leaves_in_accumulator == 0 {
            return Ok(WitnessData::default());
        }
        let version = channel_info.num_leaves_in_accumulator - 1;

        let my_account_state_with_proof = self.store.get_account_state_with_proof(
            self.account.address(),
            version,
            channel_info.num_leaves_in_accumulator - 1,
        )?;
        let participant_account_state_with_proof = self.store.get_account_state_with_proof(
            self.participant.address(),
            version,
            channel_info.num_leaves_in_accumulator - 1,
        )?;
        // TODO: check proof

        let mut state = BTreeMap::new();
        for (account, state_with_proof) in vec![
            (self.account.address(), my_account_state_with_proof),
            (
                self.participant.address(),
                participant_account_state_with_proof,
            ),
        ]
        .into_iter()
        {
            if let Some(state_blob) = state_with_proof.blob {
                let state_map: BTreeMap<Vec<u8>, Vec<u8>> =
                    SimpleDeserializer::deserialize(state_blob.as_ref())?;
                state.insert(account, state_map);
            }
        }
        let witness_data = WitnessData {
            write_set: (&state).try_into()?,
            signature: None,
        };
        Ok(witness_data)
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
                if access_path.address == self.participant.address() {
                    self.participant.get(&access_path.path)
                } else if access_path.address == self.account.address() {
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
        witness_payload: ChannelWriteSetBody,
        signature: Ed25519Signature,
    ) {
        let ChannelWriteSetBody { write_set, .. } = witness_payload;
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

    pub fn apply_witness(&self, witness_payload: ChannelTransactionPayload) -> Result<()> {
        self.check_stage(vec![ChannelStage::Opening, ChannelStage::Pending])?;
        let ChannelTransactionPayload {
            body,
            receiver_signature,
            ..
        } = witness_payload;
        let body = match body {
            ChannelTransactionPayloadBody::WriteSet(body) => body,
            _ => {
                bail!("not witness type");
            }
        };
        self.update_witness_data(body, receiver_signature);
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
        self.account.update_state(account.state().clone());
        self.participant.update_state(participant.state().clone());
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
                let state = if ap.address == self.account.address() {
                    &self.account
                } else if ap.address == self.participant.address() {
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
            self.account.address(),
            DataPath::channel_account_path(self.participant.address()),
        );
        self.get_channel_account_resource(&access_path)
    }

    pub fn participant_account_resource(&self) -> ChannelAccountResource {
        let access_path = AccessPath::new_for_data_path(
            self.participant.address(),
            DataPath::channel_account_path(self.account.address()),
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
        let operator = request.request.channel_txn().operator().clone();
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
