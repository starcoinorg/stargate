// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_state_view::ChannelStateView;
use crate::tx_applier::TxApplier;
use atomic_refcell::AtomicRefCell;
use failure::prelude::*;
use libra_types::transaction::{ChannelTransactionPayload, ChannelTransactionPayloadBody, Version};
use libra_types::write_set::WriteSet;
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    channel_account::ChannelAccountResource,
    transaction::TransactionOutput,
    write_set::WriteOp,
};
use sgchain::star_chain_client::ChainClient;
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use sgtypes::channel::ChannelInfo;
use sgtypes::channel_transaction::ChannelTransaction;
use sgtypes::channel_transaction_sigs::ChannelTransactionSigs;
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::signed_channel_transaction_with_proof::SignedChannelTransactionWithProof;
use sgtypes::{
    channel::{ChannelStage, ChannelState},
    channel_transaction::{ChannelOp, ChannelTransactionRequestAndOutput},
    sg_error::SgError,
};

#[derive(Debug)]
pub struct Channel {
    /// The version of chain when this ChannelState init.
    //TODO need version?
    //version: Version,
    stage: AtomicRefCell<ChannelStage>,
    /// Current account state in this channel
    account: ChannelState,
    /// Participant state in this channel
    participant: ChannelState,
    pending_txn_request: AtomicRefCell<Option<ChannelTransactionRequestAndOutput>>,
    store: ChannelStore<ChannelDB>,
    tx_applier: TxApplier,
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
            pending_txn_request: AtomicRefCell::new(None),
            store: store.clone(),
            tx_applier: TxApplier::new(store),
        }
    }

    /// load channel from storage
    pub fn load(
        account: ChannelState,
        participant: ChannelState,
        store: ChannelStore<ChannelDB>,
    ) -> Result<Self> {
        let channel = Channel {
            account,
            participant,
            stage: AtomicRefCell::new(ChannelStage::Idle),
            pending_txn_request: AtomicRefCell::new(None),
            store: store.clone(),
            tx_applier: TxApplier::new(store),
        };

        Ok(channel)
    }

    pub fn channel_view<'a>(
        &'a self,
        version: Option<Version>,
        client: &'a dyn ChainClient,
    ) -> Result<ChannelStateView<'a>> {
        ChannelStateView::new(self, version, client)
    }

    pub fn stage(&self) -> ChannelStage {
        *self.stage.borrow()
    }

    pub fn account(&self) -> &ChannelState {
        &self.account
    }

    pub fn participant(&self) -> &ChannelState {
        &self.participant
    }

    pub fn get(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        match self
            .store
            .get_latest_write_set()
            .and_then(|ws| ws.get(access_path).cloned())
        {
            Some(op) => match op {
                WriteOp::Value(value) => Some(value),
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

    /// apply data into local channel storage
    pub fn apply(
        &mut self,
        channel_txn: &ChannelTransaction,
        sender_sigs: &ChannelTransactionSigs,
        receiver_sigs: &ChannelTransactionSigs,
        output: &TransactionOutput,
        participant_witness_payload: ChannelTransactionPayload,
    ) -> Result<()> {
        self.check_stage(vec![ChannelStage::Opening, ChannelStage::Pending])?;
        let _pending_txn = self
            .pending_txn_request
            .borrow()
            .as_ref()
            .expect("must exist");

        match &participant_witness_payload.body {
            ChannelTransactionPayloadBody::WriteSet(_) => {}
            _ => {
                bail!("not witness type");
            }
        }

        let txn_to_apply = ChannelTransactionToApply {
            signed_channel_txn: SignedChannelTransaction {
                raw_tx: channel_txn.clone(),
                sender_signature: sender_sigs.clone(),
                receiver_signature: receiver_sigs.clone(),
            },
            travel: output.is_travel_txn(),
            write_set: if output.is_travel_txn() {
                WriteSet::default()
            } else {
                output.write_set().clone()
            },
            events: output.events().to_vec(),
            major_status: output.status().vm_status().major_status,
        };
        self.tx_applier.apply(txn_to_apply)?;

        if output.is_travel_txn() {
            self.apply_output(output.clone())?;
        }

        *self.pending_txn_request.borrow_mut() = None;
        *self.stage.borrow_mut() = ChannelStage::Idle;

        Ok(())
    }

    pub fn apply_output(&self, output: TransactionOutput) -> Result<()> {
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
        Ok(())
    }

    pub fn witness_data(&self) -> Option<WriteSet> {
        self.store.get_latest_write_set()
    }

    fn get_channel_account_resource(&self, access_path: &AccessPath) -> ChannelAccountResource {
        self.get(access_path)
            .and_then(|value| ChannelAccountResource::make_from(value).ok())
            .expect("channel must contains ChannelAccountResource")
    }

    pub fn channel_info(&self) -> ChannelInfo {
        ChannelInfo::new(self.stage(), self.account_resource())
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

    fn check_stage(&self, expect_stages: Vec<ChannelStage>) -> Result<()> {
        let current_stage = self.stage();
        if !expect_stages.contains(&current_stage) {
            return Err(SgError::new_invalid_channel_stage_error(current_stage).into());
        }
        Ok(())
    }
}

impl Channel {
    /// get signed channel transaction by it's channel_sequence_number
    pub fn get_txn_by_channel_seq_number(
        &self,
        channel_seq_number: u64,
    ) -> Result<SignedChannelTransactionWithProof> {
        self.store
            .get_transaction_by_channel_seq_number(channel_seq_number, false)
    }
}
