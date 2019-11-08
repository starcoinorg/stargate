// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_state_view::ChannelStateView;
use crate::tx_applier::TxApplier;
use atomic_refcell::AtomicRefCell;
use failure::prelude::*;
use libra_crypto::HashValue;
use libra_types::transaction::Version;
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
    sg_error::SgError,
};

#[derive(Debug)]
pub struct Channel {
    /// The version of chain when this ChannelState init.
    //TODO need version?
    //version: Version,
    /// Current account state in this channel
    account: ChannelState,
    /// Participant state in this channel
    participant: ChannelState,
    pending_state: PendingState,
    db: ChannelDB,
    store: ChannelStore<ChannelDB>,
    tx_applier: TxApplier,
}

impl Channel {
    /// create channel for participant, use `store` to store tx data.
    pub fn new(account: AccountAddress, participant: AccountAddress, db: ChannelDB) -> Self {
        let store = ChannelStore::new(db.clone());
        let pending_state = PendingState::new();
        Self {
            account: ChannelState::empty(account),
            participant: ChannelState::empty(participant),
            pending_state,
            db,
            store: store.clone(),
            tx_applier: TxApplier::new(store),
        }
    }

    /// load channel from storage
    pub fn load(account: ChannelState, participant: ChannelState, db: ChannelDB) -> Result<Self> {
        let store = ChannelStore::new(db.clone());

        let pending_state = PendingState::new();
        let channel = Channel {
            account,
            participant,
            pending_state,
            db,
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
        if self.pending_state.is_pending() {
            return ChannelStage::Pending;
        }
        let channel_account_resource = self.account_resource();
        match channel_account_resource {
            Some(resource) => {
                if resource.closed() {
                    ChannelStage::Closed
                } else {
                    ChannelStage::Idle
                }
            }
            None => ChannelStage::Opening,
        }
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
    pub fn apply(&mut self) -> Result<()> {
        self.check_stage(vec![ChannelStage::Opening, ChannelStage::Pending])?;
        let (_request_id, channel_txn, txn_output, sender_sigs, receiver_sigs) =
            match self.pending_txn() {
                Some(PendingTransaction::WaitForApply {
                    request_id,
                    raw_tx,
                    sender_sigs,
                    receiver_sigs,
                    output,
                }) => (request_id, raw_tx, output, sender_sigs, receiver_sigs),
                _ => bail!("invalid state of apply txn"),
            };

        let txn_to_apply = ChannelTransactionToApply {
            signed_channel_txn: SignedChannelTransaction::new(
                channel_txn,
                sender_sigs,
                receiver_sigs,
            ),
            events: txn_output.events().to_vec(),
            major_status: txn_output.status().vm_status().major_status,
            write_set: if txn_output.is_travel_txn() {
                None
            } else {
                Some(txn_output.write_set().clone())
            },
        };

        self.tx_applier.apply(txn_to_apply)?;

        if txn_output.is_travel_txn() {
            self.apply_travel_output(txn_output.write_set())?;
        }

        // clear cached pending state
        self.pending_state.clear()?;

        Ok(())
    }

    pub fn apply_travel_output(&self, write_set: &WriteSet) -> Result<()> {
        for (ap, op) in write_set {
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

    pub fn channel_info(&self) -> ChannelInfo {
        ChannelInfo::new(
            self.stage(),
            self.account_resource().unwrap_or_else(|| {
                ChannelAccountResource::new(0, 0, false, self.participant.address())
            }),
        )
    }

    pub fn account_resource(&self) -> Option<ChannelAccountResource> {
        let access_path = AccessPath::new_for_data_path(
            self.account.address(),
            DataPath::channel_account_path(self.participant.address()),
        );
        self.get(&access_path)
            .and_then(|value| ChannelAccountResource::make_from(value).ok())
    }

    pub fn participant_account_resource(&self) -> Option<ChannelAccountResource> {
        let access_path = AccessPath::new_for_data_path(
            self.participant.address(),
            DataPath::channel_account_path(self.account.address()),
        );
        self.get(&access_path)
            .and_then(|value| ChannelAccountResource::make_from(value).ok())
    }

    pub fn pending_txn(&self) -> Option<PendingTransaction> {
        self.pending_state.pend_txn()
    }

    pub fn save_pending_txn(&self, pending_txn: PendingTransaction, _persist: bool) -> Result<()> {
        let cur_pending_txn = self.pending_txn();
        match (&cur_pending_txn, &pending_txn) {
            (None, _)
            | (
                Some(PendingTransaction::WaitForReceiverSig { .. }),
                PendingTransaction::WaitForApply { .. },
            ) => {}
            _ => bail!("cannot save pending txn, state invalid"),
        };
        self.pending_state.store(pending_txn)
    }

    pub fn channel_sequence_number(&self) -> u64 {
        match self.account_resource() {
            None => 0,
            Some(account_resource) => account_resource.channel_sequence_number(),
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

#[derive(Debug, Clone)]
pub enum PendingTransaction {
    WaitForReceiverSig {
        request_id: HashValue,
        raw_tx: ChannelTransaction,
        output: TransactionOutput,
        sender_sigs: ChannelTransactionSigs,
    },
    WaitForApply {
        request_id: HashValue,
        raw_tx: ChannelTransaction,
        output: TransactionOutput,
        sender_sigs: ChannelTransactionSigs,
        receiver_sigs: ChannelTransactionSigs,
    },
}

impl PendingTransaction {
    pub fn request_id(&self) -> HashValue {
        match self {
            PendingTransaction::WaitForReceiverSig { request_id, .. } => request_id.clone(),
            PendingTransaction::WaitForApply { request_id, .. } => request_id.clone(),
        }
    }
}

#[derive(Debug)]
struct PendingState {
    //    store: ChannelStore<ChannelDB>,
    cache: AtomicRefCell<Option<PendingTransaction>>,
}

impl PendingState {
    pub fn new() -> Self {
        Self {
            //            store,
            cache: AtomicRefCell::new(None), // FIXME(caojiafeng): load from store
        }
    }

    pub fn is_pending(&self) -> bool {
        self.cache.borrow().is_some()
    }

    pub fn pend_txn(&self) -> Option<PendingTransaction> {
        self.cache.borrow().as_ref().cloned()
    }

    // TODO(caojiafeng): clear the storage should be in the same db txn of apply
    pub fn clear(&self) -> Result<()> {
        *self.cache.borrow_mut() = None;
        Ok(())
    }

    pub fn store(&self, pending: PendingTransaction) -> Result<()> {
        *self.cache.borrow_mut() = Some(pending);
        Ok(())
    }
}
