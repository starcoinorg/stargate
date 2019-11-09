// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_state_view::ChannelStateView;
use crate::tx_applier::TxApplier;
use crate::wallet::{
    execute_transaction, get_channel_transaction_payload_body, txn_expiration, WalletInner,
    GAS_UNIT_PRICE, MAX_GAS_AMOUNT_ONCHAIN,
};
use atomic_refcell::AtomicRefCell;
use failure::prelude::*;
use libra_crypto::{hash::CryptoHash, HashValue, VerifyingKey};
use libra_logger::prelude::*;
use libra_types::transaction::{
    ChannelTransactionPayload, ChannelWriteSetBody, RawTransaction, TransactionArgument, Version,
};
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
use sgtypes::channel_transaction::{
    ChannelOp, ChannelTransaction, ChannelTransactionRequest, ChannelTransactionResponse,
};
use sgtypes::channel_transaction_sigs::{ChannelTransactionSigs, TxnSignature};
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::signed_channel_transaction_with_proof::SignedChannelTransactionWithProof;
use sgtypes::{
    channel::{ChannelStage, ChannelState},
    sg_error::SgError,
};
use vm::gas_schedule::GasAlgebra;

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

    // TODO(caojiafeng): once actor model is used, we don't need to pass the wallet through method.
    pub fn execute<C: ChainClient + Send + Sync + 'static>(
        &self,
        wallet: &WalletInner<C>,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        let state_view = self.channel_view(None, wallet.client())?;

        // build channel_transaction first
        let channel_transaction = ChannelTransaction::new(
            state_view.version(),
            channel_op,
            self.account().address(),
            wallet.sequence_number()?,
            self.participant.address(),
            self.channel_sequence_number(),
            txn_expiration(),
            args,
        );

        // create mocked txn to execute
        let txn =
            wallet.create_mocked_signed_script_txn(self.witness_data(), &channel_transaction)?;
        let output = execute_transaction(&state_view, txn.clone())?;

        // check output gas
        let gas_used = output.gas_used();
        if gas_used > vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get() {
            warn!(
                "GasUsed {} > gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS {}",
                gas_used,
                vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get()
            );
        }

        let channel_write_set = ChannelWriteSetBody::new(
            channel_transaction.channel_sequence_number(),
            output.write_set().clone(),
            channel_transaction.sender(),
        );
        let channel_write_set_hash = channel_write_set.hash();
        let channel_write_set_signature = wallet.sign_message(&channel_write_set_hash);
        let channel_txn_hash = channel_transaction.hash();
        let channel_txn_signature = wallet.sign_message(&channel_txn_hash);

        let channel_txn_sigs = ChannelTransactionSigs::new(
            wallet.public_key().clone(),
            TxnSignature::SenderSig {
                channel_txn_signature,
            },
            channel_write_set_hash,
            channel_write_set_signature,
        );

        let channel_txn_request = ChannelTransactionRequest::new(
            channel_transaction.clone(),
            channel_txn_sigs.clone(),
            output.is_travel_txn(),
        );

        // we need to save the pending txn, in case node nown
        self.save_pending_txn(
            PendingTransaction::WaitForReceiverSig {
                request_id: channel_txn_request.request_id(),
                raw_tx: channel_transaction,
                output,
                sender_sigs: channel_txn_sigs,
            },
            true,
        )?;

        Ok(channel_txn_request)
    }
    /// called by reciever to verify sender's channel_txn.
    fn verify_channel_txn(
        &self,
        channel_txn: &ChannelTransaction,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<()> {
        let channel_sequence_number = self.channel_sequence_number();
        ensure!(
            channel_sequence_number == channel_txn.channel_sequence_number(),
            "check channel_sequence_number fail."
        );
        match &channel_txn_sigs.signature {
            TxnSignature::SenderSig {
                channel_txn_signature,
            } => {
                channel_txn_sigs
                    .public_key
                    .verify_signature(&channel_txn.hash(), channel_txn_signature)?;
            }
            _ => bail!("not support"),
        }
        //TODO check public_key match with sender address.
        Ok(())
    }
    // called by both of sender and reciver, to verify participant's witness payload
    fn verify_channel_witness(
        &self,
        output: &TransactionOutput,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<ChannelTransactionPayload> {
        let write_set_body = ChannelWriteSetBody::new(
            self.channel_sequence_number(),
            output.write_set().clone(),
            self.participant().address(),
        );
        let write_set_body_hash = write_set_body.hash();
        ensure!(
            write_set_body_hash == channel_txn_sigs.write_set_payload_hash.clone(),
            "channel output hash mismatched"
        );
        channel_txn_sigs.public_key.verify_signature(
            &write_set_body_hash,
            &channel_txn_sigs.write_set_payload_signature,
        )?;

        Ok(ChannelTransactionPayload::new_with_write_set(
            write_set_body,
            channel_txn_sigs.public_key.clone(),
            channel_txn_sigs.write_set_payload_signature.clone(),
        ))
    }

    /// called by sender, to verify receiver's response
    fn verify_response<C: ChainClient + Send + Sync + 'static>(
        &self,
        wallet: &WalletInner<C>,
        channel_txn: &ChannelTransaction,
        output: &TransactionOutput,
        receiver_sigs: &ChannelTransactionSigs,
    ) -> Result<(ChannelTransactionPayload, ChannelTransactionPayload)> {
        let channel_txn_sigs = receiver_sigs;

        let raw_txn =
            wallet.build_raw_txn_from_channel_txn(self.witness_data(), channel_txn, None)?;

        // verify receiver's channel txn payload signature
        let verified_channel_txn_payload = match &channel_txn_sigs.signature {
            TxnSignature::ReceiverSig {
                channel_script_body_signature,
            } => {
                let channel_payload = get_channel_transaction_payload_body(&raw_txn)?;
                channel_payload
                    .verify(&channel_txn_sigs.public_key, channel_script_body_signature)?;
                ChannelTransactionPayload::new(
                    channel_payload,
                    channel_txn_sigs.public_key.clone(),
                    channel_script_body_signature.clone(),
                )
            }
            _ => bail!("should not happen"),
        };

        let verified_participant_witness_payload =
            self.verify_channel_witness(&output, channel_txn_sigs)?;
        Ok((
            verified_channel_txn_payload,
            verified_participant_witness_payload,
        ))
    }

    pub fn verify_txn_request<C: ChainClient + Send + Sync + 'static>(
        &self,
        wallet: &WalletInner<C>,
        txn_request: &ChannelTransactionRequest,
    ) -> Result<ChannelTransactionResponse> {
        let request_id = txn_request.request_id();
        let channel_txn = txn_request.channel_txn();
        let channel_txn_sender_sigs = txn_request.channel_txn_sigs();

        self.verify_channel_txn(channel_txn, channel_txn_sender_sigs)?;

        let signed_txn =
            wallet.create_mocked_signed_script_txn(self.witness_data(), channel_txn)?;
        let txn_payload_signature = signed_txn
            .receiver_signature()
            .expect("signature must exist.");

        let version = channel_txn.version();
        let output = {
            let state_view = self.channel_view(Some(version), wallet.client())?;
            execute_transaction(&state_view, signed_txn)?
        };

        let _verified_participant_witness_payload =
            self.verify_channel_witness(&output, channel_txn_sender_sigs)?;

        // build signatures sent to sender
        let write_set_body = ChannelWriteSetBody::new(
            self.channel_sequence_number(),
            output.write_set().clone(),
            self.account().address(),
        );
        let witness_hash = write_set_body.hash();
        let witness_signature = wallet.sign_message(&witness_hash);

        let channel_txn_receiver_sigs = ChannelTransactionSigs::new(
            wallet.public_key().clone(),
            TxnSignature::ReceiverSig {
                channel_script_body_signature: txn_payload_signature,
            },
            witness_hash,
            witness_signature,
        );

        // if it's a travel txn, we need to persist the pending apply txn before reply to sender.
        // just in case that the node is down after sending reply to sender.
        // in this case, if it's not saved, receiver has no way to get channel_txn from onchain txn,
        // if it's offchain, there is no need. because:
        // - if sender receive the msg from receiver, receiver can sync it from sender.
        // - if sender doesn't receive the msg, sender will resend the request to receiver, as if nothing happens.

        {
            let should_persist = output.is_travel_txn();
            self.save_pending_txn(
                PendingTransaction::WaitForApply {
                    request_id,
                    raw_tx: channel_txn.clone(),
                    sender_sigs: channel_txn_sender_sigs.clone(),
                    receiver_sigs: channel_txn_receiver_sigs.clone(),
                    output,
                },
                should_persist,
            )?;
        }

        Ok(ChannelTransactionResponse::new(
            request_id,
            channel_txn_receiver_sigs,
        ))
    }

    pub fn verify_txn_response<C: ChainClient + Send + Sync + 'static>(
        &self,
        wallet: &WalletInner<C>,
        response: &ChannelTransactionResponse,
    ) -> Result<(ChannelTransactionPayload, ChannelTransactionPayload)> {
        let (request_id, channel_txn, output, sender_sigs) = match self.pending_txn() {
            Some(PendingTransaction::WaitForReceiverSig {
                request_id,
                raw_tx,
                output,
                sender_sigs,
            }) => (request_id, raw_tx, output, sender_sigs),
            //TODO(jole) can not find request has such reason:
            // 1. txn is expire.
            // 2. txn is invalid.
            _ => bail!("invalid state when sender apply txn"),
        };

        ensure!(
            request_id == response.request_id(),
            "request id mismatch, request: {}, response: {}",
            request_id,
            response.request_id()
        );

        info!("verify channel response: {}", response.request_id());
        let (verified_participant_script_payload, verified_participant_witness_payload) =
            self.verify_response(&wallet, &channel_txn, &output, response.channel_txn_sigs())?;

        let _gas_used = output.gas_used();
        let is_travel = output.is_travel_txn();

        // if it's a travel txn, we need to save the pending apply txn before submit to layer1.
        // just in case that the node is down after submit.
        // in this case, if it's not saved, receiver has no way to get channel_txn from onchain txn,
        // if it's offchain, there is no need. because:
        // - sender will resend the txn to receiver, and receiver will reply the msg.
        self.save_pending_txn(
            PendingTransaction::WaitForApply {
                request_id,
                raw_tx: channel_txn.clone(),
                sender_sigs: sender_sigs.clone(),
                receiver_sigs: response.channel_txn_sigs().clone(),
                output,
            },
            is_travel,
        )?;
        Ok((
            verified_participant_script_payload,
            verified_participant_witness_payload,
        ))
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

pub fn pending_txn_to_onchain_txn(
    pending_txn: PendingTransaction,
    verified_participant_script_payload: ChannelTransactionPayload,
) -> Result<Option<RawTransaction>> {
    let (channel_txn, output) = match pending_txn {
        PendingTransaction::WaitForApply { raw_tx, output, .. } => (raw_tx, output),
        _ => bail!("invalid state when apply to onchain"),
    };

    let gas_used = output.gas_used();
    if !output.is_travel_txn() {
        return Ok(None);
    }
    // construct onchain tx
    let max_gas_amount = std::cmp::min((gas_used as f64 * 1.1) as u64, MAX_GAS_AMOUNT_ONCHAIN);
    let new_raw_txn = RawTransaction::new_channel(
        channel_txn.sender(),
        channel_txn.sequence_number(),
        verified_participant_script_payload,
        max_gas_amount,
        GAS_UNIT_PRICE,
        channel_txn.expiration_time(),
    );
    Ok(Some(new_raw_txn))
}
