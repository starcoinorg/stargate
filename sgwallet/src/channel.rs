// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_state_view::ChannelStateView;
use crate::scripts::PackageRegistry;
use crate::tx_applier::TxApplier;
use crate::wallet::{
    execute_transaction, get_channel_transaction_payload_body, respond_with, submit_transaction,
    txn_expiration, watch_transaction, GAS_UNIT_PRICE, MAX_GAS_AMOUNT_OFFCHAIN,
    MAX_GAS_AMOUNT_ONCHAIN,
};
use failure::prelude::*;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use libra_crypto::test_utils::KeyPair;
use libra_crypto::{hash::CryptoHash, SigningKey, VerifyingKey};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::transaction::helpers::TransactionSigner;
use libra_types::transaction::{
    ChannelScriptBody, ChannelTransactionPayload, ChannelTransactionPayloadBody,
    ChannelWriteSetBody, RawTransaction, SignedTransaction, TransactionArgument,
    TransactionWithProof, Version,
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
use sgtypes::channel_transaction::{
    ChannelOp, ChannelTransaction, ChannelTransactionRequest, ChannelTransactionResponse,
};
use sgtypes::channel_transaction_sigs::{ChannelTransactionSigs, TxnSignature};
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::pending_txn::PendingTransaction;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::{
    channel::{ChannelStage, ChannelState},
    sg_error::SgError,
};
use std::sync::Arc;
use vm::gas_schedule::GasAlgebra;

pub enum ChannelMsg {
    Execute {
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
        responder: oneshot::Sender<Result<ChannelTransactionRequest>>,
    },
    VerifyTxnRequest {
        txn_request: ChannelTransactionRequest,
        responder: oneshot::Sender<Result<ChannelTransactionResponse>>,
    },
    VerifyTxnResponse {
        txn_response: ChannelTransactionResponse,
        responder: oneshot::Sender<Result<()>>,
    },
    ApplyPendingTxn {
        responder: oneshot::Sender<Result<u64>>,
    },
    GetPendingChannelTransactionRequest {
        responder: oneshot::Sender<Result<Option<ChannelTransactionRequest>>>,
    },
    AccessPath {
        path: AccessPath,
        responder: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
}
enum InternalMsg {
    ApplyPendingTxn, // when channel bootstrap, it will send this msg if it found pending txn.
}

pub enum ChainMsg {
    SubmitTxn {
        signed_txn: SignedTransaction,
        responder: oneshot::Sender<()>,
    },
    WatchTxn {
        address: AccountAddress,
        seq_number: u64,
        responder: oneshot::Sender<Option<TransactionWithProof>>,
    },
}

pub struct Channel {
    /// The version of chain when this ChannelState init.
    //TODO need version?
    //version: Version,
    account_address: AccountAddress,
    participant_address: AccountAddress,
    //    db: ChannelDB,
    //    store: ChannelStore<ChannelDB>,
    mail_sender: mpsc::Sender<ChannelMsg>,
    inner: Option<Inner>,
}

impl Channel {
    /// create channel for participant, use `store` to store tx data.
    pub fn new(
        account: AccountAddress,
        participant: AccountAddress,
        db: ChannelDB,
        mail_sender: mpsc::Sender<ChannelMsg>,
        mailbox: mpsc::Receiver<ChannelMsg>,

        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        script_registry: Arc<PackageRegistry>,
        chain_client: Arc<dyn ChainClient>,
    ) -> Self {
        Self::load(
            ChannelState::empty(account),
            ChannelState::empty(participant),
            db,
            mail_sender,
            mailbox,
            keypair,
            script_registry,
            chain_client,
        )
    }

    /// load channel from storage
    pub fn load(
        account: ChannelState,
        participant: ChannelState,
        db: ChannelDB,
        mail_sender: mpsc::Sender<ChannelMsg>,
        mailbox: mpsc::Receiver<ChannelMsg>,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        script_registry: Arc<PackageRegistry>,
        chain_client: Arc<dyn ChainClient>,
    ) -> Self {
        let store = ChannelStore::new(db.clone());
        let account_address = account.address();
        let participant_address = participant.address();
        let inner = Inner {
            account_address,
            participant_address,
            account,
            participant,
            store: store.clone(),
            keypair: keypair.clone(),
            script_registry: script_registry.clone(),
            chain_client: chain_client.clone(),
            tx_applier: TxApplier::new(store.clone()),
            mailbox,
        };
        let channel = Self {
            account_address,
            participant_address,
            mail_sender,
            inner: Some(inner),
        };
        channel
    }

    pub fn start(&mut self, executor: tokio::runtime::TaskExecutor) {
        let inner = self.inner.take().expect("channel already started");
        // TODO: wait channel start?
        executor.spawn(inner.start())
    }

    pub fn account_address(&self) -> &AccountAddress {
        &self.account_address
    }
    pub fn participant_address(&self) -> &AccountAddress {
        &self.participant_address
    }

    pub fn mail_sender(&self) -> mpsc::Sender<ChannelMsg> {
        self.mail_sender.clone()
    }
}

struct Inner {
    account_address: AccountAddress,
    participant_address: AccountAddress,
    /// Current account state in this channel
    account: ChannelState,
    /// Participant state in this channel
    participant: ChannelState,
    //    db: ChannelDB,
    store: ChannelStore<ChannelDB>,
    keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    script_registry: Arc<PackageRegistry>,
    chain_client: Arc<dyn ChainClient>,
    tx_applier: TxApplier,

    mailbox: mpsc::Receiver<ChannelMsg>,
    // event produced by the channel
    // channel_event_sender: mpsc::Sender<ChannelEvent>,
}

impl Inner {
    async fn start(mut self) {
        let (internal_msg_tx, mut internal_msg_rx) = mpsc::channel(1024);
        self.bootstrap(internal_msg_tx.clone());

        loop {
            ::futures::select! {
                maybe_external_msg = self.mailbox.next() => {
                    if let Some(msg) = maybe_external_msg {
                         self.handle_external_msg(msg).await;
                    }
                }
                maybe_internal_msg = internal_msg_rx.next() => {
                    if let(Some(msg)) = maybe_internal_msg {
                        self.handle_internal_msg(msg).await;
                    }
                }
                complete => {
                    break;
                }
            }
        }
        crit!("channel task terminated")
    }

    fn bootstrap(&mut self, mut internal_msg_tx: mpsc::Sender<InternalMsg>) {
        match self.pending_txn() {
            None => {}
            Some(PendingTransaction::WaitForReceiverSig { .. }) => {}
            Some(PendingTransaction::WaitForApply {
                request_id: _,
                raw_tx: _,
                output,
                sender_sigs: _,
                receiver_sigs: _,
            }) => {
                debug_assert!(output.is_travel_txn(), "only travel txn is persisted");
                if let Err(_e) = internal_msg_tx.try_send(InternalMsg::ApplyPendingTxn) {
                    error!("should not happen");
                }
                //                let gas = self.apply_pending_txn_async().await?;
                //                info!("sync txn from onchain successfully, gas used: {}", gas);
            }
        }
    }

    async fn handle_external_msg(&mut self, cmd: ChannelMsg) {
        match cmd {
            ChannelMsg::Execute {
                channel_op,
                args,
                responder,
            } => {
                let request = self.execute_async(channel_op, args).await;
                respond_with(responder, request);
            }
            ChannelMsg::VerifyTxnRequest {
                txn_request,
                responder,
            } => {
                let response = self.verify_txn_request_async(txn_request).await;

                respond_with(responder, response);
            }
            ChannelMsg::VerifyTxnResponse {
                txn_response,
                responder,
            } => {
                let response = self.verify_txn_response_async(txn_response).await;
                respond_with(responder, response);
            }
            ChannelMsg::ApplyPendingTxn { responder } => {
                let response = self.apply_pending_txn_async().await;
                respond_with(responder, response);
            }
            ChannelMsg::AccessPath { path, responder } => {
                let response = self.get_local(&path);
                respond_with(responder, response);
            }
            ChannelMsg::GetPendingChannelTransactionRequest { responder } => {
                let response = self.get_pending_channel_txn_request();
                respond_with(responder, Ok(response));
            }
        };
    }

    async fn handle_internal_msg(&mut self, internal_msg: InternalMsg) {
        match internal_msg {
            InternalMsg::ApplyPendingTxn => match self.apply_pending_txn_async().await {
                Ok(gas) => {
                    info!("apply pending txn successfully, gas used: {}", gas);
                }
                Err(e) => {
                    error!("apply pending txn failed, err: {:?}", e);
                }
            },
        }
    }

    fn channel_view<'a>(
        &self,
        version: Option<Version>,
        client: &'a dyn ChainClient,
    ) -> Result<ChannelStateView<'a>> {
        let (account, participant, latest_writeset) = {
            (
                self.account.clone(),
                self.participant.clone(),
                self.witness_data().unwrap_or_default(),
            )
        };
        ChannelStateView::new(account, participant, latest_writeset, version, client)
    }

    fn build_raw_txn_from_channel_txn(
        &self,
        channel_witness_data: Option<WriteSet>,
        channel_txn: &ChannelTransaction,
        payload_key_and_signature: Option<(Ed25519PublicKey, Ed25519Signature)>,
    ) -> Result<RawTransaction> {
        let channel_txn_payload = self.build_channel_script_payload(
            channel_witness_data,
            channel_txn,
            payload_key_and_signature,
        )?;
        Ok(RawTransaction::new_channel(
            channel_txn.sender(),
            channel_txn.sequence_number(),
            channel_txn_payload,
            MAX_GAS_AMOUNT_OFFCHAIN,
            GAS_UNIT_PRICE,
            channel_txn.expiration_time(),
        ))
    }

    fn build_channel_script_payload(
        &self,
        channel_witness_data: Option<WriteSet>,
        channel_txn: &ChannelTransaction,
        participant_key_and_signature: Option<(Ed25519PublicKey, Ed25519Signature)>,
    ) -> Result<ChannelTransactionPayload> {
        let channel_script = {
            let script = self
                .script_registry
                .channel_op_to_script(channel_txn.operator(), channel_txn.args().to_vec())?;
            let write_set = channel_witness_data.unwrap_or_default();
            ChannelScriptBody::new(
                channel_txn.channel_sequence_number(),
                write_set,
                channel_txn.receiver(),
                script,
            )
        };
        let script_payload = match participant_key_and_signature {
            Some((public_key, signature)) => {
                // verify first
                public_key.verify_signature(&channel_script.hash(), &signature)?;
                ChannelTransactionPayload::new_with_script(channel_script, public_key, signature)
            }
            None => {
                let payload_body = ChannelTransactionPayloadBody::Script(channel_script);
                payload_body.sign(&self.keypair.private_key, self.keypair.public_key.clone())
            }
        };
        Ok(script_payload)
    }

    pub async fn execute_async(
        &mut self,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        // TODO: state view should be shared to reduce fetching account state from layer1.
        let state_view = self.channel_view(None, self.chain_client.as_ref())?;

        // account state already cached in state view
        let account_seq_number = {
            let account_resource_blob = state_view
                .get(&AccessPath::new_for_account_resource(
                    self.account.address(),
                ))?
                .ok_or(format_err!(
                    "account resource for {} not exists on chain",
                    self.account.address()
                ))?;
            let account_resource =
                sgtypes::account_resource_ext::from_bytes(&account_resource_blob)?;
            account_resource.sequence_number()
        };

        let chain_version = state_view.version();
        // build channel_transaction first
        let channel_transaction = ChannelTransaction::new(
            chain_version,
            channel_op,
            self.account_address,
            account_seq_number,
            self.participant_address,
            self.channel_sequence_number(),
            txn_expiration(),
            args,
        );

        // create mocked txn to execute
        let txn = {
            let raw_txn = self.build_raw_txn_from_channel_txn(
                self.witness_data(),
                &channel_transaction,
                None,
            )?;
            // execute txn on offchain vm, should mock sender and receiver signature with a local
            // keypair. the vm will skip signature check on offchain vm.
            self.keypair.sign_txn(raw_txn)?
        };
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
        let channel_write_set_signature = self
            .keypair
            .private_key
            .sign_message(&channel_write_set_hash);
        let channel_txn_hash = channel_transaction.hash();
        let channel_txn_signature = self.keypair.private_key.sign_message(&channel_txn_hash);

        let channel_txn_sigs = ChannelTransactionSigs::new(
            self.keypair.public_key.clone(),
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
        self.store.save_pending_txn(
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

    async fn verify_txn_request_async(
        &mut self,
        txn_request: ChannelTransactionRequest,
    ) -> Result<ChannelTransactionResponse> {
        let request_id = txn_request.request_id();
        let channel_txn = txn_request.channel_txn();
        let channel_txn_sender_sigs = txn_request.channel_txn_sigs();

        self.verify_channel_txn_and_sigs(channel_txn, channel_txn_sender_sigs)?;
        let applied_txn = if let Some(info) = self.store.get_startup_info()? {
            if channel_txn.channel_sequence_number() > info.latest_version {
                None
            } else {
                let signed_channel_txn_with_proof =
                    self.store.get_transaction_by_channel_seq_number(
                        channel_txn.channel_sequence_number(),
                        false,
                    )?;
                debug_assert_eq!(
                    signed_channel_txn_with_proof.version,
                    channel_txn.channel_sequence_number()
                );
                Some(signed_channel_txn_with_proof.signed_transaction)
            }
        } else {
            None
        };

        // if found an already applied txn in local storage,
        // we can return directly after check the hash of transaction and signatures.
        if let Some(signed_txn) = applied_txn {
            if signed_txn.raw_tx.hash() == channel_txn.hash()
                && signed_txn.sender_signature.hash() == channel_txn_sender_sigs.hash()
            {
                return Ok(ChannelTransactionResponse::new(
                    request_id,
                    signed_txn.receiver_signature,
                ));
            } else {
                return Err(format_err!(
                    "invalid txn, txn with channel_seq_number is mismatched"
                ));
            }
        }

        let signed_txn = {
            let raw_txn =
                self.build_raw_txn_from_channel_txn(self.witness_data(), channel_txn, None)?;
            self.keypair.sign_txn(raw_txn)?
        };

        let txn_payload_signature = signed_txn
            .receiver_signature()
            .expect("signature must exist.");

        let output = {
            let version = channel_txn.version();
            let state_view = self.channel_view(Some(version), self.chain_client.as_ref())?;
            execute_transaction(&state_view, signed_txn)?
        };

        let _verified_participant_witness_payload =
            self.verify_channel_write_set_body(&output, channel_txn_sender_sigs)?;

        // build signatures sent to sender
        let write_set_body = ChannelWriteSetBody::new(
            self.channel_sequence_number(),
            output.write_set().clone(),
            self.account_address,
        );
        let witness_hash = write_set_body.hash();
        let witness_signature = self.keypair.private_key.sign_message(&witness_hash);

        let channel_txn_receiver_sigs = ChannelTransactionSigs::new(
            self.keypair.public_key.clone(),
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
            self.store.save_pending_txn(
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

    async fn verify_txn_response_async(
        &mut self,
        response: ChannelTransactionResponse,
    ) -> Result<()> {
        let (request_id, channel_txn, output, sender_sigs) = match self.pending_txn() {
            Some(PendingTransaction::WaitForReceiverSig {
                request_id,
                raw_tx,
                output,
                sender_sigs,
            }) => {
                debug_assert_eq!(self.account_address, raw_tx.sender());
                (request_id, raw_tx, output, sender_sigs)
            }
            Some(PendingTransaction::WaitForApply { raw_tx, .. }) => {
                debug_assert_eq!(self.account_address, raw_tx.receiver());
                // if receiver, no need to verify
                return Ok(());
            }
            //TODO(jole) can not find request has such reason:
            // 1. txn is expire.
            // 2. txn is invalid.
            None => {
                // If I'm the receiver, no need to verify my own response
                // TODO: figure out a better way to do it.
                let is_receiver =
                    &self.keypair.public_key == &response.channel_txn_sigs().public_key;
                if is_receiver {
                    return Ok(());
                }
                bail!(
                    "pending txn must exist when verify txn response, stage: {:?}",
                    self.stage()
                )
            }
        };

        ensure!(
            request_id == response.request_id(),
            "request id mismatch, request: {}, response: {}",
            request_id,
            response.request_id()
        );

        info!("verify channel response: {}", response.request_id());
        let (_verified_participant_script_payload, _verified_participant_witness_payload) =
            self.verify_response(&channel_txn, &output, response.channel_txn_sigs())?;

        {
            let is_travel = output.is_travel_txn();
            // if it's a travel txn, we need to save the pending apply txn before submit to layer1.
            // just in case that the node is down after submit.
            // in this case, if it's not saved, receiver has no way to get channel_txn from onchain txn,
            // if it's offchain, there is no need. because:
            // - sender will resend the txn to receiver, and receiver will reply the msg.
            let pending_txn = PendingTransaction::WaitForApply {
                request_id,
                raw_tx: channel_txn.clone(),
                sender_sigs: sender_sigs.clone(),
                receiver_sigs: response.channel_txn_sigs().clone(),
                output,
            };
            self.store.save_pending_txn(pending_txn, is_travel)?;
        }
        Ok(())
    }

    async fn apply_pending_txn_async(&mut self) -> Result<u64> {
        // apply
        let (channel_txn, output, receiver_pub_key_and_script_body_signature) =
            match self.pending_txn() {
                //can not find request has such reason:
                // 1. receiver has already apply the txn before, this msg is a retry msg.
                // 2. currently, no ongoing.
                // TODO: should distinguish these cases, and return saved gas data if former.
                None => {
                    return Ok(0);
                }
                Some(PendingTransaction::WaitForReceiverSig { .. }) => {
                    bail!("pending_txn_request must exist at stage:{:?}", self.stage())
                }
                Some(PendingTransaction::WaitForApply {
                    raw_tx,
                    output,
                    receiver_sigs,
                    ..
                }) => {
                    let participant_public_key = receiver_sigs.public_key.clone();
                    let script_body_signature = match receiver_sigs.signature {
                        TxnSignature::ReceiverSig {
                            channel_script_body_signature,
                        } => channel_script_body_signature,
                        _ => bail!("must be receiver sig"),
                    };
                    (
                        raw_tx,
                        output,
                        (participant_public_key, script_body_signature),
                    )
                }
            };

        let gas = if output.is_travel_txn() {
            if self.account.address() == channel_txn.sender() {
                let max_gas_amount = std::cmp::min(
                    (output.gas_used() as f64 * 1.1) as u64,
                    MAX_GAS_AMOUNT_ONCHAIN,
                );
                let verified_participant_script_payload = self.build_channel_script_payload(
                    self.witness_data(),
                    &channel_txn,
                    Some(receiver_pub_key_and_script_body_signature),
                )?;
                let new_raw_txn = RawTransaction::new_channel(
                    channel_txn.sender(),
                    channel_txn.sequence_number(),
                    verified_participant_script_payload,
                    max_gas_amount,
                    GAS_UNIT_PRICE,
                    channel_txn.expiration_time(),
                );
                let signed_txn = self.keypair.sign_txn(new_raw_txn)?;
                let () = submit_transaction(self.chain_client.as_ref(), signed_txn).await?;
            }

            let account_address = self.account.address();
            debug_assert!(
                account_address == channel_txn.sender()
                    || account_address == channel_txn.receiver()
            );
            let txn_with_proof = watch_transaction(
                self.chain_client.as_ref(),
                channel_txn.sender(),
                channel_txn.sequence_number(),
            )
            .await?;
            txn_with_proof.proof.transaction_info().gas_used()
        } else {
            0
        };
        self.apply()?;
        Ok(gas)
    }

    /// called by reciever to verify sender's channel_txn.
    fn verify_channel_txn_and_sigs(
        &self,
        channel_txn: &ChannelTransaction,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<()> {
        ensure!(
            channel_txn.receiver() == self.account.address(),
            "check receiver fail."
        );
        let channel_sequence_number = self.channel_sequence_number();
        let smallest_allowed_channel_seq_number =
            channel_sequence_number.checked_sub(1).unwrap_or(0);
        ensure!(
            channel_txn.channel_sequence_number() >= smallest_allowed_channel_seq_number
                && channel_txn.channel_sequence_number() <= channel_sequence_number,
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
    // called by both of sender and reciver, to verify participant's writeset payload
    fn verify_channel_write_set_body(
        &self,
        output: &TransactionOutput,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<ChannelTransactionPayload> {
        let write_set_body = ChannelWriteSetBody::new(
            self.channel_sequence_number(),
            output.write_set().clone(),
            self.participant_address,
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
    fn verify_response(
        &self,
        channel_txn: &ChannelTransaction,
        output: &TransactionOutput,
        receiver_sigs: &ChannelTransactionSigs,
    ) -> Result<(ChannelTransactionPayload, ChannelTransactionPayload)> {
        let channel_txn_sigs = receiver_sigs;

        let raw_txn =
            self.build_raw_txn_from_channel_txn(self.witness_data(), channel_txn, None)?;

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
            self.verify_channel_write_set_body(&output, channel_txn_sigs)?;
        Ok((
            verified_channel_txn_payload,
            verified_participant_witness_payload,
        ))
    }

    /// apply data into local channel storage
    fn apply(&mut self) -> Result<()> {
        self.check_stage(vec![ChannelStage::Syncing])?;
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

        // apply txn  also delete pending txn from db
        self.tx_applier.apply(txn_to_apply)?;

        if txn_output.is_travel_txn() {
            self.apply_travel_output(txn_output.write_set())?;
        }

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

    fn witness_data(&self) -> Option<WriteSet> {
        self.store.get_latest_write_set()
    }

    fn channel_sequence_number(&self) -> u64 {
        match self.channel_account_resource() {
            None => 0,
            Some(account_resource) => account_resource.channel_sequence_number(),
        }
    }

    pub fn channel_account_resource(&self) -> Option<ChannelAccountResource> {
        let access_path = AccessPath::new_for_data_path(
            self.account.address(),
            DataPath::channel_account_path(self.participant.address()),
        );
        self.get_local(&access_path)
            .unwrap()
            .and_then(|value| ChannelAccountResource::make_from(value).ok())
    }
    //
    //    pub fn participant_channel_account_resource(&self) -> Option<ChannelAccountResource> {
    //        let access_path = AccessPath::new_for_data_path(
    //            self.participant.address(),
    //            DataPath::channel_account_path(self.account.address()),
    //        );
    //        self.get_local(&access_path)
    //            .unwrap()
    //            .and_then(|value| ChannelAccountResource::make_from(value).ok())
    //    }

    fn pending_txn(&self) -> Option<PendingTransaction> {
        self.store.get_pending_txn()
    }

    fn get_pending_channel_txn_request(&self) -> Option<ChannelTransactionRequest> {
        self.pending_txn()
            .as_ref()
            .and_then(|pending| match pending {
                PendingTransaction::WaitForReceiverSig {
                    raw_tx,
                    output,
                    sender_sigs,
                    ..
                } => Some(ChannelTransactionRequest::new(
                    raw_tx.clone(),
                    sender_sigs.clone(),
                    output.is_travel_txn(),
                )),
                _ => None,
            })
    }

    fn stage(&self) -> ChannelStage {
        match self.pending_txn() {
            Some(PendingTransaction::WaitForApply { .. }) => ChannelStage::Syncing,
            Some(PendingTransaction::WaitForReceiverSig { .. }) => ChannelStage::Pending,
            None => {
                let _channel_account_resource = self.channel_account_resource();
                match self.channel_account_resource() {
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
        }
    }

    fn check_stage(&self, expect_stages: Vec<ChannelStage>) -> Result<()> {
        let current_stage = self.stage();
        if !expect_stages.contains(&current_stage) {
            return Err(SgError::new_invalid_channel_stage_error(current_stage).into());
        }
        Ok(())
    }

    fn get_local(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        match self
            .witness_data()
            .and_then(|ws| ws.get(access_path).cloned())
        {
            Some(op) => Ok(match op {
                WriteOp::Value(value) => Some(value),
                WriteOp::Deletion => None,
            }),
            None => {
                if access_path.address == self.participant_address {
                    Ok(self.participant.get(&access_path.path))
                } else if access_path.address == self.account_address {
                    Ok(self.account.get(&access_path.path))
                } else {
                    Err(format_err!(
                        "Unexpect access_path: {} for this channel: {}",
                        access_path,
                        self.participant_address
                    ))
                }
            }
        }
    }
}

//pub enum ChannelEvent {
//    ChannelStarted { channel: Channel },
//    ChannelStopped { participant: AccountAddress },
//}
//pub struct ChannelManager {}
