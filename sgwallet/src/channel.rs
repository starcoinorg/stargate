// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_state_view::ChannelStateView;
use crate::scripts::PackageRegistry;
use crate::tx_applier::TxApplier;
use crate::wallet::{
    execute_transaction, respond_with, submit_transaction, txn_expiration, watch_transaction,
    GAS_UNIT_PRICE, MAX_GAS_AMOUNT_OFFCHAIN, MAX_GAS_AMOUNT_ONCHAIN,
};
use failure::prelude::*;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use libra_crypto::test_utils::KeyPair;
use libra_crypto::{hash::CryptoHash, HashValue, SigningKey, VerifyingKey};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::access_path::DataPath;
use libra_types::channel::{
    channel_mirror_struct_tag, channel_participant_struct_tag, ChannelMirrorResource,
    ChannelParticipantAccountResource, Witness, WitnessData,
};
use libra_types::identifier::Identifier;
use libra_types::language_storage::ModuleId;
use libra_types::transaction::helpers::TransactionSigner;
use libra_types::transaction::{
    ChannelTransactionPayloadBodyV2, ChannelTransactionPayloadV2, RawTransaction, ScriptAction,
    TransactionArgument, TransactionPayload, Version,
};
use libra_types::write_set::WriteSet;
use libra_types::{
    access_path::AccessPath, account_address::AccountAddress, transaction::TransactionOutput,
    write_set::WriteOp,
};
use sgchain::star_chain_client::ChainClient;
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use sgtypes::channel::ChannelState;
use sgtypes::channel_transaction::{ChannelOp, ChannelTransaction, ChannelTransactionProposal};
use sgtypes::channel_transaction_sigs::ChannelTransactionSigs;
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::pending_txn::PendingTransaction;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::signed_channel_transaction_with_proof::SignedChannelTransactionWithProof;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use vm::gas_schedule::GasAlgebra;

pub enum ChannelMsg {
    Execute {
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
        responder: oneshot::Sender<
            Result<(
                ChannelTransactionProposal,
                ChannelTransactionSigs,
                TransactionOutput,
            )>,
        >,
    },
    CollectProposalWithSigs {
        proposal: ChannelTransactionProposal,
        /// the sigs maybe proposer's, or other participant's.
        sigs: ChannelTransactionSigs,
        responder: oneshot::Sender<Result<Option<ChannelTransactionSigs>>>,
    },
    GrantProposal {
        channel_txn_id: HashValue,
        grant: bool,
        responder: oneshot::Sender<Result<Option<ChannelTransactionSigs>>>,
    },
    CancelPendingTxn {
        channel_txn_id: HashValue,
        responder: oneshot::Sender<Result<()>>,
    },
    ApplyPendingTxn {
        proposal: ChannelTransactionProposal,
        responder: oneshot::Sender<Result<u64>>,
    },
    GetPendingTxn {
        responder: oneshot::Sender<Option<PendingTransaction>>,
    },
    AccessPath {
        path: AccessPath,
        responder: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    Stop {
        responder: oneshot::Sender<()>,
    },
}
enum InternalMsg {
    ApplyPendingTxn {
        proposal: ChannelTransactionProposal,
    }, // when channel bootstrap, it will send this msg if it found pending txn.
}

pub struct Channel {
    channel_address: AccountAddress,
    account_address: AccountAddress,
    participant_addresses: BTreeSet<AccountAddress>,
    //    db: ChannelDB,
    //    store: ChannelStore<ChannelDB>,
    mail_sender: mpsc::Sender<ChannelMsg>,
    inner: Option<Inner>,
}

impl Channel {
    /// load channel from storage
    pub fn load(
        channel_address: AccountAddress,
        account_address: AccountAddress,
        participant_addresses: BTreeSet<AccountAddress>,
        channel_state: ChannelState,
        db: ChannelDB,
        mail_sender: mpsc::Sender<ChannelMsg>,
        mailbox: mpsc::Receiver<ChannelMsg>,
        channel_event_sender: mpsc::Sender<ChannelEvent>,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        script_registry: Arc<PackageRegistry>,
        chain_client: Arc<dyn ChainClient>,
    ) -> Self {
        let store = ChannelStore::new(db.clone());
        let inner = Inner {
            channel_address,
            account_address,
            participant_addresses: participant_addresses.clone(),
            channel_state,
            store: store.clone(),
            keypair: keypair.clone(),
            script_registry: script_registry.clone(),
            chain_client: chain_client.clone(),
            tx_applier: TxApplier::new(store.clone()),
            mailbox,
            channel_event_sender,
            shutdown_signal: None,
            should_stop: false,
        };
        let channel = Self {
            channel_address,
            account_address,
            participant_addresses,
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

    pub fn channel_address(&self) -> &AccountAddress {
        &self.channel_address
    }
    pub fn participant_addresses(&self) -> &BTreeSet<AccountAddress> {
        &self.participant_addresses
    }

    pub async fn stop(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let msg = ChannelMsg::Stop { responder: tx };
        self.send(msg)?;
        rx.await?;
        Ok(())
    }

    pub fn send(&self, msg: ChannelMsg) -> Result<()> {
        if let Err(err) = self.mail_sender.clone().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            let resp_err = format_err!(
                "channel {:?} mailbox {:?}",
                self.channel_address,
                err_status
            );
            Err(resp_err)
        } else {
            Ok(())
        }
    }
}

pub enum ChannelEvent {
    Stopped { channel_address: AccountAddress },
}

struct Inner {
    channel_address: AccountAddress,
    account_address: AccountAddress,
    // participant contains self address, use btree to preserve address order.
    participant_addresses: BTreeSet<AccountAddress>,
    channel_state: ChannelState,
    //    db: ChannelDB,
    store: ChannelStore<ChannelDB>,
    keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    script_registry: Arc<PackageRegistry>,
    chain_client: Arc<dyn ChainClient>,
    tx_applier: TxApplier,

    mailbox: mpsc::Receiver<ChannelMsg>,
    shutdown_signal: Option<oneshot::Sender<()>>,
    should_stop: bool,
    // event produced by the channel
    channel_event_sender: mpsc::Sender<ChannelEvent>,
}

impl Inner {
    fn channel_address(&self) -> &AccountAddress {
        &self.channel_address
    }
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
            if self.should_stop {
                if self.shutdown_signal.is_some() {
                    respond_with(self.shutdown_signal.take().unwrap(), ());
                }
                break;
            }
        }
        if let Err(e) = self
            .channel_event_sender
            .send(ChannelEvent::Stopped {
                channel_address: self.channel_address.clone(),
            })
            .await
        {
            error!(
                "channel[{:?}]: fail to emit stopped event, error: {:?}",
                &self.channel_address, e
            );
        }
        crit!("channel {} task terminated", self.channel_address);
    }

    fn bootstrap(&mut self, mut internal_msg_tx: mpsc::Sender<InternalMsg>) {
        match self.pending_txn() {
            None => {}
            Some(PendingTransaction::WaitForSig { .. }) => {}
            Some(PendingTransaction::WaitForApply {
                proposal, output, ..
            }) => {
                debug_assert!(output.is_travel_txn(), "only travel txn is persisted");
                if let Err(_e) = internal_msg_tx.try_send(InternalMsg::ApplyPendingTxn { proposal })
                {
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
            ChannelMsg::CollectProposalWithSigs {
                proposal,
                sigs,
                responder,
            } => {
                let response = self.collect_proposal_and_sigs_async(proposal, sigs).await;
                respond_with(responder, response);
            }
            ChannelMsg::GrantProposal {
                channel_txn_id,
                grant,
                responder,
            } => {
                let response = self.grant_proposal_async(channel_txn_id, grant).await;
                respond_with(responder, response);
            }
            ChannelMsg::CancelPendingTxn {
                channel_txn_id,
                responder,
            } => {
                respond_with(responder, self.cancel_pending_txn(channel_txn_id));
            }
            ChannelMsg::ApplyPendingTxn {
                proposal,
                responder,
            } => {
                let response = self.apply_pending_txn_async(proposal).await;
                respond_with(responder, response);
            }
            ChannelMsg::AccessPath { path, responder } => {
                let response = self.get_local(&path);
                respond_with(responder, response);
            }
            ChannelMsg::GetPendingTxn { responder } => {
                respond_with(responder, self.pending_txn());
            }
            ChannelMsg::Stop { responder } => {
                self.should_stop = true;
                self.shutdown_signal = Some(responder);
            }
        };
    }

    async fn handle_internal_msg(&mut self, internal_msg: InternalMsg) {
        match internal_msg {
            InternalMsg::ApplyPendingTxn { proposal } => {
                match self.apply_pending_txn_async(proposal).await {
                    Ok(gas) => {
                        info!("apply pending txn successfully, gas used: {}", gas);
                    }
                    Err(e) => {
                        error!("apply pending txn failed, err: {:?}", e);
                    }
                }
            }
        }
    }

    fn channel_view(&self, version: Option<Version>) -> Result<ChannelStateView> {
        let latest_writeset = self.witness_data().into_write_set();
        ChannelStateView::new(
            self.account_address,
            &self.channel_state,
            latest_writeset,
            version,
            self.chain_client.as_ref(),
        )
    }

    fn build_raw_txn_from_channel_txn(
        &self,
        channel_payload_body: ChannelTransactionPayloadBodyV2,
        channel_txn: &ChannelTransaction,
        txn_signatures: Option<&BTreeMap<AccountAddress, ChannelTransactionSigs>>,
        max_gas_amount: u64,
    ) -> Result<RawTransaction> {
        let channel_participant_size = self.participant_addresses.len();
        let mut participant_keys = self.store.get_participant_keys();
        let mut sigs = Vec::with_capacity(channel_participant_size);
        if let Some(signatures) = txn_signatures {
            for addr in self.participant_addresses.iter() {
                let sig = signatures.get(&addr);
                if let Some(s) = sig {
                    participant_keys.insert(addr.clone(), s.public_key.clone());
                }
                sigs.push(sig.map(|s| s.channel_payload_signature.clone()));
            }
        }

        if channel_payload_body.witness().channel_sequence_number() == 0 {
            debug_assert!(channel_txn.operator().is_open());
        } else {
            debug_assert!(channel_participant_size == participant_keys.len());
        }

        let keys = participant_keys
            .into_iter()
            .map(|p| p.1)
            .collect::<Vec<_>>();

        let channel_txn_payload =
            ChannelTransactionPayloadV2::new(channel_payload_body, keys, sigs);
        let txn_payload = TransactionPayload::ChannelV2(channel_txn_payload);
        let raw_txn = RawTransaction::new(
            channel_txn.proposer(),
            channel_txn.sequence_number(),
            txn_payload,
            max_gas_amount,
            GAS_UNIT_PRICE,
            channel_txn.expiration_time(),
        );
        Ok(raw_txn)
    }

    /// build channel txn payload version 2.
    fn build_and_sign_channel_txn_payload_body_v2(
        &self,
        channel_witness: Witness,
        channel_txn: &ChannelTransaction,
    ) -> Result<(ChannelTransactionPayloadBodyV2, Ed25519Signature)> {
        let action =
            self.channel_op_to_action(channel_txn.operator(), channel_txn.args().to_vec())?;

        let body = ChannelTransactionPayloadBodyV2::new(
            channel_txn.channel_address(),
            channel_txn.proposer(),
            action,
            channel_witness,
        );
        let body_hash = CryptoHash::hash(&body);
        let sig = self.keypair.private_key.sign_message(&body_hash);
        Ok((body, sig))
    }

    pub async fn execute_async(
        &mut self,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<(
        ChannelTransactionProposal,
        ChannelTransactionSigs,
        TransactionOutput,
    )> {
        // generate proposal
        let proposal = self.generate_proposal(channel_op, args)?;

        // execute proposal to get txn payload and txn witness data for later use
        let (_payload_body, _payload_body_signature, output) = self.execute_proposal(&proposal)?;

        self.do_grant_proposal(proposal.clone(), output.clone(), BTreeMap::new())?;

        let pending = self.pending_txn().expect("pending txn must exists");
        let user_sigs = pending
            .get_signature(&self.account_address)
            .expect("user signature must exists");
        Ok((proposal, user_sigs, output))
    }

    /// handle incoming proposal, return my sigs.
    /// If I don't agree the proposal, return None.
    /// If the proposal is already handled, also return my sigs from local cached state.
    async fn collect_proposal_and_sigs_async(
        &mut self,
        proposal: ChannelTransactionProposal,
        sigs: ChannelTransactionSigs,
    ) -> Result<Option<ChannelTransactionSigs>> {
        debug_assert_ne!(self.account_address, sigs.address);

        // if found an already applied txn in local storage,
        // we can return directly after check the hash of transaction and signatures.
        if let Some(mut signed_txn) = self.check_applied(&proposal)? {
            let signature = signed_txn
                .signed_transaction
                .signatures
                .remove(&self.account_address)
                .expect("applied txn should have user signature");
            return Ok(Some(signature));
        }

        self.verify_proposal(&proposal)?;

        let mut verified_signatures = BTreeMap::new();
        let (payload_body, _payload_body_signature, output) = match self.pending_txn() {
            None => self.execute_proposal(&proposal)?,
            Some(PendingTransaction::WaitForSig {
                proposal: local_proposal,
                output,
                signatures,
                ..
            }) => {
                ensure!(
                    CryptoHash::hash(&proposal.channel_txn)
                        == CryptoHash::hash(&local_proposal.channel_txn),
                    format_err!("channel txn conflict with local")
                );
                ensure!(
                    &proposal.proposer_public_key == &local_proposal.proposer_public_key,
                    format_err!("txn proposer public_key conflict with local")
                );
                debug_assert_eq!(
                    &local_proposal.proposer_signature,
                    &proposal.proposer_signature
                );
                verified_signatures = signatures;

                let (payload_body, payload_body_signature) = self
                    .build_and_sign_channel_txn_payload_body_v2(
                        self.witness_data(),
                        &proposal.channel_txn,
                    )?;
                (payload_body, payload_body_signature, output)
            }
            Some(PendingTransaction::WaitForApply { signatures, .. }) => {
                match signatures.get(&self.account_address) {
                    Some(s) => return Ok(Some(s.clone())),
                    None => {
                        panic!("should already give out user signature");
                    }
                }
            }
        };

        self.verify_txn_sigs(&payload_body, &output, &sigs)?;

        verified_signatures.insert(sigs.address, sigs);

        // if the output modifies user's channel state, permission need to be granted by user.
        // it cannot be auto-signed.
        let can_auto_signed = !output
            .write_set()
            .contains_channel_resource(&self.account_address);
        if !verified_signatures.contains_key(&self.account_address) && can_auto_signed {
            self.do_grant_proposal(proposal, output, verified_signatures)?;
        } else {
            self.save_pending_txn(proposal, output, verified_signatures)?;
        };

        let pending = self.pending_txn().expect("pending txn must exists");
        let user_sigs = pending.get_signature(&self.account_address);
        Ok(user_sigs)
    }

    async fn grant_proposal_async(
        &mut self,
        channel_txn_id: HashValue,
        grant: bool,
    ) -> Result<Option<ChannelTransactionSigs>> {
        let pending_txn = self.pending_txn();
        ensure!(pending_txn.is_some(), "no pending txn");
        let pending_txn = pending_txn.unwrap();
        ensure!(!pending_txn.fulfilled(), "pending txn is already fulfilled");
        let (proposal, output, signatures) = pending_txn.into();
        if channel_txn_id != CryptoHash::hash(&proposal.channel_txn) {
            let err = format_err!("channel_txn_id conflict with local pending txn");
            return Err(err);
        }
        if grant {
            // maybe already grant the proposal
            if !signatures.contains_key(&self.account_address) {
                self.do_grant_proposal(proposal, output, signatures)?;
            }
            let pending = self.pending_txn().expect("pending txn must exists");
            let user_sigs = pending
                .get_signature(&self.account_address)
                .expect("user signature must exists");
            Ok(Some(user_sigs))
        } else {
            self.clear_pending_txn()?;
            if proposal.channel_txn.operator().is_open() {
                self.should_stop = true;
            }
            Ok(None)
        }
    }

    fn cancel_pending_txn(&mut self, channel_txn_id: HashValue) -> Result<()> {
        let pending_txn = self.pending_txn();
        ensure!(pending_txn.is_some(), "no pending txn");
        let pending_txn = pending_txn.unwrap();
        ensure!(!pending_txn.fulfilled(), "pending txn is already fulfilled");
        let (proposal, _output, _signature) = pending_txn.into();
        if channel_txn_id != CryptoHash::hash(&proposal.channel_txn) {
            let err = format_err!("channel_txn_id conflict with local pending txn");
            return Err(err);
        }
        self.clear_pending_txn()?;
        if proposal.channel_txn.operator().is_open() {
            self.should_stop = true;
        }
        Ok(())
    }

    async fn apply_pending_txn_async(
        &mut self,
        proposal: ChannelTransactionProposal,
    ) -> Result<u64> {
        if let Some(signed_txn) = self.check_applied(&proposal)? {
            warn!(
                "txn {} already applied!",
                &CryptoHash::hash(&proposal.channel_txn)
            );
            if signed_txn.proof.transaction_info().travel() {
                return Ok(signed_txn.proof.transaction_info().gas_used());
            } else {
                return Ok(0);
            }
        }

        debug!("user {} apply txn", self.account_address);
        ensure!(self.pending_txn().is_some(), "should have txn to apply");
        let pending_txn = self.pending_txn().unwrap();
        ensure!(pending_txn.fulfilled(), "txn should have been fulfilled");
        let (proposal, output, signatures) = pending_txn.into();
        let channel_txn = &proposal.channel_txn;

        let gas = if output.is_travel_txn() {
            if self.account_address == channel_txn.proposer() {
                let max_gas_amount = std::cmp::min(
                    (output.gas_used() as f64 * 1.1) as u64,
                    MAX_GAS_AMOUNT_ONCHAIN,
                );
                let (payload_body, _) = self
                    .build_and_sign_channel_txn_payload_body_v2(self.witness_data(), channel_txn)?;

                let new_raw_txn = self.build_raw_txn_from_channel_txn(
                    payload_body,
                    &channel_txn,
                    Some(&signatures),
                    max_gas_amount,
                )?;
                let signed_txn = self.keypair.sign_txn(new_raw_txn)?;
                submit_transaction(self.chain_client.as_ref(), signed_txn).await?;
            }

            let txn_with_proof = watch_transaction(
                self.chain_client.as_ref(),
                channel_txn.proposer(),
                channel_txn.sequence_number(),
            )
            .await?;
            txn_with_proof.proof.transaction_info().gas_used()
        } else {
            0
        };
        self.apply(proposal.channel_txn, output, signatures)?;
        Ok(gas)
    }

    fn verify_proposal(&self, proposal: &ChannelTransactionProposal) -> Result<()> {
        let channel_txn = &proposal.channel_txn;
        ensure!(
            self.channel_address == channel_txn.channel_address(),
            "invalid channel address"
        );
        let channel_sequence_number = self.channel_sequence_number();
        let smallest_allowed_channel_seq_number =
            channel_sequence_number.checked_sub(1).unwrap_or(0);
        ensure!(
            channel_txn.channel_sequence_number() >= smallest_allowed_channel_seq_number
                && channel_txn.channel_sequence_number() <= channel_sequence_number,
            "check channel_sequence_number fail."
        );
        proposal
            .proposer_public_key
            .verify_signature(&CryptoHash::hash(channel_txn), &proposal.proposer_signature)?;

        // TODO: check public key match proposer address
        if !channel_txn.operator().is_open() {
            ensure!(
                self.participant_addresses.contains(&channel_txn.proposer()),
                "proposer does not belong to the channel"
            );
        }
        Ok(())
    }

    /// apply data into local channel storage
    fn apply(
        &mut self,
        channel_txn: ChannelTransaction,
        txn_output: TransactionOutput,
        signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Result<()> {
        let txn_to_apply = ChannelTransactionToApply {
            signed_channel_txn: SignedChannelTransaction::new(channel_txn, signatures),
            events: txn_output.events().to_vec(),
            major_status: txn_output.status().vm_status().major_status,
            write_set: if txn_output.is_travel_txn() {
                None
            } else {
                Some(txn_output.write_set().clone())
            },
            travel: txn_output.is_travel_txn(),
            gas_used: txn_output.gas_used(),
        };

        // apply txn  also delete pending txn from db
        self.tx_applier.apply(txn_to_apply)?;

        if txn_output.is_travel_txn() {
            self.apply_travel_output(txn_output.write_set())?;
        }

        Ok(())
    }

    // FIXME
    pub fn apply_travel_output(&mut self, write_set: &WriteSet) -> Result<()> {
        for (ap, op) in write_set {
            if ap.is_channel_resource() {
                ensure!(
                    &ap.address == self.channel_address(),
                    "Unexpected witness_payload access_path {:?} apply to channel {:?}",
                    &ap.address,
                    self.channel_address()
                );
                match op {
                    WriteOp::Value(value) => {
                        self.channel_state.insert(ap.path.clone(), value.clone())
                    }
                    WriteOp::Deletion => self.channel_state.remove(&ap.path),
                };
            }
        }
        Ok(())
    }

    fn witness_data(&self) -> Witness {
        self.store.get_latest_witness().unwrap_or_default()
    }

    fn channel_sequence_number(&self) -> u64 {
        let access_path = AccessPath::new_for_data_path(
            self.channel_address,
            DataPath::channel_resource_path(self.channel_address, channel_mirror_struct_tag()),
        );
        let channel_mirror_resource = self
            .get_local(&access_path)
            .unwrap()
            .and_then(|value| ChannelMirrorResource::make_from(value).ok());
        match channel_mirror_resource {
            None => 0,
            Some(r) => r.channel_sequence_number(),
        }
    }

    fn channel_account_resource(&self) -> Option<ChannelParticipantAccountResource> {
        let access_path = AccessPath::new_for_data_path(
            self.channel_address,
            DataPath::channel_resource_path(self.account_address, channel_participant_struct_tag()),
        );
        self.get_local(&access_path)
            .unwrap()
            .and_then(|value| ChannelParticipantAccountResource::make_from(value).ok())
    }

    fn pending_txn(&self) -> Option<PendingTransaction> {
        self.store.get_pending_txn()
    }

    // TODO: should stage is needed?
    //    fn _stage(&self) -> ChannelStage {
    //        match self.pending_txn() {
    //            Some(PendingTransaction::WaitForApply { .. }) => ChannelStage::Syncing,
    //            Some(PendingTransaction::WaitForSig { .. }) => ChannelStage::Pending,
    //            None => match self.channel_account_resource() {
    //                Some(resource) => {
    //                    if resource.closed() {
    //                        ChannelStage::Closed
    //                    } else {
    //                        ChannelStage::Idle
    //                    }
    //                }
    //                None => ChannelStage::Opening,
    //            },
    //        }
    //    }
    //
    //    fn _check_stage(&self, expect_stages: Vec<ChannelStage>) -> Result<()> {
    //        let current_stage = self._stage();
    //        if !expect_stages.contains(&current_stage) {
    //            return Err(SgError::new_invalid_channel_stage_error(current_stage).into());
    //        }
    //        Ok(())
    //    }

    fn get_local(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let witness = self.witness_data();
        access_local(witness.write_set(), &self.channel_state, access_path)
    }

    fn generate_proposal(
        &self,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionProposal> {
        // TODO: state view should be shared to reduce fetching account state from layer1.
        let state_view = self.channel_view(None)?;

        // account state already cached in state view
        let account_seq_number = {
            let account_resource_blob = state_view
                .get(&AccessPath::new_for_account_resource(self.account_address))?
                .ok_or(format_err!(
                    "account resource for {} not exists on chain",
                    self.account_address,
                ))?;
            let account_resource =
                sgtypes::account_resource_ext::from_bytes(&account_resource_blob)?;
            account_resource.sequence_number()
        };

        let chain_version = state_view.version();
        // build channel_transaction first
        let channel_txn = ChannelTransaction::new(
            chain_version,
            self.channel_address,
            self.channel_sequence_number(),
            channel_op,
            args,
            self.account_address,
            account_seq_number,
            txn_expiration(),
        );
        let channel_txn_hash = CryptoHash::hash(&channel_txn);
        let channel_txn_signature = self.keypair.private_key.sign_message(&channel_txn_hash);

        let proposal = ChannelTransactionProposal {
            channel_txn,
            proposer_public_key: self.keypair.public_key.clone(),
            proposer_signature: channel_txn_signature,
        };
        Ok(proposal)
    }

    fn execute_proposal(
        &self,
        proposal: &ChannelTransactionProposal,
    ) -> Result<(
        ChannelTransactionPayloadBodyV2,
        Ed25519Signature,
        TransactionOutput,
    )> {
        let channel_txn = &proposal.channel_txn;
        let (payload_body, payload_body_signature) =
            self.build_and_sign_channel_txn_payload_body_v2(self.witness_data(), channel_txn)?;

        let output = {
            // create mocked txn to execute
            let raw_txn = self.build_raw_txn_from_channel_txn(
                payload_body.clone(),
                channel_txn,
                None,
                MAX_GAS_AMOUNT_OFFCHAIN,
            )?;
            // execute txn on offchain vm, should mock sender and receiver signature with a local
            // keypair. the vm will skip signature check on offchain vm.
            let txn = self.keypair.sign_txn(raw_txn)?;
            let version = channel_txn.version();
            let state_view = self.channel_view(Some(version))?;
            execute_transaction(&state_view, txn)?
        };

        // check output gas
        let gas_used = output.gas_used();
        if gas_used > vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get() {
            warn!(
                "GasUsed {} > gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS {}",
                gas_used,
                vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get()
            );
        }

        Ok((payload_body, payload_body_signature, output))
    }
    fn check_applied(
        &self,
        proposal: &ChannelTransactionProposal,
    ) -> Result<Option<(SignedChannelTransactionWithProof)>> {
        let channel_txn = &proposal.channel_txn;
        if let Some(info) = self.store.get_startup_info()? {
            if channel_txn.channel_sequence_number() > info.latest_version {
                Ok(None)
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
                if CryptoHash::hash(&proposal.channel_txn)
                    != CryptoHash::hash(&signed_channel_txn_with_proof.signed_transaction.raw_tx)
                {
                    bail!("invalid proposal, channel already applied a different proposal with same channel seq number {}", signed_channel_txn_with_proof.version);
                }
                Ok(Some(signed_channel_txn_with_proof))
            }
        } else {
            Ok(None)
        }
    }

    fn generate_txn_sigs(
        &self,
        channel_txn: &ChannelTransaction,
        output: &TransactionOutput,
    ) -> Result<ChannelTransactionSigs> {
        let (_, payload_body_signature) =
            self.build_and_sign_channel_txn_payload_body_v2(self.witness_data(), channel_txn)?;

        let ws = if output.is_travel_txn() {
            WriteSet::default()
        } else {
            output.write_set().clone()
        };
        let witness_data = WitnessData::new(self.channel_sequence_number() + 1, ws);
        let witness_data_hash = CryptoHash::hash(&witness_data);
        let witness_data_signature = self.keypair.private_key.sign_message(&witness_data_hash);

        let travel_output_witness_signature = if output.is_travel_txn() {
            let txn_output_witness_data = WitnessData::new(
                self.channel_sequence_number() + 1,
                output.write_set().clone(),
            );
            Some(
                self.keypair
                    .private_key
                    .sign_message(&CryptoHash::hash(&txn_output_witness_data)),
            )
        } else {
            None
        };

        let generated_sigs = ChannelTransactionSigs::new(
            self.account_address,
            self.keypair.public_key.clone(),
            payload_body_signature,
            witness_data_hash,
            witness_data_signature,
            travel_output_witness_signature,
        );

        Ok(generated_sigs)
    }

    fn verify_txn_sigs(
        &self,
        payload_body: &ChannelTransactionPayloadBodyV2,
        output: &TransactionOutput,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<()> {
        channel_txn_sigs.public_key.verify_signature(
            &CryptoHash::hash(payload_body),
            &channel_txn_sigs.channel_payload_signature,
        )?;

        let ws = if output.is_travel_txn() {
            WriteSet::default()
        } else {
            output.write_set().clone()
        };
        let witness_data = WitnessData::new(self.channel_sequence_number() + 1, ws);

        ensure!(
            &CryptoHash::hash(&witness_data) == &channel_txn_sigs.witness_data_hash,
            "witness hash mismatched"
        );
        channel_txn_sigs.public_key.verify_signature(
            &channel_txn_sigs.witness_data_hash,
            &channel_txn_sigs.witness_data_signature,
        )?;

        if output.is_travel_txn() {
            match &channel_txn_sigs.travel_output_witness_signature {
                None => bail!("travel txn should have signer's signature on output"),
                Some(signature) => {
                    let txn_output_witness_data = WitnessData::new(
                        self.channel_sequence_number() + 1,
                        output.write_set().clone(),
                    );
                    channel_txn_sigs
                        .public_key
                        .verify_signature(&CryptoHash::hash(&txn_output_witness_data), signature)?;
                }
            }
        }

        Ok(())
    }

    /// Grant the proposal and save it into pending txn
    fn do_grant_proposal(
        &mut self,
        proposal: ChannelTransactionProposal,
        output: TransactionOutput,
        mut signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Result<()> {
        let user_sigs = self.generate_txn_sigs(&proposal.channel_txn, &output)?;
        signatures.insert(user_sigs.address, user_sigs.clone());
        debug!(
            "user {:?} add signature to txn {}",
            self.account_address,
            CryptoHash::hash(&proposal.channel_txn),
        );
        self.save_pending_txn(proposal, output, signatures)
    }

    fn save_pending_txn(
        &mut self,
        proposal: ChannelTransactionProposal,
        output: TransactionOutput,
        signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Result<()> {
        let is_travel_txn = output.is_travel_txn();
        let mut pending_txn = PendingTransaction::WaitForSig {
            proposal,
            output,
            signatures,
        };
        pending_txn.try_fulfill(&self.participant_addresses);
        self.store.save_pending_txn(pending_txn, is_travel_txn)?;
        Ok(())
    }

    /// clear local pending state
    fn clear_pending_txn(&self) -> Result<()> {
        self.store.clear_pending_txn()
    }

    fn channel_op_to_action(
        &self,
        op: &ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ScriptAction> {
        match op {
            ChannelOp::Open => {
                let module_id =
                    ModuleId::new(AccountAddress::default(), Identifier::new("ChannelScript")?);

                Ok(ScriptAction::new_call(
                    module_id,
                    Identifier::new("open")?,
                    args,
                ))
            }
            ChannelOp::Close => {
                let module_id =
                    ModuleId::new(AccountAddress::default(), Identifier::new("LibraAccount")?);

                Ok(ScriptAction::new_call(
                    module_id,
                    Identifier::new("close")?,
                    args,
                ))
            }
            ChannelOp::Execute {
                package_name,
                script_name,
            } => {
                let script_code = self
                    .script_registry
                    .get_script(package_name, script_name)
                    .ok_or(format_err!(
                        "Can not find script by package {} and script name {}",
                        package_name,
                        script_name
                    ))?;
                Ok(ScriptAction::new_code(
                    script_code.byte_code().clone(),
                    args,
                ))
            }
            ChannelOp::Action {
                module_address,
                module_name,
                function_name,
            } => {
                let module_id = ModuleId::new(
                    module_address.clone(),
                    Identifier::new(module_name.clone().into_boxed_str())?,
                );
                Ok(ScriptAction::new_call(
                    module_id,
                    Identifier::new(function_name.clone().into_boxed_str())?,
                    args,
                ))
            }
        }
    }
}

pub(crate) fn access_local<'a>(
    latest_write_set: &'a WriteSet,
    channel_state: &'a ChannelState,
    access_path: &AccessPath,
) -> Result<Option<Vec<u8>>> {
    match latest_write_set.get(access_path) {
        Some(op) => match op {
            WriteOp::Value(value) => Ok(Some(value.clone())),
            WriteOp::Deletion => Ok(None),
        },
        None => {
            if channel_state.address() != &access_path.address {
                Err(format_err!("Unexpected access_path: {}", access_path))
            } else {
                Ok(channel_state.get(&access_path.path).cloned())
            }
        }
    }
}
