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
use itertools::Itertools;
use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use libra_crypto::test_utils::KeyPair;
use libra_crypto::{hash::CryptoHash, HashValue, SigningKey, VerifyingKey};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::channel::witness::{Witness, WitnessData};
use libra_types::transaction::helpers::TransactionSigner;
use libra_types::transaction::{
    ChannelScriptBody, ChannelTransactionPayload, ChannelTransactionPayloadBody,
    ChannelTransactionPayloadBodyV2, ChannelTransactionPayloadV2, ChannelWriteSetBody,
    RawTransaction, ScriptAction, SignedTransaction, TransactionArgument, TransactionPayload,
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
    ChannelOp, ChannelTransaction, ChannelTransactionProposal, ChannelTransactionRequest,
    ChannelTransactionResponse,
};
use sgtypes::channel_transaction_sigs::{ChannelTransactionSigs, TxnSignature};
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::pending_txn::PendingTransaction;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::{
    channel::{ChannelStage, ChannelState},
    sg_error::SgError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::hash::Hash;
use std::sync::Arc;
use vm::gas_schedule::GasAlgebra;

pub enum ChannelMsg {
    Execute {
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
        responder: oneshot::Sender<Result<(ChannelTransactionProposal, ChannelTransactionSigs)>>,
    },
    HandleProposalWithSigs {
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
    channel_address: AccountAddress,
    account_address: AccountAddress,
    participant_addresses: Vec<AccountAddress>,
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
        let participants = {
            let mut set = BTreeSet::new();
            set.insert(account);
            set.insert(participant);
            set
        };
        let channel_address = generate_channel_address(&participants);
        let participant_states = {
            let mut states = BTreeMap::new();
            states.insert(account, ChannelState::empty(account));
            states.insert(participant, ChannelState::empty(participant));
            states
        };
        Self::load(
            channel_address,
            account,
            participant_states,
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
        channel_address: AccountAddress,
        account_address: AccountAddress,
        participants_states: BTreeMap<AccountAddress, ChannelState>,
        db: ChannelDB,
        mail_sender: mpsc::Sender<ChannelMsg>,
        mailbox: mpsc::Receiver<ChannelMsg>,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        script_registry: Arc<PackageRegistry>,
        chain_client: Arc<dyn ChainClient>,
    ) -> Self {
        let store = ChannelStore::new(db.clone());
        let participant_addresses = participants_states
            .keys()
            .map(Clone::clone)
            .collect::<Vec<_>>();
        let inner = Inner {
            channel_address,
            account_address,
            participant_addresses: BTreeMap::new(),
            participants_states,
            store: store.clone(),
            keypair: keypair.clone(),
            script_registry: script_registry.clone(),
            chain_client: chain_client.clone(),
            tx_applier: TxApplier::new(store.clone()),
            mailbox,
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
    pub fn participant_address(&self) -> &AccountAddress {
        &self.participant_address
    }

    pub fn mail_sender(&self) -> mpsc::Sender<ChannelMsg> {
        self.mail_sender.clone()
    }

    pub fn send(&self, msg: ChannelMsg) -> Result<()> {
        if let Err(err) = self.mail_sender().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            let resp_err = format_err!(
                "channel {:?} mailbox {:?}",
                self.participant_address(),
                err_status
            );
            Err(resp_err)
        } else {
            Ok(())
        }
    }
}

// should keep the same logic with onchain
pub fn generate_channel_address(participants: &BTreeSet<AccountAddress>) -> AccountAddress {
    let mut data = Vec::new();
    for participant in participants.iter() {
        data.extend_from_slice(participant.as_ref());
    }
    let hash = HashValue::from_sha3_256(&data);
    AccountAddress::try_from(hash.as_ref()).unwrap()
}

struct Inner {
    channel_address: AccountAddress,
    account_address: AccountAddress,
    // participant contains self address, use btree to preserve address order.
    participant_addresses: BTreeMap<AccountAddress, Ed25519PublicKey>,
    participants_states: BTreeMap<AccountAddress, ChannelState>,
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
            Some(PendingTransaction::WaitForSig { .. }) => {}
            Some(PendingTransaction::WaitForApply { .. }) => {
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
            ChannelMsg::HandleProposalWithSigs {
                proposal,
                sigs,
                responder,
            } => {
                let response = self.handle_proposal_and_sigs_async(proposal, sigs).await;
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
                self.witness_data().write_set().clone(),
            )
        };
        ChannelStateView::new(account, participant, latest_writeset, version, client)
    }

    fn build_raw_txn_from_channel_txn(
        &self,
        channel_payload_body: ChannelTransactionPayloadBodyV2,
        channel_txn: &ChannelTransaction,
    ) -> Result<RawTransaction> {
        //        let pub_keys = self
        //            .participants
        //            .values()
        //            .map(|k| k.clone())
        //            .collect::<Vec<_>>();
        //
        //        let (keys, sigs) = {
        //            let channel_participant_size = self.participants.len();
        //            let mut keys = Vec::with_capacity(channel_participant_size);
        //            let mut sigs = Vec::with_capacity(channel_participant_size);
        //            for (addr, key) in self.participants.iter() {
        //                let sig = if addr == self.account_address {
        //                    debug_assert_eq!(key, &pub_key);
        //                    Some(signature)
        //                } else {
        //                    None
        //                };
        //                keys.push(key.clone());
        //                sigs.push(sig);
        //            }
        //            (keys, sigs)
        //        };
        // TODO(caojiafeng): should put my sig into the payload?
        let (keys, sigs) = (vec![], vec![]);
        let channel_txn_payload =
            ChannelTransactionPayloadV2::new(channel_payload_body, keys, sigs);
        let txn_payload = TransactionPayload::ChannelV2(channel_txn_payload);
        let raw_txn = RawTransaction::new(
            channel_txn.proposer(),
            channel_txn.sequence_number(),
            txn_payload,
            MAX_GAS_AMOUNT_OFFCHAIN,
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
        let action: ScriptAction;
        let body = ChannelTransactionPayloadBodyV2::new(
            channel_txn.channel_address(),
            channel_txn.proposer(),
            action,
            channel_witness,
        );
        let body_hash = body.hash();
        let sig = self.keypair.private_key.sign_message(&body_hash);
        Ok((body, sig))
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
    ) -> Result<(ChannelTransactionProposal, ChannelTransactionSigs)> {
        // generate proposal
        let proposal = self.generate_proposal(channel_op, args)?;
        // execute proposal to get txn payload and txn witness data for later use
        let (payload_body, payload_body_signature, witness_data) =
            self.execute_proposal(&proposal)?;

        let witness_data_hash = witness_data.hash();
        let witness_data_signature = self.keypair.private_key.sign_message(&witness_data_hash);

        let channel_txn_sigs = ChannelTransactionSigs::new(
            self.account_address,
            self.keypair.public_key.clone(),
            payload_body_signature,
            witness_data_hash,
            witness_data_signature,
        );

        // we need to save the pending txn, in case node nown
        let mut pending_txn = PendingTransaction::WaitForSig {
            proposal: proposal.clone(),
            output,
            signatures: BTreeMap::new(),
        };
        pending_txn.add_signature(channel_txn_sigs.clone());
        self.store.save_pending_txn(pending_txn, true)?;

        Ok((proposal, channel_txn_sigs))
    }

    /// handle incoming proposal, return my sigs.
    /// If I don't agree the proposal, return None.
    /// If the proposal is already handled, also return my sigs from local cached state.
    async fn handle_proposal_and_sigs_async(
        &mut self,
        proposal: ChannelTransactionProposal,
        sigs: ChannelTransactionSigs,
    ) -> Result<Option<ChannelTransactionSigs>> {
        debug_assert_ne!(self.account_address, proposal.proposer());
        debug_assert_ne!(self.account_address, sigs.address);

        // check local storage begore verifying
        if let Some(local_sigs) = self.check_applied(&proposal)? {
            return Ok(Some(local_sigs));
        }
        self.verify_proposal(&proposal)?;

        let mut verified_signatures = BTreeMap::new();
        let (payload_body, payload_body_signature, output) = match self.pending_txn() {
            None => self.execute_proposal(&proposal)?,
            Some(PendingTransaction::WaitForSig {
                proposal: local_proposal,
                output,
                signatures,
                ..
            }) => {
                ensure!(
                    proposal.channel_txn.hash() == local_proposal.channel_txn.hash(),
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
            Some(PendingTransaction::WaitForApply { .. }) => bail!("proposal already fullfilled"),
        };

        let witness_data =
            WitnessData::new(self.channel_sequence_number(), output.write_set().clone());

        self.verify_txn_sigs(&payload_body, &witness_data, &sigs)?;
        verified_signatures.insert(sigs.address, sigs);

        // if the output modifies user's channel state, permission need to be granted by user.
        // it cannot be auto-signed.
        let can_auto_signed = !witness_data
            .write_set()
            .contains_channel_resource(&self.account_address);
        if can_auto_signed && !verified_signatures.contains_key(&self.account_address) {
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
        match self.pending_txn() {
            None => Ok(None),
            Some(PendingTransaction::WaitForApply { .. }) => Ok(None),
            Some(PendingTransaction::WaitForSig {
                proposal,
                output,
                mut signatures,
            }) => {
                if channel_txn_id != proposal.channel_txn.hash() {
                    let err = format_err!("channel_txn_id confilict with local pending state");
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
                    Ok(user_sigs)
                } else {
                    self.clear_pending_txn()?;
                    Ok(None)
                }
            }
        }
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
                Some(PendingTransaction::WaitForSig { .. }) => {
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

        // TODO: ensure proposer is belong to the channel
        // TODO: check public key match proposer address
        proposal
            .proposer_public_key
            .verify_signature(&channel_txn.hash(), &proposal.proposer_signature)?;
        Ok(())
    }

    fn verify_txn_sigs(
        &self,
        payload_body: &ChannelTransactionPayloadBodyV2,
        witness_data: &WitnessData,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<()> {
        channel_txn_sigs.public_key.verify_signature(
            &payload_body.hash(),
            &channel_txn_sigs.channel_payload_signature,
        )?;
        ensure!(
            &witness_data.hash() == &channel_txn_sigs.witness_data_hash,
            "new witness hash mismatched"
        );
        channel_txn_sigs.public_key.verify_signature(
            &channel_txn_sigs.witness_data_hash,
            &channel_txn_sigs.witness_data_signature,
        )?;
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

    fn witness_data(&self) -> Witness {
        //        self.store.get_latest_write_set()
        unimplemented!()
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
                PendingTransaction::WaitForSig {
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
            Some(PendingTransaction::WaitForSig { .. }) => ChannelStage::Pending,
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

    fn generate_proposal(
        &self,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionProposal> {
        // TODO: state view should be shared to reduce fetching account state from layer1.
        let state_view = self.channel_view(None, self.chain_client.as_ref())?;

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
        let channel_transaction = ChannelTransaction::new(
            chain_version,
            self.channel_address,
            self.channel_sequence_number(),
            channel_op,
            args,
            self.account_address,
            account_seq_number,
            txn_expiration(),
        );
        let channel_txn_hash = channel_transaction.hash();
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
        let (payload_body, payload_body_signature) = self
            .build_and_sign_channel_txn_payload_body_v2(
                self.witness_data(),
                &proposal.channel_txn,
            )?;

        let output = {
            // create mocked txn to execute
            let raw_txn =
                self.build_raw_txn_from_channel_txn(payload_body.clone(), &proposal.channel_txn)?;
            // execute txn on offchain vm, should mock sender and receiver signature with a local
            // keypair. the vm will skip signature check on offchain vm.
            let txn = self.keypair.sign_txn(raw_txn)?;
            let version = channel_txn.version();
            let state_view = self.channel_view(Some(version), self.chain_client.as_ref())?;
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
    ) -> Result<Option<(ChannelTransactionSigs)>> {
        let channel_txn = &proposal.channel_txn;
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

        // FIXME: refactor this
        // if found an already applied txn in local storage,
        // we can return directly after check the hash of transaction and signatures.
        if let Some(signed_txn) = applied_txn {
            if signed_txn.raw_tx.hash() == channel_txn.hash()
                && signed_txn.sender_signature.hash() == channel_txn_sender_sigs.hash()
            {
                Ok(Some(signed_txn.receiver_signature))
            } else {
                Err(format_err!(
                    "invalid txn, txn with channel_seq_number is mismatched"
                ))
            }
        } else {
            Ok(None)
        }
    }

    fn generate_txn_sigs(
        &self,
        channel_txn: &ChannelTransaction,
        witness_data: &WitnessData,
    ) -> Result<ChannelTransactionSigs> {
        let (_, payload_body_signature) =
            self.build_and_sign_channel_txn_payload_body_v2(self.witness_data(), channel_txn)?;

        let witness_data_hash = witness_data.hash();
        let witness_data_signature = self.keypair.private_key.sign_message(&witness_data_hash);

        Ok(ChannelTransactionSigs::new(
            self.account_address,
            self.keypair.public_key.clone(),
            payload_body_signature,
            witness_data_hash,
            witness_data_signature,
        ))
    }

    /// Grant the proposal and save it into pending txn
    fn do_grant_proposal(
        &mut self,
        proposal: ChannelTransactionProposal,
        output: TransactionOutput,
        mut signatures: BtreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Result<()> {
        let witness_data =
            WitnessData::new(self.channel_sequence_number(), output.write_set().clone());
        let user_sigs = self.generate_txn_sigs(&proposal.channel_txn, &witness_data)?;
        signatures.insert(user_sigs.address, user_sigs.clone());

        self.save_pending_txn(proposal, output, signatures)
    }

    fn save_pending_txn(
        &mut self,
        proposal: ChannelTransactionProposal,
        output: TransactionOutput,
        signatures: BtreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Result<()> {
        let mut pending_txn = PendingTransaction::WaitForSig {
            proposal,
            output,
            signatures,
        };
        pending_txn.try_fullfill(&self.participants_states.keys().collect());
        let should_persist = output.write_set().contains_onchain_resource();
        self.store.save_pending_txn(pending_txn, should_persist)?;
        Ok(())
    }

    /// clear local pending state
    fn clear_pending_txn(&mut self) -> Result<()> {
        unimplemented!()
    }
}

//pub enum ChannelEvent {
//    ChannelStarted { channel: Channel },
//    ChannelStopped { participant: AccountAddress },
//}
//pub struct ChannelManager {}
