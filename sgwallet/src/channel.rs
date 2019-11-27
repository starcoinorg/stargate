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
    StreamExt,
};
use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use libra_crypto::test_utils::KeyPair;
use libra_crypto::{hash::CryptoHash, HashValue, SigningKey, VerifyingKey};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::channel::witness::{Witness, WitnessData};
use libra_types::identifier::Identifier;
use libra_types::language_storage::ModuleId;
use libra_types::transaction::helpers::TransactionSigner;
use libra_types::transaction::{
    ChannelTransactionPayloadBodyV2, ChannelTransactionPayloadV2, RawTransaction, ScriptAction,
    TransactionArgument, TransactionPayload, Version,
};
use libra_types::write_set::WriteSet;
use libra_types::{
    access_path::AccessPath, account_address::AccountAddress,
    channel_account::ChannelAccountResource, transaction::TransactionOutput, write_set::WriteOp,
};
use sgchain::star_chain_client::ChainClient;
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use sgtypes::channel_transaction::{
    ChannelOp, ChannelTransaction, ChannelTransactionProposal, ChannelTransactionRequest,
};
use sgtypes::channel_transaction_sigs::ChannelTransactionSigs;
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::pending_txn::PendingTransaction;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::{
    channel::{ChannelStage, ChannelState},
    sg_error::SgError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::sync::Arc;
use vm::gas_schedule::GasAlgebra;

pub enum ChannelMsg {
    Execute {
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
        responder: oneshot::Sender<Result<(ChannelTransactionProposal, ChannelTransactionSigs)>>,
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
        let channel_address = AccountAddress::try_from(&participants).unwrap();
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

    pub fn channel_address(&self) -> &AccountAddress {
        &self.channel_address
    }
    pub fn participant_addresses(&self) -> &[AccountAddress] {
        self.participant_addresses.as_slice()
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
            Some(PendingTransaction::WaitForApply { output, .. }) => {
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

    fn channel_view(&self, version: Option<Version>) -> Result<ChannelStateView> {
        let latest_writeset = self.witness_data().into_write_set();
        ChannelStateView::new(
            self.account_address,
            &self.participants_states,
            latest_writeset,
            version,
            self.chain_client.as_ref(),
        )
    }

    fn build_raw_txn_from_channel_txn(
        &self,
        channel_payload_body: ChannelTransactionPayloadBodyV2,
        channel_txn: &ChannelTransaction,
        mut signatures: BTreeMap<AccountAddress, Ed25519Signature>,
        max_gas_amount: u64,
    ) -> Result<RawTransaction> {
        let channel_participant_size = self.participant_addresses.len();
        let mut keys = Vec::with_capacity(channel_participant_size);
        let mut sigs = Vec::with_capacity(channel_participant_size);
        for (addr, key) in self.participant_addresses.iter() {
            let sig = signatures.remove(addr);
            keys.push(key.clone());
            sigs.push(sig);
        }
        debug_assert!(signatures.len() == 0);

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
        let action = channel_op_to_action(channel_txn.operator(), channel_txn.args().to_vec())?;

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
    ) -> Result<(ChannelTransactionProposal, ChannelTransactionSigs)> {
        // generate proposal
        let proposal = self.generate_proposal(channel_op, args)?;

        // execute proposal to get txn payload and txn witness data for later use
        let (_payload_body, _payload_body_signature, output) = self.execute_proposal(&proposal)?;

        self.do_grant_proposal(proposal.clone(), output, BTreeMap::new())?;

        let pending = self.pending_txn().expect("pending txn must exists");
        let user_sigs = pending
            .get_signature(&self.account_address)
            .expect("user signature must exists");
        Ok((proposal, user_sigs))
    }

    /// handle incoming proposal, return my sigs.
    /// If I don't agree the proposal, return None.
    /// If the proposal is already handled, also return my sigs from local cached state.
    async fn collect_proposal_and_sigs_async(
        &mut self,
        proposal: ChannelTransactionProposal,
        sigs: ChannelTransactionSigs,
    ) -> Result<Option<ChannelTransactionSigs>> {
        debug_assert_ne!(self.account_address, proposal.channel_txn.proposer());
        debug_assert_ne!(self.account_address, sigs.address);

        // check local storage begore verifying
        if let Some(local_sigs) = self.check_applied(&proposal)? {
            return Ok(Some(local_sigs));
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

        // If already sign the proposal, return directly.
        if verified_signatures.contains_key(&self.account_address) {
            return Ok(Some(
                verified_signatures.remove(&self.account_address).unwrap(),
            ));
        }

        self.verify_txn_sigs(&payload_body, &output, &sigs)?;
        verified_signatures.insert(sigs.address, sigs);

        // if the output modifies user's channel state, permission need to be granted by user.
        // it cannot be auto-signed.
        let can_auto_signed = !output
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
            None | Some(PendingTransaction::WaitForApply { .. }) => {
                bail!("no pending txn to grant")
            }
            Some(PendingTransaction::WaitForSig {
                proposal,
                output,
                signatures,
            }) => {
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
                    Ok(None)
                }
            }
        }
    }

    async fn apply_pending_txn_async(&mut self) -> Result<u64> {
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
                    signatures
                        .iter()
                        .map(|(addr, s)| (addr.clone(), s.channel_payload_signature.clone()))
                        .collect::<BTreeMap<_, _>>(),
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
                self.participants_states
                    .contains_key(&channel_txn.proposer()),
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
                let state = match self.participants_states.get(&ap.address) {
                    None => bail!(
                        "Unexpect witness_payload access_path {:?} apply to channel {:?}",
                        &ap.address,
                        self.channel_address
                    ),
                    Some(state) => state,
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
        self.store.get_latest_witness().unwrap_or_default()
    }

    fn channel_sequence_number(&self) -> u64 {
        match self.channel_account_resource() {
            None => 0,
            Some(account_resource) => account_resource.channel_sequence_number(),
        }
    }

    /// FIXME: Once the detail of channel account path is determined,
    /// this should be implemented
    pub fn channel_account_resource(&self) -> Option<ChannelAccountResource> {
        //        let access_path = AccessPath::new_for_data_path(
        //            self.account_address,
        //            DataPath::channel_account_path(self.participant.address()),
        //        );
        //        self.get_local(&access_path)
        //            .unwrap()
        //            .and_then(|value| ChannelAccountResource::make_from(value).ok())
        unimplemented!()
    }

    fn pending_txn(&self) -> Option<PendingTransaction> {
        self.store.get_pending_txn()
    }

    fn get_pending_channel_txn_request(&self) -> Option<ChannelTransactionRequest> {
        self.pending_txn()
            .as_ref()
            .and_then(|pending| match pending {
                PendingTransaction::WaitForSig {
                    proposal,
                    output: _,
                    signatures,
                    ..
                } => {
                    let user_sig = signatures.get(&self.account_address).cloned();
                    debug_assert!(user_sig.is_some());

                    Some(ChannelTransactionRequest::new(
                        proposal.clone(),
                        user_sig.unwrap(),
                    ))
                }
                _ => None,
            })
    }

    fn stage(&self) -> ChannelStage {
        match self.pending_txn() {
            Some(PendingTransaction::WaitForApply { .. }) => ChannelStage::Syncing,
            Some(PendingTransaction::WaitForSig { .. }) => ChannelStage::Pending,
            None => match self.channel_account_resource() {
                Some(resource) => {
                    if resource.closed() {
                        ChannelStage::Closed
                    } else {
                        ChannelStage::Idle
                    }
                }
                None => ChannelStage::Opening,
            },
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
        let witness = self.witness_data();
        access_local(witness.write_set(), &self.participants_states, access_path)
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
                BTreeMap::new(),
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
        if let Some(mut signed_txn) = applied_txn {
            let signature = signed_txn
                .signatures
                .remove(&self.account_address)
                .expect("applied txn should have user signature");
            Ok(Some(signature))
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
        let witness_data = WitnessData::new(self.channel_sequence_number(), ws);
        let witness_data_hash = CryptoHash::hash(&witness_data);
        let witness_data_signature = self.keypair.private_key.sign_message(&witness_data_hash);

        let travel_output_witness_signature = if output.is_travel_txn() {
            let txn_output_witness_data =
                WitnessData::new(self.channel_sequence_number(), output.write_set().clone());
            Some(
                self.keypair
                    .private_key
                    .sign_message(&CryptoHash::hash(&txn_output_witness_data)),
            )
        } else {
            None
        };

        Ok(ChannelTransactionSigs::new(
            self.account_address,
            self.keypair.public_key.clone(),
            payload_body_signature,
            witness_data_hash,
            witness_data_signature,
            travel_output_witness_signature,
        ))
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
        let witness_data = WitnessData::new(self.channel_sequence_number(), ws);

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
                        self.channel_sequence_number(),
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
        let _witness_data =
            WitnessData::new(self.channel_sequence_number(), output.write_set().clone());
        let user_sigs = self.generate_txn_sigs(&proposal.channel_txn, &output)?;
        signatures.insert(user_sigs.address, user_sigs.clone());

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
        let participants = self
            .participants_states
            .keys()
            .map(Clone::clone)
            .collect::<Vec<_>>();
        pending_txn.try_fulfill(&participants);
        self.store.save_pending_txn(pending_txn, is_travel_txn)?;
        Ok(())
    }

    /// clear local pending state
    fn clear_pending_txn(&self) -> Result<()> {
        self.store.clear_pending_txn()
    }
}

fn channel_op_to_action(op: &ChannelOp, args: Vec<TransactionArgument>) -> Result<ScriptAction> {
    match op {
        ChannelOp::Action {
            module_address,
            module_name,
            function_name,
        } => {
            let module_id = ModuleId::new(
                module_address.clone(),
                Identifier::new(module_name.clone().into_boxed_str())?,
            );
            Ok(ScriptAction::new(
                module_id,
                Identifier::new(function_name.clone().into_boxed_str())?,
                args,
            ))
        }
        ChannelOp::Open => {
            // FIXME: use methods from Channel type
            let module_id = ModuleId::new(AccountAddress::default(), Identifier::new("Channel")?);
            Ok(ScriptAction::new(module_id, Identifier::new("open")?, args))
        }
        ChannelOp::Close => unimplemented!(),
        ChannelOp::Execute { .. } => unimplemented!(),
    }
}

pub(crate) fn access_local<'a>(
    latest_write_set: &'a WriteSet,
    participant_states: &'a BTreeMap<AccountAddress, ChannelState>,
    access_path: &AccessPath,
) -> Result<Option<Vec<u8>>> {
    match latest_write_set.get(access_path) {
        Some(op) => match op {
            WriteOp::Value(value) => Ok(Some(value.clone())),
            WriteOp::Deletion => Ok(None),
        },
        None => match participant_states.get(&access_path.address) {
            Some(s) => Ok(s.get(&access_path.path)),
            None => Err(format_err!("Unexpected access_path: {}", access_path)),
        },
    }
}
