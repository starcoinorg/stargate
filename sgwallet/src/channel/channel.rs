// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::{
    channel::{
        access_local, channel_event_stream::ChannelEventStream, AccessingResource,
        ApplyCoSignedTxn, ApplyPendingTxn, ApplySoloTxn, CancelPendingTxn, Channel, ChannelEvent,
        CollectProposalWithSigs, Execute, GetPendingTxn, GrantProposal,
    },
    utils::contract::{
        channel_challenge_name, channel_close_name, channel_resolve_name, parse_channel_event,
    },
    wallet::{submit_transaction, watch_transaction, ChannelNotifyEvent},
};
use anyhow::{bail, ensure, format_err, Result};
use async_trait::async_trait;
use coerce_rt::actor::{
    context::{ActorHandlerContext, ActorStatus},
    message::{Handler, Message},
    Actor, ActorRef,
};
use futures::StreamExt;
use libra_crypto::hash::CryptoHash;
use libra_logger::prelude::*;
use libra_types::{
    account_address::AccountAddress,
    account_config::{account_module_name, core_code_address},
    channel::ChannelResource,
    contract_event::{ContractEvent, EventWithProof},
    transaction::{
        SignedTransaction, Transaction, TransactionArgument, TransactionInfo,
        TransactionListWithProof, TransactionOutput, TransactionPayload, TransactionWithProof,
    },
    write_set::WriteSet,
};
use sgtypes::{
    applied_channel_txn::AppliedChannelTxn,
    channel::ChannelState,
    channel_transaction::{ChannelOp, ChannelTransaction},
    channel_transaction_sigs::ChannelTransactionSigs,
    channel_transaction_to_commit::ChannelTransactionToCommit,
    pending_txn::{PendingTransaction, ProposalLifecycle},
    signed_channel_transaction::SignedChannelTransaction,
    signed_channel_transaction_with_proof::SignedChannelTransactionWithProof,
};
use std::collections::BTreeMap;

//impl Channel {
//    #[allow(dead_code)]
//    async fn bootstrap(&mut self) -> Result<()> {
//        let channel_state = self
//            .chain_client
//            .get_account_state(self.channel_address, None)?;
//        let onchain_channel_resource = channel_state
//            .get_resource::<ChannelResource>(&DataPath::onchain_resource_path(
//                ChannelResource::struct_tag(),
//            ))?
//            .ok_or(format_err!("channel resource should exists"))?;
//        if onchain_channel_resource.closed() {
//            bail!("channel is already closed");
//        } else if onchain_channel_resource.locked() {
//        } else {
//            //
//        }
//
//        Ok(())
//    }
//}
//
#[async_trait]
impl Actor for Channel {
    async fn started(&mut self, ctx: &mut ActorHandlerContext) {
        let to_be_apply = {
            let pending_proposal = self.pending_txn();
            if let Some(pending_proposal) = pending_proposal {
                if pending_proposal.consensus_reached() {
                    let (proposal, _output, _) = pending_proposal.into();
                    //        debug_assert!(output.is_travel_txn(), "only travel txn is persisted");
                    Some(proposal)
                } else {
                    None
                }
            } else {
                None
            }
        };

        let mut myself = self.actor_ref(ctx).await;

        if let Some(_) = to_be_apply {
            if let Err(_) = myself.notify(ApplyPendingTxn).await {
                panic!("should not happen");
            }
        }

        let start_number = self
            .stm
            .channel_resource()
            .map(|r| r.event_handle().count());
        if let Some(c) = start_number {
            let channel_event_stream = ChannelEventStream::new_from_chain_client(
                self.chain_client.clone(),
                self.channel_address().clone(),
                c,
                10,
            );
            tokio::task::spawn(channel_event_loop(channel_event_stream, myself.clone()));
        }
    }

    async fn stopped(&mut self, _ctx: &mut ActorHandlerContext) {
        if let Err(e) = self
            .channel_event_sender
            .notify(ChannelNotifyEvent {
                channel_event: ChannelEvent::Stopped {
                    channel_address: self.channel_address().clone(),
                },
            })
            .await
        {
            error!(
                "channel[{:?}]: fail to emit stopped event, error: {:?}",
                &self.channel_address(),
                e
            );
        }
        crit!("channel {} task terminated", self.channel_address());
    }
}
#[async_trait]
impl Handler<Execute> for Channel {
    async fn handle(
        &mut self,
        message: Execute,
        _ctx: &mut ActorHandlerContext,
    ) -> <Execute as Message>::Result {
        let Execute { channel_op, args } = message;
        let proposal = self.stm.generate_proposal(channel_op, args)?;
        let mut pending_txn = self.pending_txn();
        self.stm.handle_new_proposal(&mut pending_txn, proposal)?;
        debug_assert!(pending_txn.is_some());
        let mut pending_txn = pending_txn.unwrap();
        let my_signature = self
            .stm
            .generate_txn_sigs(&pending_txn.proposal().channel_txn, pending_txn.output())?;
        let channel_txn_id = CryptoHash::hash(&pending_txn.proposal().channel_txn);
        self.stm.handle_proposal_signature(
            &mut pending_txn,
            channel_txn_id,
            my_signature.clone(),
        )?;
        self.save_pending_txn(pending_txn.clone())?;
        let (proposal, output, _) = pending_txn.into();
        Ok((proposal, my_signature, output))
    }
}

/// handle incoming proposal, return my sigs.
/// If I don't agree the proposal, return None.
/// If the proposal is already handled, also return my sigs from local cached state.
#[async_trait]
impl Handler<CollectProposalWithSigs> for Channel {
    async fn handle(
        &mut self,
        message: CollectProposalWithSigs,
        _ctx: &mut ActorHandlerContext,
    ) -> <CollectProposalWithSigs as Message>::Result {
        let CollectProposalWithSigs { proposal, sigs } = message;
        debug_assert_ne!(self.account_address(), &sigs.address);
        debug!(
            "{} - collect proposal signature from {}",
            &self.account_address(),
            &sigs.address
        );
        // if found an already applied txn in local storage,
        // we can return directly after check the hash of transaction and signatures.
        if let Some(signed_txn) =
            self.check_applied(proposal.channel_txn.channel_sequence_number())?
        {
            let version = signed_txn.version;
            let applied_txn = signed_txn.signed_transaction;
            match applied_txn {
                AppliedChannelTxn::Travel(_) => bail!("proposal is already commited onchain"),
                AppliedChannelTxn::Offchain(mut t) => {
                    if CryptoHash::hash(&proposal.channel_txn) != CryptoHash::hash(&t.raw_tx) {
                        bail!("invalid proposal, channel already applied a different proposal with same channel seq number {}", version);
                    }

                    let signature = t
                        .signatures
                        .remove(&self.account_address())
                        .expect("applied txn should have user signature");
                    return Ok(Some(signature));
                }
            }
        }
        let mut pending_txn = self.pending_txn();
        self.stm.handle_new_proposal(&mut pending_txn, proposal)?;
        debug_assert!(pending_txn.is_some());

        let mut pending_txn = pending_txn.unwrap();
        let txn_hash = CryptoHash::hash(&pending_txn.proposal().channel_txn);
        self.stm
            .handle_proposal_signature(&mut pending_txn, txn_hash, sigs)?;

        if self.stm.can_auto_sign_pending_proposal(&pending_txn)? {
            debug!(
                "{}/{} - auto sign channel txn",
                &self.account_address(),
                &self.channel_address()
            );

            let my_signature = self
                .stm
                .generate_txn_sigs(&pending_txn.proposal().channel_txn, pending_txn.output())?;
            let proposal_hash = CryptoHash::hash(&pending_txn.proposal().channel_txn);
            self.stm
                .handle_proposal_signature(&mut pending_txn, proposal_hash, my_signature)?;
        }

        self.save_pending_txn(pending_txn.clone())?;

        let user_sigs = pending_txn.get_signature(&self.account_address());
        Ok(user_sigs)
    }
}

#[async_trait]
impl Handler<GrantProposal> for Channel {
    async fn handle(
        &mut self,
        message: GrantProposal,
        _ctx: &mut ActorHandlerContext,
    ) -> <GrantProposal as Message>::Result {
        let GrantProposal { channel_txn_id } = message;
        debug!(
            "{} grant proposal {}",
            &self.account_address(),
            &channel_txn_id
        );
        let pending_txn = self.pending_txn();
        ensure!(pending_txn.is_some(), "no pending txn");
        let mut pending_txn = pending_txn.unwrap();
        let proposal = pending_txn.proposal();
        if channel_txn_id != CryptoHash::hash(&proposal.channel_txn) {
            let err = format_err!("channel_txn_id conflict with local pending txn");
            return Err(err);
        }
        ensure!(
            !pending_txn.consensus_reached(),
            "pending txn is already consensus_reached"
        );

        let my_signature = self
            .stm
            .generate_txn_sigs(&pending_txn.proposal().channel_txn, pending_txn.output())?;
        let proposal_hash = CryptoHash::hash(&pending_txn.proposal().channel_txn);
        self.stm.handle_proposal_signature(
            &mut pending_txn,
            proposal_hash,
            my_signature.clone(),
        )?;
        self.save_pending_txn(pending_txn)?;
        Ok(my_signature)
    }
}

#[async_trait]
impl Handler<CancelPendingTxn> for Channel {
    async fn handle(
        &mut self,
        message: CancelPendingTxn,
        ctx: &mut ActorHandlerContext,
    ) -> <CancelPendingTxn as Message>::Result {
        let CancelPendingTxn { channel_txn_id } = message;

        let pending_txn = self.pending_txn();
        ensure!(pending_txn.is_some(), "no pending txn");
        let pending_txn = pending_txn.unwrap();
        let proposal = pending_txn.proposal();
        if channel_txn_id != CryptoHash::hash(&proposal.channel_txn) {
            let err = format_err!("channel_txn_id conflict with local pending txn");
            return Err(err);
        }
        ensure!(
            !pending_txn.consensus_reached(),
            "pending txn is already consensus_reached"
        );

        self.clear_pending_txn()?;
        if proposal.channel_txn.operator().is_open() {
            ctx.set_status(ActorStatus::Stopping);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<ApplyPendingTxn> for Channel {
    async fn handle(
        &mut self,
        _message: ApplyPendingTxn,
        _ctx: &mut ActorHandlerContext,
    ) -> <ApplyPendingTxn as Message>::Result {
        debug!("{} apply pending txn", self.account_address());

        let pending_txn = self.pending_txn();
        ensure!(pending_txn.is_some(), "should have txn to apply");
        let mut pending_txn = pending_txn.unwrap();
        ensure!(
            pending_txn.lifecycle() == ProposalLifecycle::Negotiating
                || pending_txn.lifecycle() == ProposalLifecycle::Agreed,
            "cannot apply pending txn which is already applying or traveling",
        );

        self.stm.handle_apply_proposal(&mut pending_txn)?;

        let proposal_lifecycle = pending_txn.lifecycle();
        match proposal_lifecycle {
            ProposalLifecycle::Applying => {
                let (proposal, output, signatures) = pending_txn.into();
                self.apply(proposal.channel_txn, output, signatures)?;
                return Ok(None);
            }
            ProposalLifecycle::Traveling => {
                let channel_txn = &pending_txn.proposal().channel_txn;
                if self.account_address() == &channel_txn.proposer() {
                    let signed_txn = self.stm.build_signed_txn(&pending_txn)?;
                    submit_transaction(self.chain_client.as_ref(), signed_txn).await?;
                }
                let txn_sender = channel_txn.proposer();
                let seq_number = channel_txn.sequence_number();

                self.save_pending_txn(pending_txn)?;
                Ok(Some((txn_sender, seq_number)))
            }
            _ => unreachable!(),
        }
    }
}

#[async_trait]
impl Handler<AccessingResource> for Channel {
    async fn handle(
        &mut self,
        message: AccessingResource,
        _ctx: &mut ActorHandlerContext,
    ) -> <AccessingResource as Message>::Result {
        let AccessingResource { path } = message;
        debug!(
            "{} accessing resource {:?}",
            self.account_address(),
            path.data_path()
        );
        access_local(
            self.stm.witness().write_set(),
            self.stm.channel_state(),
            &path,
        )
        .map(|d| d.map(|o| o.to_vec()))
    }
}

#[async_trait]
impl Handler<GetPendingTxn> for Channel {
    async fn handle(
        &mut self,
        _message: GetPendingTxn,
        _ctx: &mut ActorHandlerContext,
    ) -> <GetPendingTxn as Message>::Result {
        debug!("{} get pending txn", &self.account_address());
        self.pending_txn()
    }
}

#[async_trait]
impl Handler<ApplyCoSignedTxn> for Channel {
    async fn handle(
        &mut self,
        message: ApplyCoSignedTxn,
        ctx: &mut ActorHandlerContext,
    ) -> <ApplyCoSignedTxn as Message>::Result {
        let ApplyCoSignedTxn {
            txn,
            txn_info,
            version,
            events,
            ..
        } = message;
        debug!(
            "{} apply co-signed txn at version {}",
            &self.account_address(),
            version
        );
        let signed_txn = match txn {
            Transaction::UserTransaction(s) => s,
            _ => {
                bail!("should be user txn");
            }
        };

        let raw_txn = signed_txn.raw_txn();
        let txn_sender = raw_txn.sender();
        let channel_txn_payload = match raw_txn.payload() {
            TransactionPayload::Channel(channel_txn_payload) => channel_txn_payload,
            _ => bail!("should be channel txn"),
        };

        debug_assert!(self.participant_addresses().contains(&txn_sender));
        debug_assert!(self.channel_address() == &channel_txn_payload.channel_address());
        debug_assert!(channel_txn_payload.is_authorized());

        let txn_channel_seq_number = channel_txn_payload.witness().channel_sequence_number();
        let local_channel_seq_number = self.stm.channel_sequence_number();
        // compare the new txn's witness sequence number with local sequence_number
        // if equal, it means new txn committed on-chain, but I don't aware.
        // if less by only one, maybe proposer didn't receive my signature, and he proposed the txn on-chain,
        // or it means the new txn proposer had submitted a stale channel txn purposely.
        // if bigger, it's a bug.
        debug_assert!(
            txn_channel_seq_number <= local_channel_seq_number,
            "Local state is stale, there must be some bugs"
        );
        // if the message is outdated
        if txn_channel_seq_number < local_channel_seq_number {
            let applied_txn = self.check_applied(txn_channel_seq_number)?;
            debug_assert!(applied_txn.is_some());
            let applied_txn = applied_txn.unwrap();
            match &applied_txn.signed_transaction {
                AppliedChannelTxn::Travel(s) => {
                    if s.raw_txn().hash() == raw_txn.hash() {
                        // it's ok, it may be a late message.
                        return Ok(applied_txn.proof.transaction_info().gas_used());
                    } else {
                        // FIXME: what happened, why I apply a travel txn different from on chain.
                        unimplemented!()
                    }
                }
                AppliedChannelTxn::Offchain(_s) => {
                    if &raw_txn.sender() == self.account_address() {
                        // FIXME: what happened, why I apply a offchain txn, while still travelled it.
                        unimplemented!()
                    } else {
                        // it means participant make a stale offchain txn travel directly.
                        // but I already applied the txn locally.
                        // I cannot challenge him, because the channel is not locked.
                        // FIXME: what's should I do.
                        unimplemented!()
                    }
                }
            }
        }

        debug_assert!(txn_channel_seq_number <= local_channel_seq_number);
        let gas_used = txn_info.gas_used();

        // 1. I trust the txn and apply it into local.
        self.apply_travel(version, signed_txn.clone(), txn_info, events)?;
        // 2. after apply, check channel state
        let channel_resource: ChannelResource = self
            .stm
            .channel_resource()
            .ok_or(format_err!("channel resource should exists in local"))?;
        debug_assert!(!channel_resource.locked());

        if channel_resource.opened() {
            // nothing to do. everything is good now.
            debug!(
                "{}/{} - channel resource seq number: {}",
                self.account_address(),
                self.channel_address(),
                channel_resource.channel_sequence_number()
            );
            if channel_resource.channel_sequence_number() == 1 {
                debug!(
                    "{}/{} - just open channel, start watch channel event",
                    self.account_address(),
                    self.channel_address()
                );
                let channel_event_stream = ChannelEventStream::new_from_chain_client(
                    self.chain_client.clone(),
                    self.channel_address().clone(),
                    channel_resource.event_handle().count(),
                    10,
                );
                let myself = self.actor_ref(ctx).await;
                tokio::task::spawn(channel_event_loop(channel_event_stream, myself));
            }
        } else if channel_resource.closed() {
            debug!(
                "{}/{} - applied a action which close channel",
                self.account_address(),
                self.channel_address(),
            );
            ctx.set_status(ActorStatus::Stopping);
        }

        Ok(gas_used)
    }
}

#[async_trait]
impl Handler<ApplySoloTxn> for Channel {
    async fn handle(
        &mut self,
        message: ApplySoloTxn,
        ctx: &mut ActorHandlerContext,
    ) -> <ApplySoloTxn as Message>::Result {
        let ApplySoloTxn {
            txn,
            txn_info,
            version,
            events,
            ..
        } = message;
        debug!(
            "{} apply solo txn at version {}",
            &self.account_address(),
            version
        );
        let signed_txn = match txn {
            Transaction::UserTransaction(s) => s,
            _ => {
                bail!("should be user txn");
            }
        };

        let raw_txn = signed_txn.raw_txn();
        let txn_sender = raw_txn.sender();
        let channel_txn_payload = match raw_txn.payload() {
            TransactionPayload::Channel(channel_txn_payload) => channel_txn_payload,
            _ => bail!("should be channel txn"),
        };

        debug_assert!(self.participant_addresses().contains(&txn_sender));
        debug_assert!(self.channel_address() == &channel_txn_payload.channel_address());
        debug_assert!(!channel_txn_payload.is_authorized());

        let txn_channel_seq_number = channel_txn_payload.witness().channel_sequence_number();
        let local_channel_seq_number = self.stm.channel_sequence_number();
        // compare the new txn's witness sequence number with local sequence_number
        // if equal, it means new txn committed on-chain, but I don't aware.
        // if less by only one, maybe proposer didn't receive my signature, and he proposed the txn on-chain,
        // or it means the new txn proposer had submitted a stale channel txn purposely.
        // if bigger, it's a bug.
        debug_assert!(
            txn_channel_seq_number <= local_channel_seq_number,
            "Local state is stale, there must be some bugs"
        );

        if txn_channel_seq_number < local_channel_seq_number {
            let applied_txn = self.check_applied(channel_txn_payload.channel_sequence_number())?;
            debug_assert!(applied_txn.is_some());
            let applied_txn = applied_txn.unwrap();
            match &applied_txn.signed_transaction {
                AppliedChannelTxn::Travel(s) => {
                    if s.raw_txn().hash() == raw_txn.hash() {
                        return Ok(applied_txn.proof.transaction_info().gas_used());
                    } else {
                        if self.account_address() == &raw_txn.sender() {
                            // FIXME: why would I applied a txn which is different the travel txn which sent by myself.
                            unimplemented!()
                        } else {
                            // FIXME: why would I applied a travel txn whose hash
                            // is different from the new received travel txn.
                            unimplemented!()
                        }
                    }
                }
                AppliedChannelTxn::Offchain(_s) => {
                    if self.account_address() == &raw_txn.sender() {
                        // FIXME: why whould I applied an offchain txn, while still submit a outdated solo txn to chain.
                        unimplemented!()
                    } else {
                        // dual submits a stale txn, I need to challenge him
                        debug!(
                            "{}/{} - unauthorized channel txn, going challenge dual",
                            self.account_address(),
                            self.channel_address(),
                        );
                        // so I submit a challenge to chain.
                        let _ = self
                            .solo_action(
                                ctx,
                                ChannelOp::Action {
                                    module_address: core_code_address(),
                                    module_name: account_module_name().as_str().to_string(),
                                    function_name: channel_challenge_name().as_str().to_string(),
                                },
                                vec![],
                            )
                            .await?;

                        return Ok(0);
                    }
                }
            }
        }

        debug_assert!(txn_channel_seq_number == local_channel_seq_number);
        let gas_used = txn_info.gas_used();
        // 1. I trust the txn and apply it into local.
        self.apply_travel(version, signed_txn.clone(), txn_info, events)?;
        // 2. after apply, check channel state
        let channel_resource: ChannelResource = self
            .stm
            .channel_resource()
            .ok_or(format_err!("channel resource should exists in local"))?;
        if channel_resource.locked() {
            debug!(
                "{}/{} - applied a action which lock channel",
                self.account_address(),
                self.channel_address(),
            );
            if self.account_address() == &txn_sender {
                // I lock the channel, wait sender to resolve
                // TODO: move the timeout check into a timer
                let time_lock = self.stm.channel_lock_by_resource().unwrap().time_lock;
                debug!(
                    "{}/{} - the solo txn I submitted applied locally, wait receiver timeout, time_lock: {}",
                    self.account_address(), self.channel_address(), time_lock
                );
                self.watch_channel_lock_timeout(ctx).await?;
            } else {
                debug!(
                    "{}/{} - receiver a txn which lock channel, going to resolve it",
                    self.account_address(),
                    self.channel_address(),
                );

                // drop the receiver, as I don't need wait the result
                let _ = self
                    .solo_action(
                        ctx,
                        ChannelOp::Action {
                            module_address: core_code_address(),
                            module_name: account_module_name().as_str().to_string(),
                            function_name: channel_resolve_name().as_str().to_string(),
                        },
                        vec![],
                    )
                    .await?;
            }
        } else if channel_resource.closed() {
            // no matter who close ths channel, the channel is done. we just live with it.
            debug!(
                "{}/{} - applied a action which close channel",
                self.account_address(),
                self.channel_address(),
            );
            ctx.set_status(ActorStatus::Stopping);
        } else {
            // nothing to do. everything is good now.
            debug!(
                "{}/{} - channel resolved now, channel sequence number: {}",
                self.account_address(),
                self.channel_address(),
                channel_resource.channel_sequence_number()
            );
        }

        Ok(gas_used)
    }
}

struct ChannelLockTimeout {
    pub block_height: u64,
    pub time_lock: u64,
}
impl Message for ChannelLockTimeout {
    type Result = Result<()>;
}
#[async_trait]
impl Handler<ChannelLockTimeout> for Channel {
    async fn handle(
        &mut self,
        message: ChannelLockTimeout,
        ctx: &mut ActorHandlerContext,
    ) -> <ChannelLockTimeout as Message>::Result {
        let ChannelLockTimeout {
            block_height,
            time_lock,
        } = message;
        debug!(
            "{}/{} - channel lock timeout-ed, block_height: {}, time_lock: {}, close channel now!",
            self.account_address(),
            self.channel_address(),
            block_height,
            time_lock
        );

        let ps = {
            let mut ps = self.participant_addresses().clone();
            ps.remove(&self.account_address());
            ps.into_iter()
                .next()
                .expect("should contain at least 1 participants")
        };

        // I submit a close channel to chain.
        let _ = self
            .solo_action(
                ctx,
                ChannelOp::Action {
                    module_address: core_code_address(),
                    module_name: account_module_name().as_str().to_string(),
                    function_name: channel_close_name().as_str().to_string(),
                },
                vec![TransactionArgument::Address(ps)],
            )
            .await?;

        Ok(())
    }
}

async fn channel_event_loop<A>(
    mut channel_event_stream: ChannelEventStream,
    mut actor_ref: ActorRef<A>,
) where
    A: Actor + Handler<ChannelStageChange> + 'static + Send + Sync,
{
    while let Some(evt) = channel_event_stream.next().await {
        let result = evt.and_then(|t| {
            let EventWithProof {
                transaction_version,
                event,
                ..
            } = t;
            let channel_event = parse_channel_event(&event);
            channel_event.map(|evt| ChannelStageChange {
                stage: evt.stage(),
                version: transaction_version,
                event_number: event.sequence_number(),
            })
        });
        match result {
            Err(e) => error!("get channel state change error, {}", e),
            Ok(t) => match actor_ref.send(t).await {
                Err(_) => {
                    info!("actor {:?} is gone, stop now", &actor_ref);
                    break;
                }
                Ok(Err(e)) => error!("fail to handle channel stage change event, {:?}", e),
                Ok(Ok(_)) => {}
            },
        }
    }
}

#[derive(Debug)]
struct ChannelStageChange {
    // channel stage, locked, closed
    pub stage: u64,
    // which txn version produce the change
    pub version: u64,
    pub event_number: u64,
}

impl Message for ChannelStageChange {
    type Result = Result<()>;
}

#[async_trait]
impl Handler<ChannelStageChange> for Channel {
    async fn handle(
        &mut self,
        message: ChannelStageChange,
        _ctx: &mut ActorHandlerContext,
    ) -> <ChannelStageChange as Message>::Result {
        debug!(
            "{}/{} - receiver channel stage change event: {:?}",
            self.account_address(),
            self.channel_address(),
            &message
        );

        let ChannelStageChange { version, .. } = message;

        if version <= self.stm.channel_state().version() {
            info!(
                "{}/{}, outdated channel event, version: {}, local version: {}, ignore it",
                &self.account_address(),
                &self.channel_address(),
                version,
                self.stm.channel_state().version()
            );
            return Ok(());
        }

        let TransactionListWithProof {
            mut transactions,
            events,
            proof,
            first_transaction_version,
        } = self
            .chain_client
            .get_transaction_async(version, 1, true)
            .await?;

        let (txn, txn_info, events) = match first_transaction_version {
            Some(v) => {
                debug_assert_eq!(v, version);
                let txn = transactions.remove(0);
                let txn_info = proof.transaction_infos().to_vec().remove(0);
                let events = events.unwrap().remove(0);
                (txn, txn_info, events)
            }
            None => {
                bail!("get_transaction return empty txn for version {}", version);
            }
        };

        let raw_txn = txn.as_signed_user_txn().unwrap().raw_txn();
        debug_assert!(raw_txn.payload().is_channel());

        if let TransactionPayload::Channel(cp) = raw_txn.payload() {
            let is_authorized = cp.is_authorized();
            // only watch unauthorized txn sent by participant
            if !is_authorized && self.account_address() != &raw_txn.sender() {
                let _ = self
                    .handle(
                        ApplySoloTxn {
                            txn,
                            txn_info,
                            version,
                            events,
                        },
                        _ctx,
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

impl Channel {
    async fn solo_action(
        &mut self,
        ctx: &mut ActorHandlerContext,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<()> {
        let _ = self
            .handle(
                Execute {
                    channel_op: channel_op.clone(),
                    args: args.clone(),
                },
                ctx,
            )
            .await?;

        let (sender, seq_number) = self
            .handle(ApplyPendingTxn, ctx)
            .await?
            .ok_or(format_err!("expect solo channel txn not applying"))?;
        let TransactionWithProof {
            version,
            transaction,
            events,
            proof,
        } = watch_transaction(self.chain_client.clone(), sender, seq_number).await?;
        let mut actor_ref = self.actor_ref(ctx).await;
        tokio::task::spawn(async move {
            let result = actor_ref
                .send(ApplySoloTxn {
                    txn: transaction,
                    txn_info: proof.transaction_info().clone(),
                    events: events.unwrap_or_default(),
                    version,
                })
                .await
                .map_err(|_| format_err!("channel actor gone"))
                .and_then(|r| r);
            if let Err(e) = result {
                error!(
                    "fail to apply solo txn, {}, {:?}, error: {:?}",
                    &channel_op, &args, e
                );
            }
        });
        Ok(())
    }

    fn apply_travel(
        &mut self,
        version: u64,
        signed_txn: SignedTransaction,
        txn_info: TransactionInfo,
        events: Vec<ContractEvent>,
    ) -> Result<()> {
        let txn_to_commit = ChannelTransactionToCommit {
            signed_channel_txn: AppliedChannelTxn::Travel(signed_txn),
            events,
            major_status: txn_info.major_status(),
            write_set: WriteSet::default(),
            gas_used: txn_info.gas_used(),
        };
        let channel_address_state = self
            .chain_client
            .get_account_state(self.channel_address().clone(), Some(version))?;
        // NOTICE: apply after we fetch channel state
        self.tx_applier.apply(txn_to_commit)?;

        // update stm
        self.stm.advance_state(
            Some(ChannelState::new(
                self.channel_address().clone(),
                channel_address_state,
            )),
            self.store.get_latest_witness().unwrap_or_default(),
            self.store.get_participant_keys(),
        );
        Ok(())
    }

    /// apply data into local channel storage
    fn apply(
        &mut self,
        channel_txn: ChannelTransaction,
        txn_output: TransactionOutput,
        signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Result<()> {
        let txn_to_commit = ChannelTransactionToCommit {
            signed_channel_txn: AppliedChannelTxn::Offchain(SignedChannelTransaction::new(
                channel_txn,
                signatures,
            )),
            events: txn_output.events().to_vec(),
            major_status: txn_output.status().vm_status().major_status,
            write_set: txn_output.write_set().clone(),
            gas_used: txn_output.gas_used(),
        };

        // apply txn  also delete pending txn from db
        self.tx_applier.apply(txn_to_commit)?;

        // update stm
        self.stm.advance_state(
            None,
            self.store.get_latest_witness().unwrap_or_default(),
            self.store.get_participant_keys(),
        );
        Ok(())
    }

    fn pending_txn(&self) -> Option<PendingTransaction> {
        self.store.get_pending_txn()
    }

    fn check_applied(
        &self,
        channel_sequence_number: u64,
    ) -> Result<Option<SignedChannelTransactionWithProof>> {
        if let Some(info) = self.store.get_startup_info()? {
            if channel_sequence_number > info.latest_version {
                Ok(None)
            } else {
                let signed_channel_txn_with_proof = self
                    .store
                    .get_transaction_by_channel_seq_number(channel_sequence_number, false)?;
                debug_assert_eq!(
                    signed_channel_txn_with_proof.version,
                    channel_sequence_number
                );
                Ok(Some(signed_channel_txn_with_proof))
            }
        } else {
            Ok(None)
        }
    }

    fn save_pending_txn(&mut self, pending_txn: PendingTransaction) -> Result<()> {
        if let Some(cur) = self.store.get_pending_txn() {
            // already in storage
            if &cur == &pending_txn {
                return Ok(());
            } else if cur.newer_than(&pending_txn) {
                bail!("cannot save pending txn, state invalid");
            }
        }

        // always persist pending txn
        self.store.save_pending_txn(pending_txn, true)?;
        Ok(())
    }

    /// helper method to get self actor ref from `ctx`
    async fn actor_ref(&self, ctx: &mut ActorHandlerContext) -> ActorRef<Self> {
        let self_id = ctx.actor_id().clone();
        let self_ref = ctx
            .actor_context_mut()
            .get_actor::<Self>(self_id)
            .await
            .expect("get self actor ref should be ok");
        self_ref
    }
    async fn watch_channel_lock_timeout(&self, ctx: &mut ActorHandlerContext) -> Result<()> {
        let lock_by = self
            .stm
            .channel_lock_by_resource()
            .expect("expect lock_by resource exists");

        let time_lock = lock_by.time_lock;

        let mut timeout_receiver = self
            .chain_txn_watcher
            .add_interest(Box::new(move |txn| txn.block_height > time_lock))
            .await?;
        let mut self_ref = self.actor_ref(ctx).await;

        tokio::task::spawn(async move {
            while let Some(txn_info) = timeout_receiver.next().await {
                match self_ref
                    .send(ChannelLockTimeout {
                        block_height: txn_info.block_height,
                        time_lock,
                    })
                    .await
                {
                    Err(_) => break,
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) => {
                        error!(
                            "actor fail to handle channel lock timeout, continue watch, err: {}",
                            e
                        );
                    }
                }
            }
        });

        Ok(())
    }

    /// clear local pending state
    fn clear_pending_txn(&self) -> Result<()> {
        self.store.clear_pending_txn()
    }
}

pub fn is_participant_channel_resource_modified(
    old_write_set: &WriteSet,
    new_write_set: &WriteSet,
    participant: &AccountAddress,
) -> bool {
    let prev_write_set = old_write_set
        .iter()
        .map(|p| (&p.0, &p.1))
        .collect::<BTreeMap<_, _>>();
    for (ap, op) in new_write_set {
        let contain_participant_data = ap
            .data_path()
            .and_then(|data_path| data_path.participant())
            .filter(|account| account == participant)
            .is_some();
        let modified_in_this_epoch = !prev_write_set
            .get(ap)
            .filter(|old_op| **old_op == op)
            .is_some();
        if contain_participant_data && modified_in_this_epoch {
            return true;
        }
    }
    return false;
}
