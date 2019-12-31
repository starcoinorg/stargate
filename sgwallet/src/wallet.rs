// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::{
    chain_watcher::{ChainWatcher, ChainWatcherHandle},
    channel::{
        ApplyCoSignedTxn, ApplyPendingTxn, ApplySoloTxn, CancelPendingTxn, Channel, ChannelEvent,
        ChannelHandle, CollectProposalWithSigs, Execute, ForceTravel, GrantProposal,
    },
    scripts::*,
};
use anyhow::{bail, ensure, format_err, Error, Result};
use chrono::Utc;
use coerce_rt::actor::context::ActorContext;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use lazy_static::lazy_static;
use libra_config::config::VMConfig;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue,
};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::{
    access_path::DataPath,
    account_address::AccountAddress,
    account_config::{coin_struct_tag, AccountResource},
    byte_array::ByteArray,
    channel::{
        channel_mirror_struct_tag, channel_struct_tag, user_channels_struct_tag,
        ChannelMirrorResource, ChannelParticipantAccountResource, ChannelResource,
        UserChannelsResource,
    },
    language_storage::StructTag,
    libra_resource::{make_resource, LibraResource},
    transaction::{
        helpers::{create_signed_payload_txn, TransactionSigner},
        Module, RawTransaction, SignedTransaction, Transaction, TransactionArgument,
        TransactionOutput, TransactionPayload, TransactionStatus, TransactionWithProof,
    },
    vm_error::*,
};
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use sgconfig::config::WalletConfig;
use sgstorage::{channel_db::ChannelDB, channel_store::ChannelStore, storage::SgStorage};
use sgtypes::{
    account_resource_ext,
    account_state::AccountState,
    applied_channel_txn::AppliedChannelTxn,
    channel::ChannelState,
    channel_transaction::{
        ChannelOp, ChannelTransactionProposal, ChannelTransactionRequest,
        ChannelTransactionResponse,
    },
    pending_txn::PendingTransaction,
    script_package::{ChannelScriptPackage, ScriptCode},
    sg_error::SgError,
    signed_channel_transaction::SignedChannelTransaction,
};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::runtime;
use vm_runtime::{MoveVM, VMExecutor};

lazy_static! {
    pub static ref DEFAULT_ASSET: StructTag = coin_struct_tag();
    static ref VM_CONFIG: VMConfig = VMConfig::offchain();
}

// const RETRY_INTERVAL: u64 = 1000;
const TXN_EXPIRATION: Duration = Duration::from_secs(24 * 60 * 60);
pub(crate) const MAX_GAS_AMOUNT_OFFCHAIN: u64 = std::u64::MAX;
pub(crate) const MAX_GAS_AMOUNT_ONCHAIN: u64 = 1_000_000;
pub(crate) const GAS_UNIT_PRICE: u64 = 1;

pub struct Wallet {
    mailbox_sender: mpsc::Sender<WalletCmd>,
    shared: Shared,
    sgdb: Arc<SgStorage>,
    inner: Option<Inner>,
}

impl Wallet {
    pub fn new(
        account: AccountAddress,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        rpc_host: &str,
        rpc_port: u32,
    ) -> Result<Self> {
        let chain_client = StarChainClient::new(rpc_host, rpc_port as u32);
        let client = Arc::new(chain_client);
        Self::new_with_client(account, keypair, client, WalletConfig::default().store_dir)
    }

    pub fn new_with_client<P: AsRef<Path>>(
        account: AccountAddress,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        client: Arc<dyn ChainClient>,
        store_dir: P,
    ) -> Result<Self> {
        let (mail_sender, mailbox) = mpsc::channel(1000);
        let sgdb = Arc::new(SgStorage::new(account, store_dir));

        let script_registry = Arc::new(PackageRegistry::build()?);

        let shared = Shared {
            account,
            keypair,
            client,
            script_registry,
        };
        let (channel_event_sender, channel_event_receiver) = mpsc::channel(128);
        let inner = Inner {
            inner: shared.clone(),
            channel_enabled: false,
            channels: HashMap::new(),
            sgdb: sgdb.clone(),
            chain_txn_handle: None,
            mailbox,
            channel_event_sender,
            channel_event_receiver,
            should_stop: false,
            actor_context: None,
        };
        let wallet = Wallet {
            mailbox_sender: mail_sender.clone(),
            shared,
            sgdb: sgdb.clone(),
            inner: Some(inner),
            //            _rt: runtime,
        };
        Ok(wallet)
    }
    pub fn start(&mut self, executor: &runtime::Handle) -> Result<()> {
        let inner = self.inner.take().expect("wallet already started");
        executor.spawn(inner.start());
        Ok(())
    }

    pub fn get_txn_by_channel_sequence_number(
        &self,
        participant_address: AccountAddress,
        channel_seq_number: u64,
    ) -> Result<SignedChannelTransaction> {
        let txn = self
            .get_applied_txn_by_channel_sequence_number(participant_address, channel_seq_number)?;
        match txn {
            AppliedChannelTxn::Offchain(t) => Ok(t),
            _ => bail!("txn at {} is a travel txn", channel_seq_number),
        }
    }

    pub fn get_applied_txn_by_channel_sequence_number(
        &self,
        participant_address: AccountAddress,
        channel_seq_number: u64,
    ) -> Result<AppliedChannelTxn> {
        let (channel_address, ps) = generate_channel_address(self.account(), participant_address);
        let channel_db = ChannelDB::new(channel_address, self.sgdb.clone());
        let txn = ChannelStore::new(ps, channel_db)?
            .get_transaction_by_channel_seq_number(channel_seq_number, false)?;
        Ok(txn.signed_transaction)
    }

    pub fn account(&self) -> AccountAddress {
        self.shared.account
    }

    pub fn client(&self) -> &dyn ChainClient {
        self.shared.client.as_ref()
    }

    pub fn get_chain_client(&self) -> Arc<dyn ChainClient> {
        self.shared.client.clone()
    }

    /// TODO: use async version of cient
    pub fn account_resource(&self) -> Result<AccountResource> {
        // account_resource must exist.
        //TODO handle unwrap
        let account_state = self
            .shared
            .client
            .get_account_state(self.shared.account, None)?;
        let account_resource_bytes = account_state
            .get(&DataPath::account_resource_data_path().to_vec())
            .unwrap();
        account_resource_ext::from_bytes(&account_resource_bytes)
    }
    pub fn sequence_number(&self) -> Result<u64> {
        Ok(self.account_resource()?.sequence_number())
    }
    //TODO support more asset type
    pub fn balance(&self) -> Result<u64> {
        Ok(self.account_resource()?.balance())
    }
}

impl Wallet {
    /// enable channel for this wallet, return gas_used
    pub async fn enable_channel(&self) -> Result<u64> {
        let (tx, rx) = oneshot::channel();

        let resp = self
            .call(WalletCmd::EnableChannel { responder: tx }, rx)
            .await??;
        Ok(resp)
    }

    pub async fn is_channel_feature_enabled(&self) -> Result<bool> {
        let (tx, rx) = oneshot::channel();

        let resp = self
            .call(WalletCmd::IsChannelFeatureEnabled { responder: tx }, rx)
            .await??;
        Ok(resp)
    }

    pub async fn channel_sequence_number(&self, participant: AccountAddress) -> Result<u64> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);
        let channel = self.get_channel(generated_channel_address).await?;

        let struct_tag = channel_mirror_struct_tag();
        // channel mirror resource is a shared resource
        let data_path = DataPath::channel_resource_path(generated_channel_address, struct_tag);
        let mirror = channel
            .get_channel_resource::<ChannelMirrorResource>(data_path)
            .await?;

        Ok(mirror.map(|r| r.channel_sequence_number()).unwrap_or(0))
    }

    pub async fn participant_channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self
            .channel_participant_account_resource(participant, participant)
            .await?
            .map(|account| account.balance())
            .unwrap_or(0))
    }

    pub async fn channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self
            .channel_participant_account_resource(participant, self.shared.account)
            .await?
            .map(|account| account.balance())
            .unwrap_or(0))
    }

    pub async fn channel_handle(&self, participant: AccountAddress) -> Result<Arc<ChannelHandle>> {
        let (channel_address, _) = generate_channel_address(participant, self.shared.account);
        let handle = self.get_channel(channel_address).await?;
        Ok(handle)
    }

    /// Open channel and deposit default asset.
    pub async fn open(
        &self,
        participant: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.open receiver:{}, sender_amount:{}, receiver_amount:{}",
            participant, sender_amount, receiver_amount
        );

        self.execute_async(
            participant,
            ChannelOp::Open,
            vec![
                TransactionArgument::Address(participant),
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
            ],
        )
        .await
    }

    pub async fn deposit(
        &self,
        receiver: AccountAddress,
        amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!("wallet.deposit receiver:{}, amount:{}", receiver, amount);

        self.execute_async(
            receiver,
            ChannelOp::Action {
                module_address: AccountAddress::default(),
                module_name: "ChannelScript".to_string(), // FIXME:change to ChannelScript
                function_name: "deposit".to_string(),
            },
            vec![TransactionArgument::U64(amount)],
        )
        .await
    }

    /// send payment to `participant`
    /// who use his `preimage` hashed in `hash_lock` to retrieve the money
    /// within the `timeout` duration of blocks from now.
    pub async fn send_payment(
        &self,
        participant: AccountAddress,
        amount: u64,
        hash_lock: Vec<u8>,
        timeout: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.send_payment receiver: {}, amount: {}, hash_lock: {:?}",
            &participant, amount, &hash_lock
        );
        self.execute_async(
            participant,
            ChannelOp::Action {
                module_address: AccountAddress::default(),
                module_name: "ChannelScript".to_string(),
                function_name: "send_payment".to_string(),
            },
            vec![
                TransactionArgument::Address(participant),
                TransactionArgument::U64(amount),
                TransactionArgument::ByteArray(ByteArray::new(hash_lock)),
                TransactionArgument::U64(timeout),
            ],
        )
        .await
    }

    pub async fn receive_payment(
        &self,
        participant: AccountAddress,
        preimage: Vec<u8>,
    ) -> Result<ChannelTransactionRequest> {
        info!("wallet.receive_payment participant: {}", &participant);
        self.execute_async(
            participant,
            ChannelOp::Action {
                module_address: AccountAddress::default(),
                module_name: "ChannelScript".to_string(),
                function_name: "receive_payment".to_string(),
            },
            vec![TransactionArgument::ByteArray(ByteArray::new(preimage))],
        )
        .await
    }
    /// sender can recall payment if the payment is timeouted
    pub async fn recall_timeout_payment(
        &self,
        participant: AccountAddress,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.recall_timeout_payment participant: {}",
            &participant
        );
        self.execute_async(
            participant,
            ChannelOp::Action {
                module_address: AccountAddress::default(),
                module_name: "ChannelScript".to_string(),
                function_name: "cancel_payment_after_timeout".to_string(),
            },
            vec![],
        )
        .await
    }

    pub async fn transfer(
        &self,
        receiver: AccountAddress,
        amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!("wallet.transfer receiver:{}, amount:{}", receiver, amount);

        self.execute_async(
            receiver,
            ChannelOp::Action {
                module_address: AccountAddress::default(),
                module_name: "ChannelScript".to_string(), // FIXME:change to ChannelScript
                function_name: "transfer".to_string(),
            },
            vec![
                TransactionArgument::Address(receiver),
                TransactionArgument::U64(amount),
            ],
        )
        .await
    }

    pub async fn withdraw(
        &self,
        receiver: AccountAddress,
        amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!("wallet.withdraw receiver:{}, amount: {}", receiver, amount);

        self.execute_async(
            receiver,
            ChannelOp::Action {
                module_address: AccountAddress::default(),
                module_name: "ChannelScript".to_string(), // FIXME:change to ChannelScript
                function_name: "withdraw".to_string(),
            },
            vec![TransactionArgument::U64(amount)],
        )
        .await
    }

    pub async fn close(&mut self, receiver: AccountAddress) -> Result<ChannelTransactionRequest> {
        self.execute_async(receiver, ChannelOp::Close, vec![]).await
    }

    pub async fn execute_script(
        &self,
        receiver: AccountAddress,
        package_name: &str,
        script_name: &str,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.execute_script receiver:{}, package_name:{}, script_name:{}, args:{:?}",
            receiver, package_name, script_name, args
        );
        self.execute_async(
            receiver,
            ChannelOp::Execute {
                package_name: package_name.to_string(),
                script_name: script_name.to_string(),
            },
            args,
        )
        .await
    }

    async fn execute_async(
        &self,
        participant: AccountAddress,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        let (channel_address, participants) =
            generate_channel_address(participant, self.shared.account);
        let channel = if channel_op.is_open() {
            self.spawn_new_channel(channel_address, participants)
                .await?
        } else {
            self.get_channel(channel_address).await?
        };

        let (proposal, sigs, output) = channel
            .channel_ref()
            .send(Execute { channel_op, args })
            .await??;
        let request = ChannelTransactionRequest::new(proposal, sigs, output.is_travel_txn());
        Ok(request)
    }

    /// Receiver verify txn.
    /// If return None, it means the txn needs to be approved by user.
    pub async fn verify_txn(
        &self,
        participant: AccountAddress,
        txn_request: &ChannelTransactionRequest,
    ) -> Result<Option<ChannelTransactionResponse>> {
        let request_id = txn_request.request_id();

        let channel_txn = txn_request.channel_txn();

        debug!("verify_txn id:{}", request_id);
        ensure!(
            participant == channel_txn.proposer(),
            "peer id and txn proposer mismatch"
        );

        let (generated_channel_address, participants) =
            generate_channel_address(channel_txn.proposer(), self.shared.account);
        ensure!(
            generated_channel_address == channel_txn.channel_address(),
            "invalid channel address in txn"
        );

        let channel = if channel_txn.operator().is_open() {
            self.spawn_new_channel(generated_channel_address, participants)
                .await?
        } else {
            self.get_channel(generated_channel_address).await?
        };

        let (proposal, sigs, _) = txn_request.clone().into();

        let sig_opt = channel
            .channel_ref()
            .send(CollectProposalWithSigs {
                proposal: proposal.clone(),
                sigs,
            })
            .await??;

        Ok(sig_opt.map(|s| ChannelTransactionResponse::new(proposal, s)))
    }

    pub async fn approve_txn(
        &self,
        participant: AccountAddress,
        request_id: HashValue,
    ) -> Result<ChannelTransactionResponse> {
        let resp = self
            .grant_txn_request(participant, request_id, true)
            .await?;
        debug_assert!(
            resp.is_some(),
            "invalid state of channel, should return signatures"
        );
        Ok(resp.unwrap())
    }

    pub async fn reject_txn(
        &self,
        participant: AccountAddress,
        request_id: HashValue,
    ) -> Result<()> {
        let resp = self
            .grant_txn_request(participant, request_id, false)
            .await?;
        debug_assert!(
            resp.is_none(),
            "invalid state of channel, should not return signatures"
        );
        Ok(())
    }
    async fn grant_txn_request(
        &self,
        participant: AccountAddress,
        request_id: HashValue,
        grant: bool,
    ) -> Result<Option<ChannelTransactionResponse>> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);
        let channel = self.get_channel(generated_channel_address).await?;
        let pending_txn = channel.get_pending_txn().await?;
        let proposal: ChannelTransactionProposal = match pending_txn {
            Some(r) => {
                let (p, _, _) = r.into();
                p
            }
            None => bail!("no pending txn to grant"),
        };

        let resp = channel
            .channel_ref()
            .send(GrantProposal {
                channel_txn_id: request_id,
                grant,
            })
            .await??;

        Ok(resp.map(|s| ChannelTransactionResponse::new(proposal, s)))
    }

    /// After receiver reject the txn, sender should cancel his local pending txn to cleanup state.
    pub async fn cancel_pending_request(
        &self,
        participant: AccountAddress,
        request_id: HashValue,
    ) -> Result<()> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);

        let channel = self.get_channel(generated_channel_address).await?;

        let _resp = channel
            .channel_ref()
            .send(CancelPendingTxn {
                channel_txn_id: request_id,
            })
            .await??;

        Ok(())
    }

    pub async fn verify_txn_response(
        &self,
        participant: AccountAddress,
        txn_response: &ChannelTransactionResponse,
    ) -> Result<()> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);

        let channel = self.get_channel(generated_channel_address).await?;

        let (proposal, sigs) = txn_response.clone().into();
        let _ = channel
            .channel_ref()
            .send(CollectProposalWithSigs { proposal, sigs })
            .await??;
        Ok(())
    }

    pub async fn force_travel_txn(&self, participant: AccountAddress) -> Result<u64> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);

        let channel = self.get_channel(generated_channel_address).await?;
        let (txn_sender, seq_number) = channel.channel_ref().send(ForceTravel).await??;

        let TransactionWithProof {
            version,
            transaction,
            events,
            proof,
        } = watch_transaction(self.shared.client.clone(), txn_sender, seq_number).await?;
        let gas = channel
            .channel_ref()
            .send(ApplySoloTxn {
                version,
                txn: transaction,
                txn_info: proof.transaction_info().clone(),
                events: events.unwrap_or_default(),
            })
            .await
            .map_err(|_| format_err!("channel actor gone"))
            .and_then(|r| r)?;
        Ok(gas)
    }

    pub async fn apply_txn(
        &self,
        participant: AccountAddress,
        txn_response: &ChannelTransactionResponse,
    ) -> Result<u64> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);

        let channel = self.get_channel(generated_channel_address).await?;

        let (proposal, _) = txn_response.clone().into();

        let option_watch = channel
            .channel_ref()
            .send(ApplyPendingTxn { proposal })
            .await??;
        if option_watch.is_none() {
            return Ok(0);
        }
        let (txn_sender, seq_number) = option_watch.unwrap();

        let TransactionWithProof {
            version,
            transaction,
            events,
            proof,
        } = watch_transaction(self.shared.client.clone(), txn_sender, seq_number).await?;

        let gas = channel
            .channel_ref()
            .send(ApplyCoSignedTxn {
                version,
                txn: transaction,
                txn_info: proof.transaction_info().clone(),
                events: events.unwrap_or_default(),
            })
            .await
            .map_err(|_| format_err!("channel actor gone"))
            .and_then(|r| r)?;

        Ok(gas)
    }

    /// Called by receiver to get proposal waiting user approval.
    pub async fn get_waiting_proposal(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelTransactionProposal>> {
        let pending_txn = self.get_pending_txn(participant).await?;
        let proposal = pending_txn.and_then(|pending| {
            if pending.is_negotiating() {
                let (proposal, _, signatures) = pending.into();
                if !signatures.contains_key(&self.shared.account)
                    && proposal.channel_txn.proposer() != self.shared.account
                {
                    Some(proposal)
                } else {
                    None
                }
            } else {
                None
            }
        });
        Ok(proposal)
    }

    /// Get pending txn request.
    pub async fn get_pending_txn_request(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelTransactionRequest>> {
        let pending_txn = self.get_pending_txn(participant).await?;
        let request = pending_txn.and_then(|pending| {
            if pending.is_negotiating() {
                let (proposal, output, mut signatures) = pending.into();
                let proposer_sigs = signatures.remove(&proposal.channel_txn.proposer());
                if proposal.channel_txn.proposer() == self.shared.account {
                    debug_assert!(proposer_sigs.is_some());
                }

                Some(ChannelTransactionRequest::new(
                    proposal.clone(),
                    proposer_sigs.unwrap(),
                    output.is_travel_txn(),
                ))
            } else {
                None
            }
        });
        Ok(request)
    }

    async fn get_pending_txn(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<PendingTransaction>> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);
        let channel = self.get_channel(generated_channel_address).await?;
        channel.get_pending_txn().await
    }

    pub async fn install_package(&self, package: ChannelScriptPackage) -> Result<()> {
        self.shared.script_registry.install_package(package)?;
        Ok(())
    }
    pub async fn deploy_module(&self, module_byte_code: Vec<u8>) -> Result<TransactionWithProof> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::DeployModule {
            module_byte_code,
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp
    }
    pub async fn get_script(
        &self,
        package_name: String,
        script_name: String,
    ) -> Result<Option<ScriptCode>> {
        let resp = self
            .shared
            .script_registry
            .get_script(&package_name, &script_name);
        Ok(resp)
    }

    pub async fn get_all_channels(&self) -> Result<HashSet<AccountAddress>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GetAllChannels { responder: tx };

        let resp = self.call(cmd, rx).await?;
        resp
    }

    async fn spawn_new_channel(
        &self,
        channel_address: AccountAddress,
        participants: BTreeSet<AccountAddress>,
    ) -> Result<Arc<ChannelHandle>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::SpawnNewChannel {
            channel_address,
            participants,
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp
    }
    async fn get_channel(&self, channel_address: AccountAddress) -> Result<Arc<ChannelHandle>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GetChannel {
            channel_address,
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp
    }
    async fn channel_participant_account_resource(
        &self,
        participant: AccountAddress,
        address: AccountAddress,
    ) -> Result<Option<ChannelParticipantAccountResource>> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.shared.account);
        let channel = self.get_channel(generated_channel_address).await?;

        let data_path = DataPath::channel_resource_path(
            address,
            ChannelParticipantAccountResource::struct_tag(),
        );
        let resp = channel
            .get_channel_resource::<ChannelParticipantAccountResource>(data_path)
            .await?;

        Ok(resp)
    }

    pub async fn stop(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        // make stop idempotent
        if let Err(_e) = self
            .mailbox_sender
            .clone()
            .send(WalletCmd::Stop { responder: tx })
            .await
        {
            warn!("wallet mailbox is already closed");
            Ok(())
        } else {
            match rx.await {
                Ok(result) => Ok(result?),
                Err(_) => bail!("sender dropped"),
            }
        }
    }

    async fn call<T>(&self, cmd: WalletCmd, rx: oneshot::Receiver<T>) -> Result<T> {
        if let Err(_e) = self.mailbox_sender.clone().try_send(cmd) {
            bail!("wallet mailbox is full or close");
        }
        match rx.await {
            Ok(result) => Ok(result),
            Err(_) => bail!("sender dropped"),
        }
    }
}

#[derive(Debug)]
pub enum WalletCmd {
    IsChannelFeatureEnabled {
        responder: oneshot::Sender<Result<bool>>,
    },
    EnableChannel {
        responder: oneshot::Sender<Result<u64>>,
    },
    SpawnNewChannel {
        channel_address: AccountAddress,
        participants: BTreeSet<AccountAddress>,
        responder: oneshot::Sender<Result<Arc<ChannelHandle>>>,
    },
    GetChannel {
        channel_address: AccountAddress,
        responder: oneshot::Sender<Result<Arc<ChannelHandle>>>,
    },
    GetAllChannels {
        responder: oneshot::Sender<Result<HashSet<AccountAddress>>>,
    },
    DeployModule {
        module_byte_code: Vec<u8>,
        responder: oneshot::Sender<Result<TransactionWithProof>>,
    },
    StopChannel {
        participant: AccountAddress,
        responder: oneshot::Sender<Result<()>>,
    },
    Stop {
        responder: oneshot::Sender<Result<()>>,
    },
}

pub struct Inner {
    inner: Shared,
    channel_enabled: bool,
    channels: HashMap<AccountAddress, Arc<ChannelHandle>>,
    sgdb: Arc<SgStorage>,
    //    rt_handle: runtime::Handle,
    chain_txn_handle: Option<ChainWatcherHandle>,
    mailbox: mpsc::Receiver<WalletCmd>,
    channel_event_receiver: mpsc::Receiver<ChannelEvent>,
    channel_event_sender: mpsc::Sender<ChannelEvent>,
    should_stop: bool,
    actor_context: Option<ActorContext>,
}

impl Inner {
    async fn start(mut self) {
        let actor_context = ActorContext::new();
        self.actor_context = Some(actor_context.clone());

        let account_state = self
            .inner
            .client
            .get_account_state(self.inner.account, None);
        if let Err(e) = account_state {
            error!("fail to get account state from chain, e: {}", e);
            return ();
        }
        let account_state = account_state.unwrap();

        // start chain txn watcher
        // TODO: what version should we start to watch on.
        let chain_txn_watcher =
            ChainWatcher::new(self.inner.client.clone(), account_state.version(), 16);
        let chain_txn_handle = chain_txn_watcher
            .start(actor_context)
            .await
            .expect("start chain watcher should ok");
        self.chain_txn_handle = Some(chain_txn_handle);

        if let Some(blob) =
            account_state.get_state(&DataPath::onchain_resource_path(user_channels_struct_tag()))
        {
            self.channel_enabled = true;
            let user_channels: UserChannelsResource =
                make_resource(blob.as_slice()).expect("parse user channels should work");
            if let Err(e) = self
                .refresh_channels(user_channels, account_state.version())
                .await
            {
                error!("fail to start all channels, err: {:?}", e);
                return ();
            }
        } else {
            self.channel_enabled = false;
            warn!("channel feature is not enabled for this wallet account");
        }

        loop {
            ::futures::select! {
               maybe_external_cmd = self.mailbox.next() => {
                   if let Some(cmd) = maybe_external_cmd {
                       self.handle_external_cmd(cmd).await;
                   }
               }
               channel_event = self.channel_event_receiver.next() => {
                   if let Some(event) = channel_event {
                       self.handle_channel_event(event).await;
                   }
               }
               complete => {
                   break;
               }
            }
            if self.should_stop {
                break;
            }
        }
        if let Some(h) = self.chain_txn_handle.take() {
            h.stop().await;
        }
        crit!("wallet {} task stopped", self.inner.account);
    }

    async fn handle_channel_event(&mut self, event: ChannelEvent) {
        match event {
            ChannelEvent::Stopped { channel_address } => {
                self.channels.remove(&channel_address);
            }
        }
    }

    async fn handle_external_cmd(&mut self, cmd: WalletCmd) {
        match cmd {
            WalletCmd::IsChannelFeatureEnabled { responder } => {
                respond_with(responder, Ok(self.channel_enabled));
            }
            WalletCmd::EnableChannel { responder } => {
                respond_with(responder, self.enable_channel().await);
            }
            WalletCmd::SpawnNewChannel {
                channel_address,
                participants,
                responder,
            } => {
                self.spawn_channel(channel_address, participants, AccountState::new())
                    .await;
                let channel = self.get_channel(&channel_address);
                respond_with(responder, channel);
            }
            WalletCmd::GetChannel {
                channel_address,
                responder,
            } => {
                let channel = self.get_channel(&channel_address);
                respond_with(responder, channel);
            }
            WalletCmd::DeployModule {
                module_byte_code,
                responder,
            } => {
                let response = self.deploy_module(module_byte_code).await;
                respond_with(responder, response);
            }
            WalletCmd::GetAllChannels { responder } => {
                let all_channels = self
                    .channels
                    .values()
                    .map(|c| {
                        let mut participants = c
                            .participant_addresses()
                            .iter()
                            .map(Clone::clone)
                            .collect::<Vec<_>>();
                        participants.retain(|e| e != c.account_address());
                        debug_assert_eq!(1, participants.len());
                        participants[0]
                    })
                    .collect::<HashSet<_>>();
                respond_with(responder, Ok(all_channels));
            }
            WalletCmd::StopChannel {
                responder,
                participant,
            } => {
                let (generated_channel_address, _participants) =
                    generate_channel_address(participant, self.inner.account);
                self.channels.remove(&generated_channel_address);
                respond_with(responder, Ok(()));
            }
            WalletCmd::Stop { responder } => {
                for (a, c) in self.channels.iter() {
                    if let Err(e) = c.stop().await {
                        error!("stop channel {} error: {}", a, e);
                    }
                }
                self.channels.clear();
                self.should_stop = true;
                respond_with(responder, Ok(()));
            }
        }
    }

    async fn refresh_channels(
        &mut self,
        user_channels: UserChannelsResource,
        version: u64,
    ) -> Result<()> {
        let mut channel_states = HashMap::new();
        for channel_address in user_channels.channels().iter() {
            let channel_account_state = self
                .inner
                .client
                .get_account_state(channel_address.clone(), Some(version))?;

            let channel_resource_blob = channel_account_state
                .get_state(&DataPath::onchain_resource_path(channel_struct_tag()))
                .expect(
                    format!(
                        "Channel resource should exists in channel {}",
                        channel_address
                    )
                    .as_str(),
                );
            let channel_resource = ChannelResource::make_from(channel_resource_blob).unwrap();
            let participants = channel_resource
                .participants()
                .iter()
                .map(Clone::clone)
                .collect::<BTreeSet<_>>();

            channel_states.insert(
                channel_address.clone(),
                (participants, channel_account_state),
            );
        }
        for (channel_address, (participants, channel_state)) in channel_states.into_iter() {
            self.spawn_channel(channel_address, participants, channel_state)
                .await;
        }
        Ok(())
    }

    fn get_channel(&self, participant: &AccountAddress) -> Result<Arc<ChannelHandle>> {
        let channel = match self.channels.get(&participant) {
            Some(channel) => Ok(channel.clone()),
            None => {
                let e: Error = SgError::new_channel_not_exist_error(&participant).into();
                Err(e)
            }
        };
        channel
    }

    async fn enable_channel(&mut self) -> Result<u64> {
        ensure!(!self.channel_enabled, "channel feature is already enabled");
        let seq_number = self.sequence_number()?;
        let raw_txn = RawTransaction::new_script(
            self.inner.account,
            seq_number,
            encode_enable_channel_script(),
            1000_000 as u64,
            1,
            Duration::from_secs(u64::max_value()),
        );
        let signed_txn = raw_txn
            .sign(
                &self.inner.keypair.private_key,
                self.inner.keypair.public_key.clone(),
            )?
            .into_inner();
        let _ = submit_transaction(self.inner.client.as_ref(), signed_txn).await?;
        let proof =
            watch_transaction(self.inner.client.clone(), self.inner.account, seq_number).await?;
        self.channel_enabled = true;
        Ok(proof.proof.transaction_info().gas_used())
    }

    /// Deploy a module to Chain
    async fn deploy_module(&self, module_byte_code: Vec<u8>) -> Result<TransactionWithProof> {
        let payload = TransactionPayload::Module(Module::new(module_byte_code));
        //TODO pre execute deploy module txn on local , and get real gas used to set max_gas_amount.
        let txn = create_signed_payload_txn(
            self.inner.keypair.as_ref(),
            payload,
            self.inner.account,
            self.sequence_number()?,
            MAX_GAS_AMOUNT_ONCHAIN,
            GAS_UNIT_PRICE,
            TXN_EXPIRATION.as_secs() as i64,
        )?;
        //TODO need execute at local vm for check?
        let address = txn.sender();
        let seq_number = txn.sequence_number();
        submit_transaction(self.inner.client.as_ref(), txn).await?;
        watch_transaction(self.inner.client.clone(), address, seq_number).await
    }

    /// TODO: use async version of cient
    /// this will block executor's thread
    fn account_resource(&self) -> Result<AccountResource> {
        // account_resource must exist.
        //TODO handle unwrap
        let account_state = self
            .inner
            .client
            .get_account_state(self.inner.account, None)?;
        let account_resource_bytes = account_state
            .get(&DataPath::account_resource_data_path().to_vec())
            .unwrap();
        account_resource_ext::from_bytes(&account_resource_bytes)
    }
    fn sequence_number(&self) -> Result<u64> {
        Ok(self.account_resource()?.sequence_number())
    }

    #[allow(dead_code)]
    fn exist_channel(&self, channel_address: &AccountAddress) -> bool {
        self.channels.contains_key(channel_address)
    }

    async fn spawn_channel(
        &mut self,
        channel_address: AccountAddress,
        participants: BTreeSet<AccountAddress>,
        channel_account_state: AccountState,
    ) {
        let channel = Channel::load(
            channel_address,
            self.inner.account,
            participants,
            ChannelState::new(channel_address, channel_account_state),
            self.get_channel_db(channel_address),
            self.chain_txn_handle.as_ref().unwrap().clone(),
            self.channel_event_sender.clone(),
            self.inner.keypair.clone(),
            self.inner.script_registry.clone(),
            self.inner.client.clone(),
        );

        let channel_handle = channel
            .start(self.actor_context.as_ref().unwrap().clone())
            .await;

        // TODO: should wait signal of channel saying it's started
        self.channels
            .insert(channel_address, Arc::new(channel_handle));
        info!("Init new channel {:?}", channel_address);
    }

    #[inline]
    fn get_channel_db(&self, participant_address: AccountAddress) -> ChannelDB {
        ChannelDB::new(participant_address, self.sgdb.clone())
    }
}

impl TransactionSigner for Wallet {
    fn sign_txn(&self, raw_txn: RawTransaction) -> Result<SignedTransaction> {
        self.shared.keypair.sign_txn(raw_txn)
    }
}

pub struct Shared {
    account: AccountAddress,
    keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    client: Arc<dyn ChainClient>,
    script_registry: Arc<PackageRegistry>,
}

// NOTICE: need to manually implement clone, due to https://github.com/rust-lang/rust/issues/26925
impl Clone for Shared {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            keypair: Arc::clone(&self.keypair),
            client: Arc::clone(&self.client),
            script_registry: Arc::clone(&self.script_registry),
        }
    }
}

pub(crate) fn txn_expiration() -> Duration {
    std::time::Duration::new(
        (Utc::now().timestamp() + TXN_EXPIRATION.as_secs() as i64) as u64,
        0,
    )
}

pub(crate) fn execute_transaction(
    state_view: &dyn StateView,
    transaction: SignedTransaction,
) -> Result<TransactionOutput> {
    let tx_hash = transaction.raw_txn().hash();
    let output = MoveVM::execute_block(
        vec![Transaction::UserTransaction(transaction)],
        &VM_CONFIG,
        state_view,
    )?
    .pop()
    .expect("at least return 1 output.");
    debug!("offchain execute txn:{} output: {}", tx_hash, output);
    match output.status() {
        TransactionStatus::Discard(vm_status) => {
            bail!("transaction execute fail for: {:#?}", vm_status)
        }
        TransactionStatus::Keep(vm_status) => match vm_status.major_status {
            StatusCode::EXECUTED => {
                //continue
            }
            _ => bail!("transaction execute fail for: {:#?}", vm_status),
        },
    };
    Ok(output)
}

pub async fn submit_transaction(
    client: &dyn ChainClient,
    signed_transaction: SignedTransaction,
) -> Result<()> {
    let raw_txn_hash = signed_transaction.raw_txn().hash();
    debug!("submit_transaction {}", raw_txn_hash);
    // TODO: should use async version
    client.submit_signed_transaction(signed_transaction)
}

pub async fn watch_transaction(
    client: Arc<dyn ChainClient>,
    sender: AccountAddress,
    seq_number: u64,
) -> Result<TransactionWithProof> {
    let watch_future = client.watch_transaction(&sender, seq_number);
    let (tx_proof, _account_proof) = watch_future.await?;
    match tx_proof {
        Some(proof) => Ok(proof),
        None => Err(format_err!(
            "proof not found by address {:?} and seq num {} .",
            sender,
            seq_number
        )),
    }
}

pub fn respond_with<T>(responder: oneshot::Sender<T>, msg: T) {
    if let Err(_t) = responder.send(msg) {
        error!("fail to send back response, receiver is dropped",);
    };
}

fn generate_channel_address(
    p1: AccountAddress,
    p2: AccountAddress,
) -> (AccountAddress, BTreeSet<AccountAddress>) {
    let mut addresses = BTreeSet::new();
    addresses.insert(p1);
    addresses.insert(p2);
    (AccountAddress::from(&addresses), addresses)
}
