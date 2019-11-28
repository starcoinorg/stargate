// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::channel::ChannelMsg;
use crate::{channel::Channel, scripts::*};
use chrono::Utc;
use failure::prelude::*;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use lazy_static::lazy_static;
use libra_config::config::VMConfig;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue,
};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::access_path::AccessPath;
use libra_types::byte_array::ByteArray;
use libra_types::channel_account::channel_account_struct_tag;
use libra_types::transaction::Transaction;
use libra_types::{
    access_path::DataPath,
    account_address::AccountAddress,
    account_config::{coin_struct_tag, AccountResource},
    channel_account::ChannelAccountResource,
    language_storage::StructTag,
    transaction::{
        helpers::{create_signed_payload_txn, ChannelPayloadSigner, TransactionSigner},
        Module, RawTransaction, SignedTransaction, TransactionArgument, TransactionOutput,
        TransactionPayload, TransactionStatus, TransactionWithProof,
    },
    vm_error::*,
};
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use sgconfig::config::WalletConfig;
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;

use sgstorage::storage::SgStorage;
use sgtypes::channel::ChannelState;
use sgtypes::channel_transaction::ChannelTransactionProposal;
use sgtypes::pending_txn::PendingTransaction;
use sgtypes::sg_error::SgError;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::{
    account_resource_ext,
    channel_transaction::{ChannelOp, ChannelTransactionRequest, ChannelTransactionResponse},
    script_package::{ChannelScriptPackage, ScriptCode},
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::{sync::Arc, time::Duration};
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

        let mut builder = runtime::Builder::new();
        let runtime = builder.name_prefix("wallet").core_threads(4).build()?;

        let inner1 = Shared {
            account,
            keypair,
            client,
            script_registry,
        };

        let inner = Inner {
            inner: inner1.clone(),
            channels: HashMap::new(),
            sgdb: sgdb.clone(),
            runtime,
            mailbox,
        };
        let wallet = Wallet {
            mailbox_sender: mail_sender.clone(),
            shared: inner1,
            sgdb: sgdb.clone(),
            inner: Some(inner),
        };
        Ok(wallet)
    }
    pub fn start(&mut self, executor: runtime::TaskExecutor) -> Result<()> {
        let inner = self.inner.take().expect("wallet already started");
        executor.spawn(inner.start());
        Ok(())
    }

    pub fn get_txn_by_channel_sequence_number(
        &self,
        participant_address: AccountAddress,
        channel_seq_number: u64,
    ) -> Result<SignedChannelTransaction> {
        let channel_db = ChannelDB::new(participant_address, self.sgdb.clone());
        let txn = ChannelStore::new(channel_db)
            .get_transaction_by_channel_seq_number(channel_seq_number, false)?;
        Ok(txn.signed_transaction)
    }
    pub fn account(&self) -> AccountAddress {
        self.shared.account
    }

    pub fn client(&self) -> &dyn ChainClient {
        self.shared.client.as_ref()
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
    pub async fn channel_account_resource(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelAccountResource>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GetChannelResource {
            participant,
            struct_tag: channel_account_struct_tag(),
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp?
            .map(|blob| ChannelAccountResource::make_from(blob))
            .transpose()
    }

    pub async fn channel_sequence_number(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self
            .channel_account_resource(participant)
            .await?
            .map(|account| account.channel_sequence_number())
            .unwrap_or(0))
    }

    pub async fn channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self
            .channel_account_resource(participant)
            .await?
            .map(|account| account.balance())
            .unwrap_or(0))
    }

    /// Open channel and deposit default asset.
    pub async fn open(
        &self,
        participant: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64, // TODO: delete me
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.open receiver:{}, sender_amount:{}, receiver_amount:{}",
            participant, sender_amount, receiver_amount
        );

        self.execute_async(
            participant,
            ChannelOp::Open,
            vec![
                TransactionArgument::ByteArray(ByteArray::new(participant.to_vec())),
                TransactionArgument::U64(sender_amount),
            ],
        )
        .await
    }

    pub async fn deposit(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.deposit receiver:{}, sender_amount:{}, receiver_amount:{}",
            receiver, sender_amount, receiver_amount
        );

        self.execute_async(
            receiver,
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "deposit".to_string(),
            },
            vec![
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
            ],
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
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "transfer".to_string(),
            },
            vec![TransactionArgument::U64(amount)],
        )
        .await
    }

    pub async fn withdraw(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.withdraw receiver:{}, sender_amount:{}, receiver_amount:{}",
            receiver, sender_amount, receiver_amount
        );

        self.execute_async(
            receiver,
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "withdraw".to_string(),
            },
            vec![
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
            ],
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
        let (tx, rx) = oneshot::channel();
        let (_channel_address, _participants) =
            generate_channel_address(self.shared.account, participant);

        let cmd = WalletCmd::Execute {
            participant,
            channel_op,
            args,
            responder: tx,
        };
        let resp = self.call(cmd, rx).await?;
        resp
    }

    /// Receiver verify txn.
    /// If return None, it means the txn needs to be approved by user.
    pub async fn verify_txn(
        &self,
        participant: AccountAddress,
        txn_request: &ChannelTransactionRequest,
    ) -> Result<Option<ChannelTransactionResponse>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::VerifyTxnRequest {
            participant,
            txn_request: txn_request.clone(),
            responder: tx,
        };
        let resp = self.call(cmd, rx).await?;
        resp
    }

    pub async fn approve_txn(
        &self,
        participant: AccountAddress,
        request_id: HashValue,
    ) -> Result<ChannelTransactionResponse> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GrantTxnRequest {
            participant,
            request_id,
            grant: true,
            responder: tx,
        };
        let resp = self.call(cmd, rx).await??;
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
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GrantTxnRequest {
            participant,
            request_id,
            grant: false,
            responder: tx,
        };
        let resp = self.call(cmd, rx).await??;
        debug_assert!(
            resp.is_none(),
            "invalid state of channel, should not return signatures"
        );
        Ok(())
    }

    pub async fn verify_txn_response(
        &self,
        participant: AccountAddress,
        txn_response: &ChannelTransactionResponse,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::VerifyTxnResponse {
            participant,
            txn_response: txn_response.clone(),
            responder: tx,
        };
        let resp = self.call(cmd, rx).await?;
        resp
    }

    pub async fn apply_txn(
        &self,
        participant: AccountAddress,
        txn_response: &ChannelTransactionResponse,
    ) -> Result<u64> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::ApplyTxnResponse {
            participant,
            txn_response: txn_response.clone(),
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp
    }

    /// Called by receiver to get proposal waiting user approval.
    pub async fn get_waiting_proposal(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelTransactionProposal>> {
        let pending_txn = self.get_pending_txn(participant).await?;
        let proposal = pending_txn.and_then(|pending| match pending {
            PendingTransaction::WaitForSig {
                proposal,
                mut signatures,
                ..
            } => {
                if proposal.channel_txn.proposer() == self.shared.account {
                    None
                } else {
                    let _user_sigs = signatures.remove(&self.shared.account);
                    if signatures.contains_key(&self.shared.account) {
                        None
                    } else {
                        Some(proposal)
                    }
                }
            }
            PendingTransaction::WaitForApply { .. } => None,
        });
        Ok(proposal)
    }

    /// Get pending txn request.
    pub async fn get_pending_txn_request(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelTransactionRequest>> {
        let pending_txn = self.get_pending_txn(participant).await?;
        let request = pending_txn.and_then(|pending| match pending {
            PendingTransaction::WaitForSig {
                proposal,
                mut signatures,
                ..
            } => {
                let proposer_sigs = signatures.remove(&proposal.channel_txn.proposer());
                debug_assert!(proposer_sigs.is_some());

                Some(ChannelTransactionRequest::new(
                    proposal.clone(),
                    proposer_sigs.unwrap(),
                ))
            }
            _ => None,
        });

        Ok(request)
    }

    async fn get_pending_txn(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<PendingTransaction>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GetPendingTxn {
            participant,
            responder: tx,
        };

        let pending_txn = self.call(cmd, rx).await??;
        Ok(pending_txn)
    }

    pub async fn install_package(&self, package: ChannelScriptPackage) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::InstallPackage {
            package,
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp
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
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GetScriptCode {
            package_name,
            script_name,
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp
    }

    pub async fn get_all_channels(&self) -> Result<HashSet<AccountAddress>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GetAllChannels { responder: tx };

        let resp = self.call(cmd, rx).await?;
        resp
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
    Execute {
        participant: AccountAddress,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
        responder: oneshot::Sender<Result<ChannelTransactionRequest>>,
    },
    VerifyTxnRequest {
        participant: AccountAddress,
        txn_request: ChannelTransactionRequest,
        responder: oneshot::Sender<Result<Option<ChannelTransactionResponse>>>,
    },
    GrantTxnRequest {
        participant: AccountAddress,
        request_id: HashValue,
        grant: bool,
        responder: oneshot::Sender<Result<Option<ChannelTransactionResponse>>>,
    },
    VerifyTxnResponse {
        participant: AccountAddress,
        txn_response: ChannelTransactionResponse,
        responder: oneshot::Sender<Result<()>>,
    },
    ApplyTxnResponse {
        participant: AccountAddress,
        txn_response: ChannelTransactionResponse,
        responder: oneshot::Sender<Result<u64>>,
    },
    InstallPackage {
        package: ChannelScriptPackage,
        responder: oneshot::Sender<Result<()>>,
    },
    GetAllChannels {
        responder: oneshot::Sender<Result<HashSet<AccountAddress>>>,
    },
    DeployModule {
        module_byte_code: Vec<u8>,
        responder: oneshot::Sender<Result<TransactionWithProof>>,
    },
    GetScriptCode {
        package_name: String,
        script_name: String,
        responder: oneshot::Sender<Result<Option<ScriptCode>>>,
    },
    GetChannelResource {
        participant: AccountAddress,
        struct_tag: StructTag,
        responder: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    GetPendingTxn {
        participant: AccountAddress,
        responder: oneshot::Sender<Result<Option<PendingTransaction>>>,
    },
}

pub struct Inner {
    inner: Shared,
    channels: HashMap<AccountAddress, Channel>,
    sgdb: Arc<SgStorage>,
    runtime: tokio::runtime::Runtime,
    mailbox: mpsc::Receiver<WalletCmd>,
    //    channel_event_receiver: mpsc::Receiver<ChannelEvent>,
}

impl Inner {
    async fn start(mut self) {
        if let Err(e) = self.refresh_channels() {
            error!("fail to start all channels, err: {:?}", e);
            return ();
        }
        loop {
            ::futures::select! {
               maybe_external_cmd = self.mailbox.next() => {
                   if let Some(cmd) = maybe_external_cmd {
                       self.handle_external_cmd(cmd).await;
                   }
               }
               complete => {
                   break;
               }
            }
        }
        crit!("wallet dispatcher task terminated");
    }

    async fn handle_external_cmd(&mut self, cmd: WalletCmd) {
        match cmd {
            WalletCmd::Execute {
                participant,
                channel_op,
                args,
                responder,
            } => {
                let resp = self.execute(participant, channel_op, args).await;
                respond_with(responder, resp);
            }
            WalletCmd::VerifyTxnRequest {
                participant,
                txn_request,
                responder,
            } => {
                respond_with(responder, self.verify_txn(participant, txn_request).await);
            }
            WalletCmd::GrantTxnRequest {
                participant,
                grant,
                request_id,
                responder,
            } => {
                respond_with(
                    responder,
                    self.grant_txn_request(participant, request_id, grant).await,
                );
            }
            WalletCmd::VerifyTxnResponse {
                participant,
                txn_response,
                responder,
            } => {
                respond_with(
                    responder,
                    self.verify_txn_response(participant, txn_response).await,
                );
            }
            WalletCmd::ApplyTxnResponse {
                participant,
                txn_response,
                responder,
            } => {
                respond_with(responder, self.apply_txn(participant, txn_response).await);
            }
            WalletCmd::GetChannelResource {
                participant,
                struct_tag,
                responder,
            } => {
                respond_with(
                    responder,
                    self.get_channel_resource(participant, struct_tag).await,
                );
            }
            WalletCmd::GetPendingTxn {
                participant,
                responder,
            } => {
                respond_with(responder, self.get_channel_pending_txn(participant).await);
            }
            WalletCmd::InstallPackage { package, responder } => {
                let result = self.install_package(package);
                respond_with(responder, result);
            }
            WalletCmd::DeployModule {
                module_byte_code,
                responder,
            } => {
                let response = self.deploy_module(module_byte_code).await;
                respond_with(responder, response);
            }
            WalletCmd::GetScriptCode {
                package_name,
                script_name,
                responder,
            } => {
                let resp = self
                    .inner
                    .script_registry
                    .get_script(&package_name, &script_name);
                respond_with(responder, Ok(resp));
            }
            WalletCmd::GetAllChannels { responder } => {
                let all_channels = self
                    .channels
                    .values()
                    .map(|c| {
                        let mut participants = c.participant_addresses().to_vec();
                        participants.retain(|e| e != c.account_address());
                        debug_assert_eq!(1, participants.len());
                        participants[0]
                    })
                    .collect::<HashSet<_>>();
                respond_with(responder, Ok(all_channels));
            }
        }
    }

    /// FIXME: load from correct path
    fn refresh_channels(&mut self) -> Result<()> {
        let account_state = self
            .inner
            .client
            .get_account_state(self.inner.account, None)?;
        let my_channel_states = account_state.filter_channel_state(self.inner.account);
        let version = account_state.version();
        for (participant, my_channel_state) in my_channel_states {
            if !self.exist_channel(&participant) {
                let participant_account_state = self
                    .inner
                    .client
                    .get_account_state(participant, Some(version))?;
                let mut participant_channel_states =
                    participant_account_state.filter_channel_state(participant);
                let participant_channel_state = participant_channel_states
                    .remove(&self.inner.account)
                    .ok_or(format_err!(
                        "Can not find channel {} in {}",
                        self.inner.account,
                        participant
                    ))?;
                let (channel_address, _) =
                    generate_channel_address(self.inner.account, participant);
                let participant_states = {
                    let mut s = BTreeMap::new();
                    s.insert(
                        participant_channel_state.address(),
                        participant_channel_state,
                    );
                    s.insert(my_channel_state.address(), my_channel_state);
                    s
                };
                self.spawn_channel(channel_address, participant_states);
            }
        }
        Ok(())
    }

    fn ensure_channel_not_exists(&self, channel_address: &AccountAddress) -> Result<()> {
        if self.exist_channel(channel_address) {
            let err = format_err!("Channel with address {} exist.", &channel_address);
            Err(err)
        } else {
            Ok(())
        }
    }
    fn get_channel_mut(&mut self, participant: &AccountAddress) -> Result<&mut Channel> {
        let channel = match self.channels.get_mut(&participant) {
            Some(channel) => Ok(channel),
            None => {
                let e: Error = SgError::new_channel_not_exist_error(&participant).into();
                Err(e)
            }
        };
        channel
    }

    async fn execute(
        &mut self,
        participant: AccountAddress,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        let (channel_address, participants) =
            generate_channel_address(participant, self.inner.account);
        if channel_op.is_open() {
            self.ensure_channel_not_exists(&channel_address)?;
            self.spawn_new_channel(channel_address, participants);
        }

        let channel = self.get_channel_mut(&channel_address)?;

        let (tx, rx) = oneshot::channel();
        let msg = ChannelMsg::Execute {
            channel_op,
            args,
            responder: tx,
        };
        channel.send(msg)?;
        let (proposal, sigs) = rx.await??;
        let request = ChannelTransactionRequest::new(proposal, sigs);
        Ok(request)
    }

    /// Verify channel participant's txn
    async fn verify_txn(
        &mut self,
        participant: AccountAddress,
        txn_request: ChannelTransactionRequest,
    ) -> Result<Option<ChannelTransactionResponse>> {
        let request_id = txn_request.request_id();

        let channel_txn = txn_request.channel_txn();

        debug!("verify_txn id:{}", request_id);
        ensure!(
            participant == channel_txn.proposer(),
            "peer id and txn proposer mismatch"
        );

        let (generated_channel_address, participants) =
            generate_channel_address(channel_txn.proposer(), self.inner.account);
        ensure!(
            generated_channel_address == channel_txn.channel_address(),
            "invalid channel address in txn"
        );

        if channel_txn.operator().is_open() {
            self.ensure_channel_not_exists(&generated_channel_address)?;
            self.spawn_new_channel(generated_channel_address, participants);
        }

        let channel = self.get_channel_mut(&generated_channel_address)?;

        let (proposal, sigs) = txn_request.into();
        let (tx, rx) = oneshot::channel();
        let msg = ChannelMsg::CollectProposalWithSigs {
            proposal: proposal.clone(),
            sigs,
            responder: tx,
        };
        channel.send(msg)?;
        let sig_opt = rx.await??;
        Ok(sig_opt.map(|s| ChannelTransactionResponse::new(proposal, s)))
    }

    async fn grant_txn_request(
        &mut self,
        participant: AccountAddress,
        request_id: HashValue,
        grant: bool,
    ) -> Result<Option<ChannelTransactionResponse>> {
        let pending_txn = self.get_channel_pending_txn(participant).await?;
        let proposal: ChannelTransactionProposal = match pending_txn {
            Some(r) => {
                let (p, _, _) = r.into();
                p
            }
            None => bail!("no pending txn to grant"),
        };

        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.inner.account);

        let channel = self.get_channel_mut(&generated_channel_address)?;

        let (tx, rx) = oneshot::channel();
        let msg = ChannelMsg::GrantProposal {
            channel_txn_id: request_id,
            grant,
            responder: tx,
        };
        channel.send(msg)?;
        let resp = rx.await??;
        Ok(resp.map(|s| ChannelTransactionResponse::new(proposal, s)))
    }

    async fn verify_txn_response(
        &mut self,
        participant: AccountAddress,
        txn_response: ChannelTransactionResponse,
    ) -> Result<()> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.inner.account);

        let channel = self.get_channel_mut(&generated_channel_address)?;

        let (tx, rx) = oneshot::channel();
        let (proposal, sigs) = txn_response.into();
        let msg = ChannelMsg::CollectProposalWithSigs {
            proposal,
            sigs,
            responder: tx,
        };
        channel.send(msg)?;
        let _ = rx.await??; // the result is not need.
        Ok(())
    }

    async fn apply_txn(
        &mut self,
        participant: AccountAddress,
        _txn_response: ChannelTransactionResponse,
    ) -> Result<u64> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.inner.account);

        let channel = self.get_channel_mut(&generated_channel_address)?;

        let (tx, rx) = oneshot::channel();
        let msg = ChannelMsg::ApplyPendingTxn { responder: tx };
        channel.send(msg)?;

        let gas = rx.await??;
        Ok(gas)
    }

    async fn get_channel_pending_txn(
        &mut self,
        participant: AccountAddress,
    ) -> Result<Option<PendingTransaction>> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.inner.account);
        let channel = self.get_channel_mut(&generated_channel_address)?;
        let (tx, rx) = oneshot::channel();
        let msg = ChannelMsg::GetPendingTxn { responder: tx };
        channel.send(msg)?;
        Ok(rx.await?)
    }

    /// get channel account resource data from channel task
    async fn get_channel_resource(
        &mut self,
        participant: AccountAddress,
        struct_tag: StructTag,
    ) -> Result<Option<Vec<u8>>> {
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.inner.account);
        let (tx, rx) = oneshot::channel();

        let data_path = DataPath::channel_resource_path(participant, struct_tag);
        let msg = ChannelMsg::AccessPath {
            path: AccessPath::new_for_data_path(self.inner.account, data_path),
            responder: tx,
        };
        let channel = self.get_channel_mut(&generated_channel_address)?;
        channel.send(msg)?;
        rx.await?
    }

    fn install_package(&self, package: ChannelScriptPackage) -> Result<()> {
        //TODO(jole) package should limit channel?
        self.inner.script_registry.install_package(package)?;
        Ok(())
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
        watch_transaction(self.inner.client.as_ref(), address, seq_number).await
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

    fn exist_channel(&self, channel_address: &AccountAddress) -> bool {
        self.channels.contains_key(channel_address)
    }

    fn spawn_new_channel(
        &mut self,
        channel_address: AccountAddress,
        participants: BTreeSet<AccountAddress>,
    ) {
        self.spawn_channel(
            channel_address,
            participants
                .into_iter()
                .map(|addr| (addr, ChannelState::empty(addr)))
                .collect(),
        );
    }

    fn spawn_channel(
        &mut self,
        channel_address: AccountAddress,
        participants_states: BTreeMap<AccountAddress, ChannelState>,
    ) {
        let (channel_msg_sender, channel_msg_receiver) = mpsc::channel(1000);

        let mut channel = Channel::load(
            channel_address,
            self.inner.account,
            participants_states,
            self.get_channel_db(channel_address),
            channel_msg_sender,
            channel_msg_receiver,
            self.inner.keypair.clone(),
            self.inner.script_registry.clone(),
            self.inner.client.clone(),
        );
        channel.start(self.runtime.executor().clone());

        // TODO: should wait signal of channel saying it's started
        self.channels.insert(channel_address, channel);
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

impl ChannelPayloadSigner for Wallet {
    fn sign_bytes(&self, bytes: Vec<u8>) -> Result<Ed25519Signature> {
        self.shared.keypair.sign_bytes(bytes)
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
    debug!("execute txn:{} output: {}", tx_hash, output);
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
    client: &dyn ChainClient,
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
