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
};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::access_path::AccessPath;
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
        ChannelTransactionPayloadBody, Module, RawTransaction, SignedTransaction,
        TransactionArgument, TransactionOutput, TransactionPayload, TransactionStatus,
        TransactionWithProof,
    },
    vm_error::*,
};
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use sgconfig::config::WalletConfig;
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use sgstorage::storage::SgStorage;
use sgtypes::channel::{ChannelInfo, ChannelState};
use sgtypes::sg_error::SgError;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::{
    account_resource_ext,
    channel_transaction::{ChannelOp, ChannelTransactionRequest, ChannelTransactionResponse},
    script_package::{ChannelScriptPackage, ScriptCode},
};
use std::collections::{HashMap, HashSet};
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
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.open receiver:{}, sender_amount:{}, receiver_amount:{}",
            receiver, sender_amount, receiver_amount
        );

        self.execute_async(
            receiver,
            ChannelOp::Open,
            vec![
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
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
        receiver: AccountAddress,
        channel_op: ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::Execute {
            participant: receiver,
            channel_op,
            args,
            responder: tx,
        };
        let resp = self.call(cmd, rx).await?;
        resp
    }

    pub async fn verify_txn(
        &self,
        txn_request: &ChannelTransactionRequest,
    ) -> Result<ChannelTransactionResponse> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::VerifyTxnRequest {
            txn_request: txn_request.clone(),
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

    pub async fn get_pending_txn_request(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelTransactionRequest>> {
        let (tx, rx) = oneshot::channel();
        let cmd = WalletCmd::GetPendingTxnRequest {
            participant,
            responder: tx,
        };

        let resp = self.call(cmd, rx).await?;
        resp
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
        txn_request: ChannelTransactionRequest,
        responder: oneshot::Sender<Result<ChannelTransactionResponse>>,
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
    GetPendingTxnRequest {
        participant: AccountAddress,
        responder: oneshot::Sender<Result<Option<ChannelTransactionRequest>>>,
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
    //    async fn start_channel_manager(channel_event_receiver: mpsc::Receiver<ChannelEvent>) {
    //        loop {
    //            ::futures::select! {
    //                maybe_channel_event = channel_event_receiver.next() => {
    //                    if let Some(event) = maybe_channel_event {
    //                        Self::handle_channel_event(event).await
    //                    }
    //                }
    //            }
    //        }
    //    }
    //    async fn handle_channel_event(event: ChannelEvent) {}

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
            } => self.execute(channel_op, participant, args, responder).await,
            WalletCmd::VerifyTxnRequest {
                txn_request,
                responder,
            } => self.verify_txn(&txn_request, responder).await,
            WalletCmd::ApplyTxnResponse {
                participant,
                txn_response,
                responder,
            } => self.apply_txn(participant, &txn_response, responder).await,
            WalletCmd::GetChannelResource {
                participant,
                struct_tag,
                responder,
            } => {
                self.get_channel_resource(participant, struct_tag, responder)
                    .await;
            }
            WalletCmd::GetPendingTxnRequest {
                participant,
                responder,
            } => {
                self.get_pending_channel_txn_request(participant, responder)
                    .await
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
                    .keys()
                    .map(Clone::clone)
                    .collect::<HashSet<_>>();
                respond_with(responder, Ok(all_channels));
            }
        }
    }
    //    fn ensure_channel_not_exists(&self, participant: AccountAddress) -> Result<()> {
    //        if self.channels.contains_key(&participant) {
    //            bail!("Channel with address {} exist.", participant);
    //        }
    //        Ok(())
    //    }

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
                self.spawn_channel(my_channel_state, participant_channel_state);
            }
        }
        Ok(())
    }

    //    pub fn default_asset() -> StructTag {
    //        DEFAULT_ASSET.clone()
    //    }
    //
    //    pub fn get_resources() -> Vec<Resource> {
    //        unimplemented!()
    //    }
    //
    async fn execute(
        &mut self,
        channel_op: ChannelOp,
        receiver: AccountAddress,
        args: Vec<TransactionArgument>,
        responder: oneshot::Sender<Result<ChannelTransactionRequest>>,
    ) {
        if channel_op.is_open() {
            if self.exist_channel(&receiver) {
                let err = format_err!("Channel with address {} exist.", &receiver);
                respond_with(responder, Err(err));
                return ();
            }
            self.spawn_new_channel(receiver);
        }

        let channel = match self.channels.get_mut(&receiver) {
            Some(channel) => channel,
            None => {
                let e: Error = SgError::new_channel_not_exist_error(&receiver).into();
                if let Err(_) = responder.send(Err(e)) {
                    error!(
                        "fail to send back response of op({:?}) , receiver is dropped",
                        &channel_op
                    );
                };
                return ();
            }
        };

        let msg = ChannelMsg::Execute {
            channel_op,
            args,
            responder,
        };
        if let Err(err) = channel.mail_sender().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            if let ChannelMsg::Execute { responder, .. } = err.into_inner() {
                let resp_err = format_err!("channel {:?} mailbox {:?}", &receiver, err_status);
                respond_with(responder, Err(resp_err));
            }
        };
    }

    /// Verify channel participant's txn
    async fn verify_txn(
        &mut self,
        txn_request: &ChannelTransactionRequest,
        responder: oneshot::Sender<Result<ChannelTransactionResponse>>,
    ) -> () {
        let request_id = txn_request.request_id();
        let channel_txn = txn_request.channel_txn();

        // get channel
        debug!("verify_txn id:{}", request_id);

        let participant = channel_txn.sender();
        if channel_txn.operator().is_open() {
            if self.exist_channel(&participant) {
                respond_with(
                    responder,
                    Err(format_err!("Channel with address {} exist.", &participant)),
                );
                return ();
            }
            self.spawn_new_channel(participant);
        }

        let channel = match self.channels.get_mut(&participant) {
            Some(channel) => channel,
            None => {
                let e: Error = SgError::new_channel_not_exist_error(&participant).into();
                respond_with(responder, Err(e));
                return ();
            }
        };

        let msg = ChannelMsg::VerifyTxnRequest {
            txn_request: txn_request.clone(),
            responder,
        };
        if let Err(err) = channel.mail_sender().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            if let ChannelMsg::VerifyTxnRequest { responder, .. } = err.into_inner() {
                let resp_err = format_err!("channel {:?} mailbox {:?}", &participant, err_status);
                respond_with(responder, Err(resp_err));
            }
        }
    }

    async fn apply_txn(
        &mut self,
        participant: AccountAddress,
        txn_response: &ChannelTransactionResponse,
        responder: oneshot::Sender<Result<u64>>,
    ) {
        let channel = match self.channels.get_mut(&participant) {
            Some(channel) => channel,
            None => {
                let e: Error = SgError::new_channel_not_exist_error(&participant).into();
                respond_with(responder, Err(e));
                return ();
            }
        };

        // first validate response
        let (tx, rx) = oneshot::channel();
        let msg = ChannelMsg::VerifyTxnResponse {
            txn_response: txn_response.clone(),
            responder: tx,
        };
        if let Err(err) = channel.mail_sender().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            let resp_err = format_err!("channel {:?} mailbox {:?}", &participant, err_status);
            if let Err(_) = responder.send(Err(resp_err)) {
                error!("fail to send back response , receiver is dropped");
            }
            return ();
        };

        let resp = rx.await;
        if let Some(err) = resp
            .map_err(|_| format_err!("sender dropped"))
            .and_then(|r| r)
            .err()
        {
            if let Err(_) = responder.send(Err(err)) {
                error!("fail to send back response , receiver is dropped");
            }
            return ();
        }

        //        info!("success apply channel request: {}", response.request_id());
        let msg = ChannelMsg::ApplyPendingTxn { responder };
        if let Err(err) = channel.mail_sender().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            if let ChannelMsg::ApplyPendingTxn { responder, .. } = err.into_inner() {
                let resp_err = format_err!("channel {:?} mailbox {:?}", &participant, err_status);
                respond_with(responder, Err(resp_err));
            }
        };
    }

    async fn get_pending_channel_txn_request(
        &mut self,
        participant: AccountAddress,
        responder: oneshot::Sender<Result<Option<ChannelTransactionRequest>>>,
    ) {
        let channel = match self.channels.get(&participant) {
            Some(channel) => channel,
            None => {
                let e: Error = SgError::new_channel_not_exist_error(&participant).into();
                respond_with(responder, Err(e));
                return ();
            }
        };
        let msg = ChannelMsg::GetPendingChannelTransactionRequest { responder };
        if let Err(err) = channel.mail_sender().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            if let ChannelMsg::AccessPath { responder, .. } = err.into_inner() {
                let resp_err = format_err!("channel {:?} mailbox {:?}", &participant, err_status);
                respond_with(responder, Err(resp_err));
            }
        }
    }

    /// get channel account resource data from channel task
    async fn get_channel_resource(
        &self,
        participant: AccountAddress,
        struct_tag: StructTag,
        responder: oneshot::Sender<Result<Option<Vec<u8>>>>,
    ) {
        let channel = match self.channels.get(&participant) {
            Some(channel) => channel,
            None => {
                let e: Error = SgError::new_channel_not_exist_error(&participant).into();
                respond_with(responder, Err(e));
                return ();
            }
        };
        let data_path = DataPath::channel_resource_path(participant, struct_tag);
        let msg = ChannelMsg::AccessPath {
            path: AccessPath::new_for_data_path(self.inner.account, data_path),
            responder,
        };
        if let Err(err) = channel.mail_sender().try_send(msg) {
            let err_status = if err.is_disconnected() {
                "closed"
            } else {
                "full"
            };
            if let ChannelMsg::AccessPath { responder, .. } = err.into_inner() {
                let resp_err = format_err!("channel {:?} mailbox {:?}", &participant, err_status);
                respond_with(responder, Err(resp_err));
            }
        }
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

    pub fn get(&self, _path: &DataPath) -> Result<Option<Vec<u8>>> {
        //        if path.is_channel_resource() {
        //            let participant = path.participant().expect("participant must exist");
        //            self.with_channel(&participant, |channel| {
        //                Ok(channel.get(&AccessPath::new_for_data_path(
        //                    self.inner.account,
        //                    path.clone(),
        //                )))
        //            })
        //        } else {
        //            let account_state = self
        //                .inner
        //                .client
        //                .get_account_state(self.inner.account, None)?;
        //            Ok(account_state.get(&path.to_vec()))
        //        }
        unimplemented!()
    }

    /// return all channels' state infos
    pub fn channel_infos(&self) -> HashMap<AccountAddress, ChannelInfo> {
        //        let channels = self.channels.read().unwrap();
        //        channels
        //            .iter()
        //            .map(|(ap, channel)| (ap.clone(), channel.channel_info()))
        //            .collect::<HashMap<_, _>>()
        unimplemented!()
    }

    fn exist_channel(&self, participant: &AccountAddress) -> bool {
        self.channels.contains_key(participant)
    }

    fn spawn_new_channel(&mut self, participant: AccountAddress) {
        self.spawn_channel(
            ChannelState::empty(self.inner.account),
            ChannelState::empty(participant),
        );
    }

    fn spawn_channel(
        &mut self,
        account_channel_state: ChannelState,
        participant_channel_state: ChannelState,
    ) {
        let participant = participant_channel_state.address();
        let (channel_msg_sender, channel_msg_receiver) = mpsc::channel(1000);

        let mut channel = Channel::load(
            account_channel_state,
            participant_channel_state,
            self.get_channel_db(participant),
            channel_msg_sender,
            channel_msg_receiver,
            self.inner.keypair.clone(),
            self.inner.script_registry.clone(),
            self.inner.client.clone(),
        );
        channel.start(self.runtime.executor().clone());

        // TODO: should wait signal of channel saying it's started
        self.channels.insert(participant, channel);
        info!("Init new channel with: {}", participant);
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

pub(crate) fn get_channel_transaction_payload_body(
    raw_txn: &RawTransaction,
) -> Result<ChannelTransactionPayloadBody> {
    match raw_txn.payload() {
        TransactionPayload::Channel(payload) => Ok(payload.body.clone()),
        _ => bail!("raw txn must a Channel Transaction"),
    }
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
