// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel::{pending_txn_to_onchain_txn, PendingTransaction};
use crate::{channel::Channel, scripts::*};
use chrono::Utc;
use failure::prelude::*;
use lazy_static::lazy_static;
use libra_config::config::VMConfig;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, SigningKey, VerifyingKey,
};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::access_path::AccessPath;
use libra_types::transaction::Transaction;
use libra_types::write_set::WriteSet;
use libra_types::{
    access_path::DataPath,
    account_address::AccountAddress,
    account_config::{coin_struct_tag, AccountResource},
    channel_account::ChannelAccountResource,
    language_storage::StructTag,
    transaction::{
        helpers::{create_signed_payload_txn, ChannelPayloadSigner, TransactionSigner},
        ChannelScriptBody, ChannelTransactionPayload, ChannelTransactionPayloadBody, Module,
        RawTransaction, Script, SignedTransaction, TransactionArgument, TransactionOutput,
        TransactionPayload, TransactionStatus, TransactionWithProof,
    },
    vm_error::*,
};
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use sgconfig::config::WalletConfig;
use sgstorage::channel_db::ChannelDB;
use sgstorage::storage::SgStorage;
use sgtypes::channel::ChannelInfo;
use sgtypes::sg_error::SgError;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use sgtypes::{
    account_resource_ext,
    channel_transaction::{
        ChannelOp, ChannelTransaction, ChannelTransactionRequest, ChannelTransactionResponse,
    },
    resource::Resource,
    script_package::{ChannelScriptPackage, ScriptCode},
};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::RwLock;
use std::{sync::Arc, time::Duration};
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

pub struct Wallet<C>
where
    C: ChainClient + Send + Sync + 'static,
{
    inner: WalletInner<C>,
    channels: RwLock<HashMap<AccountAddress, Channel>>,
    sgdb: Arc<SgStorage>,
}

impl<C> Wallet<C>
where
    C: ChainClient + Send + Sync + 'static,
{
    pub fn new(
        account: AccountAddress,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        rpc_host: &str,
        rpc_port: u32,
    ) -> Result<Wallet<StarChainClient>> {
        let chain_client = StarChainClient::new(rpc_host, rpc_port as u32);
        let client = Arc::new(chain_client);
        Wallet::new_with_client(account, keypair, client, WalletConfig::default().store_dir)
    }

    pub fn new_with_client<P: AsRef<Path>>(
        account: AccountAddress,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        client: Arc<C>,
        store_dir: P,
    ) -> Result<Self> {
        let sgdb = Arc::new(SgStorage::new(account, store_dir));

        let script_registry = Arc::new(PackageRegistry::build()?);
        let inner = WalletInner {
            account,
            keypair,
            client,
            script_registry,
        };
        let mut wallet = Self {
            inner,
            channels: RwLock::new(HashMap::new()),
            sgdb,
        };
        wallet.refresh_channels()?;
        Ok(wallet)
    }

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
                let channel_db = self.get_channel_db(participant);
                let channel =
                    Channel::load(my_channel_state, participant_channel_state, channel_db)?;
                info!("Init new channel with: {}", participant);
                self.channels.write().unwrap().insert(participant, channel);
            }
        }
        Ok(())
    }

    pub fn account(&self) -> AccountAddress {
        self.inner.account
    }

    pub fn client(&self) -> &dyn ChainClient {
        self.inner.client()
    }

    pub fn default_asset() -> StructTag {
        DEFAULT_ASSET.clone()
    }

    pub fn get_resources() -> Vec<Resource> {
        unimplemented!()
    }

    /// Open channel and deposit default asset.
    pub fn open(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.open receiver:{}, sender_amount:{}, receiver_amount:{}",
            receiver, sender_amount, receiver_amount
        );
        if self.exist_channel(&receiver) {
            bail!("Channel with address {} exist.", receiver);
        }
        self.new_channel(receiver);

        self.execute(
            ChannelOp::Open,
            receiver,
            vec![
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
            ],
        )
    }

    pub fn deposit(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.deposit receiver:{}, sender_amount:{}, receiver_amount:{}",
            receiver, sender_amount, receiver_amount
        );
        self.execute(
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "deposit".to_string(),
            },
            receiver,
            vec![
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
            ],
        )
    }

    pub fn transfer(
        &self,
        receiver: AccountAddress,
        amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!("wallet.transfer receiver:{}, amount:{}", receiver, amount);

        self.execute(
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "transfer".to_string(),
            },
            receiver,
            vec![TransactionArgument::U64(amount)],
        )
    }

    pub fn withdraw(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<ChannelTransactionRequest> {
        info!(
            "wallet.withdraw receiver:{}, sender_amount:{}, receiver_amount:{}",
            receiver, sender_amount, receiver_amount
        );
        self.execute(
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "withdraw".to_string(),
            },
            receiver,
            vec![
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
            ],
        )
    }

    pub fn close(&self, receiver: AccountAddress) -> Result<ChannelTransactionRequest> {
        self.execute(ChannelOp::Close, receiver, vec![])
    }

    pub fn execute_script(
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

        self.execute(
            ChannelOp::Execute {
                package_name: package_name.to_string(),
                script_name: script_name.to_string(),
            },
            receiver,
            args,
        )
    }

    fn execute(
        &self,
        channel_op: ChannelOp,
        receiver: AccountAddress,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        let channels = self.channels.read().unwrap();
        let channel = channels
            .deref()
            .get(&receiver)
            .ok_or::<Error>(SgError::new_channel_not_exist_error(&receiver).into())?;
        channel.execute(&self.inner, channel_op, args)
    }

    /// Verify channel participant's txn
    pub fn verify_txn(
        &self,
        txn_request: &ChannelTransactionRequest,
    ) -> Result<ChannelTransactionResponse> {
        let request_id = txn_request.request_id();
        let channel_txn = txn_request.channel_txn();
        let _channel_txn_sender_sigs = txn_request.channel_txn_sigs();

        // get channel
        debug!("verify_txn id:{}", request_id);
        ensure!(
            channel_txn.receiver() == self.inner.account,
            "check receiver fail."
        );
        let sender = channel_txn.sender();
        if channel_txn.operator().is_open() {
            if self.exist_channel(&sender) {
                bail!("Channel with address {} exist.", sender);
            }
            self.new_channel(sender);
        }

        let channels = self.channels.read().unwrap();
        let channel = channels
            .deref()
            .get(&sender)
            .ok_or::<Error>(SgError::new_channel_not_exist_error(&sender).into())?;
        channel.verify_txn_request(&self.inner, txn_request)
    }

    pub async fn receiver_apply_txn(
        &self,
        participant: AccountAddress,
        response: &ChannelTransactionResponse,
    ) -> Result<u64> {
        let txn_to_watch = self.with_channel(&participant, |channel| {
            let (channel_txn, output) = match channel.pending_txn() {
                Some(PendingTransaction::WaitForApply { raw_tx, output, .. }) => (raw_tx, output),
                Some(_) => bail!("invalid state of receiver apply txn"),
                //TODO(jole) can not find request has such reason:
                // 1. txn is expire.
                // 2. txn is invalid.
                None => bail!(
                    "pending_txn_request must exist at stage:{:?}",
                    channel.stage()
                ),
            };
            Ok(if output.is_travel_txn() {
                Some((channel_txn.sender(), channel_txn.sequence_number()))
            } else {
                None
            })
        })?;

        let gas = match txn_to_watch {
            Some((address, seq_number)) => {
                let watch_future = self.inner.client().watch_transaction(&address, seq_number);
                // FIXME: should not panic here, handle timeout situation.
                let txn_with_proof = watch_future.await?.0.expect("proof is none.");

                txn_with_proof.proof.transaction_info().gas_used()
            }
            None => 0,
        };

        self.with_channel_mut(&participant, |channel| channel.apply())?;

        info!("success apply channel request: {}", response.request_id());

        Ok(gas)
    }

    pub async fn sender_apply_txn(
        &self,
        participant: AccountAddress,
        response: &ChannelTransactionResponse,
    ) -> Result<u64> {
        let onchain_txn_to_submit = self.with_channel(&participant, |channel| {
            //verify response
            let (verified_participant_script_payload, _verified_participant_witness_payload) =
                channel.verify_txn_response(&self.inner, response)?;
            let signed_txn = match channel.pending_txn() {
                //TODO(jole) can not find request has such reason:
                // 1. txn is expire.
                // 2. txn is invalid.
                None => bail!(
                    "pending_txn_request must exist at stage:{:?}",
                    channel.stage()
                ),
                Some(pending_txn) => {
                    match pending_txn_to_onchain_txn(
                        pending_txn,
                        verified_participant_script_payload,
                    )? {
                        Some(raw_txn) => Some(self.inner.mock_signature(raw_txn)?),
                        None => None,
                    }
                }
            };
            Ok(signed_txn)
        })?;

        // then, submit txn to chain
        let gas = if let Some(signed_txn) = onchain_txn_to_submit {
            let txn_with_proof = self.inner.submit_transaction(signed_txn).await?;
            txn_with_proof.proof.transaction_info().gas_used()
        } else {
            0
        };

        // if ok, apply the channel txn to db
        self.with_channel_mut(&participant, |channel| channel.apply())?;

        info!("success apply channel request: {}", response.request_id());
        Ok(gas)
    }

    pub fn install_package(&self, package: ChannelScriptPackage) -> Result<()> {
        //TODO(jole) package should limit channel?
        self.inner.script_registry.install_package(package)?;
        Ok(())
    }

    /// Deploy a module to Chain
    pub async fn deploy_module(&self, module_byte_code: Vec<u8>) -> Result<TransactionWithProof> {
        let payload = TransactionPayload::Module(Module::new(module_byte_code));
        //TODO pre execute deploy module txn on local , and get real gas used to set max_gas_amount.
        let txn = create_signed_payload_txn(
            self,
            payload,
            self.inner.account,
            self.sequence_number()?,
            MAX_GAS_AMOUNT_ONCHAIN,
            GAS_UNIT_PRICE,
            TXN_EXPIRATION.as_secs() as i64,
        )?;
        //TODO need execute at local vm for check?
        self.inner.submit_transaction(txn).await
    }

    pub fn get_script(&self, package_name: &str, script_name: &str) -> Option<ScriptCode> {
        self.inner
            .script_registry
            .get_script(package_name, script_name)
    }

    pub fn get(&self, path: &DataPath) -> Result<Option<Vec<u8>>> {
        if path.is_channel_resource() {
            let participant = path.participant().expect("participant must exist");
            self.with_channel(&participant, |channel| {
                Ok(channel.get(&AccessPath::new_for_data_path(
                    self.inner.account,
                    path.clone(),
                )))
            })
        } else {
            let account_state = self
                .inner
                .client
                .get_account_state(self.inner.account, None)?;
            Ok(account_state.get(&path.to_vec()))
        }
    }

    pub fn account_resource(&self) -> Result<AccountResource> {
        self.inner.account_resource()
    }
    pub fn sequence_number(&self) -> Result<u64> {
        self.inner.sequence_number()
    }
    //TODO support more asset type
    pub fn balance(&self) -> Result<u64> {
        self.inner.balance()
    }

    pub fn channel_account_resource(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelAccountResource>> {
        self.get(&DataPath::channel_account_path(participant))
            .and_then(|value| match value {
                Some(value) => Ok(Some(ChannelAccountResource::make_from(value)?)),
                None => Ok(None),
            })
    }

    pub fn channel_sequence_number(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self
            .channel_account_resource(participant)?
            .map(|account| account.channel_sequence_number())
            .unwrap_or(0))
    }

    pub fn channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self
            .channel_account_resource(participant)?
            .map(|account| account.balance())
            .unwrap_or(0))
    }

    pub fn get_txn_by_channel_sequence_number(
        &self,
        participant_address: AccountAddress,
        channel_seq_number: u64,
    ) -> Result<SignedChannelTransaction> {
        let txn = self.with_channel(&participant_address, |channel| {
            channel.get_txn_by_channel_seq_number(channel_seq_number)
        })?;
        Ok(txn.signed_transaction)
    }

    /// return all channels' state infos
    pub fn channel_infos(&self) -> HashMap<AccountAddress, ChannelInfo> {
        let channels = self.channels.read().unwrap();
        channels
            .iter()
            .map(|(ap, channel)| (ap.clone(), channel.channel_info()))
            .collect::<HashMap<_, _>>()
    }

    fn exist_channel(&self, participant: &AccountAddress) -> bool {
        self.channels
            .read()
            .unwrap()
            .deref()
            .contains_key(participant)
    }

    fn new_channel(&self, participant: AccountAddress) {
        let mut channels = self.channels.write().unwrap();
        channels.insert(
            participant,
            Channel::new(
                self.inner.account,
                participant,
                self.get_channel_db(participant),
            ),
        );
    }

    fn with_channel<T, F>(&self, participant: &AccountAddress, action: F) -> Result<T>
    where
        F: FnOnce(&Channel) -> Result<T>,
    {
        let channels = self.channels.read().unwrap();
        let channel = channels
            .deref()
            .get(participant)
            .ok_or::<Error>(SgError::new_channel_not_exist_error(participant).into())?;
        action(channel)
    }
    fn with_channel_mut<T, F>(&self, participant: &AccountAddress, action: F) -> Result<T>
    where
        F: FnOnce(&mut Channel) -> Result<T>,
    {
        let mut channels = self.channels.write().unwrap();
        let channel = channels
            .deref_mut()
            .get_mut(participant)
            .ok_or::<Error>(SgError::new_channel_not_exist_error(participant).into())?;
        action(channel)
    }

    #[inline]
    fn get_channel_db(&self, participant_address: AccountAddress) -> ChannelDB {
        ChannelDB::new(participant_address, self.sgdb.clone())
    }
}

impl<C> TransactionSigner for Wallet<C>
where
    C: ChainClient + Send + Sync + 'static,
{
    fn sign_txn(&self, raw_txn: RawTransaction) -> Result<SignedTransaction> {
        self.inner.keypair.sign_txn(raw_txn)
    }
}

impl<C> ChannelPayloadSigner for Wallet<C>
where
    C: ChainClient + Send + Sync + 'static,
{
    fn sign_bytes(&self, bytes: Vec<u8>) -> Result<Ed25519Signature> {
        self.inner.keypair.sign_bytes(bytes)
    }
}

pub struct WalletInner<C> {
    account: AccountAddress,
    keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    client: Arc<C>,
    script_registry: Arc<PackageRegistry>,
}

// NOTICE: need to manually implement clone, due to https://github.com/rust-lang/rust/issues/26925
impl<C> Clone for WalletInner<C> {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            keypair: Arc::clone(&self.keypair),
            client: Arc::clone(&self.client),
            script_registry: Arc::clone(&self.script_registry),
        }
    }
}

impl<C> WalletInner<C>
where
    C: ChainClient + Send + Sync + 'static,
{
    pub fn client(&self) -> &dyn ChainClient {
        &*self.client
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.keypair.public_key
    }
    pub fn sequence_number(&self) -> Result<u64> {
        Ok(self.account_resource()?.sequence_number())
    }

    //TODO support more asset type
    pub fn balance(&self) -> Result<u64> {
        self.account_resource().map(|r| r.balance())
    }

    pub fn account_resource(&self) -> Result<AccountResource> {
        // account_resource must exist.
        //TODO handle unwrap
        let account_state = self.client.get_account_state(self.account, None)?;
        let account_resource_bytes = account_state
            .get(&DataPath::account_resource_data_path().to_vec())
            .unwrap();
        account_resource_ext::from_bytes(&account_resource_bytes)
    }

    fn channel_op_to_script(
        &self,
        channel_op: &ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<Script> {
        let script_code = match channel_op {
            ChannelOp::Open => self.script_registry.open_script(),
            ChannelOp::Close => self.script_registry.close_script(),
            ChannelOp::Execute {
                package_name,
                script_name,
            } => self
                .script_registry
                .get_script(package_name, script_name)
                .ok_or(format_err!(
                    "Can not find script by package {} and script name {}",
                    package_name,
                    script_name
                ))?,
        };
        let script = script_code.encode_script(args);
        Ok(script)
    }

    pub(crate) fn build_raw_txn_from_channel_txn(
        &self,
        channel_witness_data: Option<WriteSet>,
        channel_txn: &ChannelTransaction,
        payload_key_and_signature: Option<(Ed25519PublicKey, Ed25519Signature)>,
    ) -> Result<RawTransaction> {
        let script =
            self.channel_op_to_script(channel_txn.operator(), channel_txn.args().to_vec())?;
        let write_set = channel_witness_data.unwrap_or_default();
        let channel_script = ChannelScriptBody::new(
            channel_txn.channel_sequence_number(),
            write_set,
            channel_txn.receiver(),
            script,
        );
        let channel_txn_payload = match payload_key_and_signature {
            Some((public_key, signature)) => {
                // verify first
                public_key.verify_signature(&channel_script.hash(), &signature)?;
                ChannelTransactionPayload::new_with_script(channel_script, public_key, signature)
            }
            None => {
                self.mock_payload_signature(ChannelTransactionPayloadBody::Script(channel_script))
            }
        };
        Ok(RawTransaction::new_payload_txn(
            channel_txn.sender(),
            channel_txn.sequence_number(),
            TransactionPayload::Channel(channel_txn_payload),
            MAX_GAS_AMOUNT_OFFCHAIN,
            GAS_UNIT_PRICE,
            channel_txn.expiration_time(),
        ))
    }
    /// Craft a mocked transaction request.
    pub(crate) fn create_mocked_signed_script_txn(
        &self,
        channel_witness_data: Option<WriteSet>,
        channel_txn: &ChannelTransaction,
    ) -> Result<SignedTransaction> {
        let txn = self.build_raw_txn_from_channel_txn(channel_witness_data, channel_txn, None)?;
        let signed_txn = self.mock_signature(txn)?;
        Ok(signed_txn)
    }

    pub(crate) fn mock_signature(&self, txn: RawTransaction) -> Result<SignedTransaction> {
        // execute txn on offchain vm, should mock sender and receiver signature with a local
        // keypair. the vm will skip signature check on offchain vm.
        let signed_txn = self.keypair.sign_txn(txn)?;
        Ok(signed_txn)
    }

    fn mock_payload_signature(
        &self,
        payload_body: ChannelTransactionPayloadBody,
    ) -> ChannelTransactionPayload {
        payload_body.sign(&self.keypair.private_key, self.keypair.public_key.clone())
    }

    pub async fn submit_transaction(
        &self,
        signed_transaction: SignedTransaction,
    ) -> Result<TransactionWithProof> {
        let raw_txn_hash = signed_transaction.raw_txn().hash();
        debug!("submit_transaction {}", raw_txn_hash);
        let seq_number = signed_transaction.sequence_number();
        let sender = &signed_transaction.sender();
        let _resp = self.client.submit_signed_transaction(signed_transaction)?;
        let watch_future = self.client.watch_transaction(sender, seq_number);
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

    pub fn sign_message(&self, message: &HashValue) -> Ed25519Signature {
        self.keypair.private_key.sign_message(message)
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
