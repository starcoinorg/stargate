use std::sync::{Arc, Mutex};

use atomic_refcell::AtomicRefCell;
use futures::{sync::mpsc::channel};
use tokio::{runtime::TaskExecutor};

use {
    futures_03::{
        compat::Future01CompatExt,
    },
};
use chain_client::{ChainClient, RpcChainClient};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crypto::hash::{CryptoHash, CryptoHasher, TestOnlyHasher};
use crypto::SigningKey;
use crypto::test_utils::KeyPair;
use failure::prelude::*;
use lazy_static::lazy_static;
use local_state_storage::{LocalStateStorage, WitnessData};
use logger::prelude::*;
use star_types::{account_resource_ext, transaction_output_helper};
use star_types::resource_type::resource_def::{StructDefResolve};
use star_types::channel_transaction::{
    ChannelTransaction,
};
use star_types::resource::Resource;
use state_store::{StateStore, StateViewPlus};
use types::access_path::AccessPath;
use types::account_address::AccountAddress;
use types::account_config::{account_resource_path, AccountResource, coin_struct_tag};
use types::language_storage::StructTag;
use types::transaction::{Program, RawTransaction, SignedTransaction, TransactionArgument, TransactionStatus, ChannelScriptPayload, Script, TransactionPayload, TransactionOutput, ChannelWriteSetPayload};
use types::transaction_helpers::{TransactionSigner, ChannelPayloadSigner};
use types::vm_error::*;

use crate::scripts::*;
use crate::transaction_processor::{start_processor, SubmitTransactionFuture, TransactionProcessor};
use types::write_set::{WriteSet, WriteOp};
use std::collections::{HashMap, HashSet};
use types::channel_account::{ChannelAccountResource, channel_account_struct_tag, channel_account_resource_path};
use vm_runtime::{MoveVM, VMExecutor};
use state_view::StateView;
use config::config::VMConfig;
use star_types::message::{ErrorMessage, SgError};

lazy_static! {
    pub static ref DEFAULT_ASSET:StructTag = coin_struct_tag();
    static ref VM_CONFIG:VMConfig = VMConfig::offchain();
}


pub struct Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    account_address: AccountAddress,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    client: Arc<C>,
    storage: Arc<LocalStateStorage<C>>,
    script_registry: AssetScriptRegistry,
    txn_processor: Arc<Mutex<TransactionProcessor>>,
    lock:futures_locks::Mutex<u64>,
}

impl<C> Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    const TXN_EXPIRATION: i64 = 1000 * 60;
    const MAX_GAS_AMOUNT: u64 = 200000;
    const GAS_UNIT_PRICE: u64 = 1;

    pub fn new(
        executor: TaskExecutor,
        account_address: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        rpc_host: &str,
        rpc_port: u32,
    ) -> Result<Wallet<RpcChainClient>> {
        let client = Arc::new(RpcChainClient::new(rpc_host, rpc_port));
        Wallet::new_with_client(executor, account_address, keypair, client)
    }

    pub fn new_with_client(
        _executor: TaskExecutor,
        account_address: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        client: Arc<C>,
    ) -> Result<Self> {
        let storage = Arc::new(LocalStateStorage::new(account_address, client.clone())?);
        let script_registry = AssetScriptRegistry::build()?;
        let transaction_processor = Arc::new(Mutex::new(TransactionProcessor::new()));
        start_processor(client.clone(), account_address, transaction_processor.clone())?;
        Ok(Self {
            account_address,
            keypair,
            client,
            storage,
            script_registry,
            txn_processor: transaction_processor,
            lock:futures_locks::Mutex::new(1),
        })
    }

    fn watch_address(&self,account_address:AccountAddress)->Result<()>{
        start_processor(self.client.clone(), account_address, self.txn_processor.clone())
    }

    pub fn default_asset() -> StructTag {
        DEFAULT_ASSET.clone()
    }

    fn execute_transaction(&self,state_view: &dyn StateView, transaction: SignedTransaction) -> Result<TransactionOutput> {
        let tx_hash = transaction.raw_txn().hash();
        let output = MoveVM::execute_block(vec![transaction], &VM_CONFIG, state_view).pop().unwrap();
        debug!("execute txn:{} output: {}", tx_hash, output);
        match output.status() {
            TransactionStatus::Discard(vm_status) => bail!("transaction execute fail for: {:#?}", vm_status),
            TransactionStatus::Keep(vm_status) => match vm_status.major_status{
                StatusCode::EXECUTED => {
                    //continue
                }
                _ => {
                    bail!("transaction execute fail for: {:#?}", vm_status)
                }
            },
        };
        Ok(output)
    }

    pub fn get_resources() -> Vec<Resource> {
        unimplemented!()
    }

    fn execute_asset_op(&self, asset_tag: &StructTag, op: ChannelOp, receiver: AccountAddress, args: Vec<TransactionArgument>) -> Result<ChannelTransaction> {
        let scripts = self.script_registry.get_scripts(&asset_tag).ok_or(format_err!("Unsupported asset {:?}", asset_tag))?;
        let script = scripts.get_script(op);
        self.execute_script(script, receiver, args)
    }

    fn execute_script(&self, script: &ScriptCode, receiver: AccountAddress, args: Vec<TransactionArgument>) -> Result<ChannelTransaction> {
        let program = script.encode_script(args);
        let channel_sequence_number = self.channel_sequence_number(receiver)?;
        let txn = self.create_signed_script_txn(channel_sequence_number, receiver, program)?;
        let state_view = self.storage.new_state_view(None)?;
        let output = self.execute_transaction(&state_view,txn.clone())?;
        //TODO handle travel txn
        let write_set = output.write_set();
        let witness_payload = ChannelWriteSetPayload::new(channel_sequence_number, write_set.clone(), receiver);
        let signature = self.sign_write_set_payload(&witness_payload)?;
        Ok(ChannelTransaction::new(state_view.version(), txn, witness_payload, signature))
    }

    /// Verify channel participant's txn
    pub fn verify_txn(&self, channel_txn: &ChannelTransaction) -> Result<ChannelTransaction> {
        debug!("verify_txn {}", channel_txn.txn().raw_txn().hash());
        ensure!(channel_txn.receiver() == self.account_address, "check receiver fail.");
        let sender = channel_txn.txn().sender();
        if !self.storage.exist_channel(&sender){
            self.watch_address(sender)?;
            //return Err(SgError{error_code:0,error_message:"111".to_string()}.into())
        }

        let mut txn = channel_txn.txn().clone();
        let txn_signature = self.sign_script_payload(channel_txn.channel_script_payload().ok_or(format_err!("txn must be channel script txn."))?)?;
        txn.set_receiver_public_key_and_signature(self.keypair.public_key.clone(), txn_signature);
        let version = channel_txn.version();
        let state_view = self.storage.new_state_view(Some(version))?;
        let output = self.execute_transaction(&state_view,txn.clone())?;
        let write_set = output.write_set();
        let sender_payload = channel_txn.witness_payload();
        ensure!(write_set == &sender_payload.write_set, "check write_set fail.");
        let witness_payload = ChannelWriteSetPayload::new(sender_payload.channel_sequence_number, write_set.clone(), sender);
        let witness_signature = self.sign_write_set_payload(&witness_payload)?;

        Ok(ChannelTransaction::new(version, txn, witness_payload, witness_signature))
    }

    /// Open channel and deposit default asset.
    pub fn open(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.open receiver:{}, sender_amount:{}, receiver_amount:{}", receiver, sender_amount, receiver_amount);
        if self.storage.exist_channel(&receiver){
            bail!("Channel with address {} exist.", receiver);
        }
        //TODO watch when channel is establish and track watch thead.
        self.watch_address(receiver)?;
        self.execute_script(self.script_registry.open_script(), receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit_by_tag(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.deposit asset_tag:{:?}, receiver:{}, sender_amount:{}, receiver_amount:{}", &asset_tag, receiver, sender_amount, receiver_amount);
        self.execute_asset_op(&asset_tag, ChannelOp::Deposit, receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        self.deposit_by_tag(Self::default_asset(), receiver, sender_amount, receiver_amount)
    }

    pub fn transfer_by_tag(&self, asset_tag: StructTag, receiver: AccountAddress, amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.deposit asset_tag:{:?}, receiver:{}, amount:{}", &asset_tag, receiver, amount);
        self.execute_asset_op(&asset_tag, ChannelOp::Transfer, receiver, vec![
            TransactionArgument::U64(amount),
        ])
    }

    pub fn transfer(&self, receiver: AccountAddress, amount: u64) -> Result<ChannelTransaction> {
        self.transfer_by_tag(Self::default_asset(), receiver, amount)
    }

    pub fn withdraw_by_tag(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.withdraw asset_tag:{:?}, receiver:{}, sender_amount:{}, receiver_amount:{}", &asset_tag, receiver, sender_amount, receiver_amount);
        self.execute_asset_op(&asset_tag, ChannelOp::Withdraw, receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn withdraw(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        self.withdraw_by_tag(Self::default_asset(), receiver, sender_amount, receiver_amount)
    }

    pub fn close(&self, receiver: AccountAddress) -> Result<ChannelTransaction> {
        //TODO implements script.
        self.execute_script(self.script_registry.close_script(), receiver, vec![])
    }

    pub async fn apply_txn(&self, txn: &ChannelTransaction) -> Result<TransactionOutput> {
        info!("apply_txn: {}", txn.txn().raw_txn().hash());
        let txn_sender = txn.txn().sender();
        let witness_receiver = txn.witness_payload().receiver;
        ensure!(witness_receiver == self.account_address, "unexpect witness_payload receiver: {}", witness_receiver);
        let participant = if txn_sender == self.account_address {
            txn.receiver()
        }else{
            txn.sender()
        };
        //TODO verify signature
        let (execute_onchain,output) = if txn.is_travel_txn() {
            let mut data=self.lock.lock().compat().await.unwrap();
            let (_,output) = if txn_sender == self.account_address {
                // sender submit transaction to chain.
                self.submit_transaction(txn.txn().clone()).await?
            }else{
                self.watch_transaction(txn.txn()).await?
            };
            *data+=1;
            (true, output)
        } else {
            (false, TransactionOutput::new_with_write_set(txn.witness_payload().write_set.clone()))
        };
        self.check_output(&output)?;
        self.storage.apply_witness(participant, execute_onchain, txn.witness_payload().clone(), txn.witness_signature().clone())?;
        Ok(output)
    }

    fn check_output(&self, output:&TransactionOutput) -> Result<()>{
        info!("check_output: {}", output);
        match output.status() {
            TransactionStatus::Discard(vm_status) => {
                bail!("transaction execute fail for: {:#?}", vm_status)
            }
            TransactionStatus::Keep(vm_status) => {
                match &vm_status.major_status {
                    StatusCode::EXECUTED => {}
                    _ => bail!("transaction executed but status code : {:#?}", vm_status)
                }
            }
        }

        Ok(())
    }

    pub fn get(&self, path: &Vec<u8>) -> Result<Option<Vec<u8>>> {
        let state_view = self.storage.new_state_view(None)?;
        state_view.get(&AccessPath::new(self.account_address, path.clone()))
    }

    pub fn account_resource(&self) -> Result<AccountResource> {
        // account_resource must exist.
        //TODO handle unwrap
        self.get(&account_resource_path())
            .and_then(|value| account_resource_ext::from_bytes(&value.unwrap()))
    }

    pub fn channel_account_resource(&self, participant: AccountAddress) -> Result<Option<ChannelAccountResource>> {
        self.get(&channel_account_resource_path(participant)).and_then(|value|match value{
            Some(value) => Ok(Some(ChannelAccountResource::make_from(value)?)),
            None => Ok(None),
        })
    }

    pub fn channel_sequence_number(&self, participant: AccountAddress) -> Result<u64>{
        Ok(self.channel_account_resource(participant)?.map(|account|account.channel_sequence_number()).unwrap_or(0))
    }

    pub fn sequence_number(&self) -> Result<u64> {
        Ok(self.account_resource()?.sequence_number())
    }

    //TODO support more asset type
    pub fn balance(&self) -> Result<u64> {
        self.account_resource().map(|r|r.balance())
    }

    fn get_resource(&self, access_path: &AccessPath) -> Result<Option<Resource>> {
        let state_view = self.storage.new_state_view(None)?;
        state_view.get_resource(access_path)
    }

    pub fn get_channel_resource(&self, participant: AccountAddress, resource_tag: StructTag) -> Result<Option<Resource>> {
        let access_path = AccessPath::channel_resource_access_path(self.account_address, participant, resource_tag);
        self.get_resource(&access_path)
    }

    pub fn channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self.channel_account_resource(participant)?.map(|account|account.balance()).unwrap_or(0))
    }

    pub fn channel_balance_by_tag(&self, participant: AccountAddress, asset_tag: StructTag) -> Result<u64> {
        if asset_tag == Self::default_asset() {
            self.channel_balance(participant)
        }else {
            self.get_channel_resource(participant, asset_tag.clone())
                .and_then(|resource| match resource {
                    Some(resource) => resource.assert_balance().ok_or(format_err!("resource {:?} not asset.", asset_tag)),
                    //if channel or resource not exist, take default value 0
                    None => Ok(0)
                })
        }
    }

    /// Craft a transaction request.
    fn create_signed_script_txn(
        &self,
        channel_sequence_number: u64,
        receiver: AccountAddress,
        script: Script,
    ) -> Result<SignedTransaction> {
        let WitnessData{channel_sequence_number:_,write_set,signature} = self.storage.get_witness_data(receiver)?;
        let channel_script = ChannelScriptPayload::new(channel_sequence_number, write_set, receiver, script);
        let mut txn = types::transaction_helpers::create_signed_payload_txn(
            self,
            TransactionPayload::ChannelScript(channel_script),
            self.account_address,
            self.sequence_number()?,
            Self::MAX_GAS_AMOUNT,
            Self::GAS_UNIT_PRICE,
            Self::TXN_EXPIRATION,
        )?;
        //TODO mock signature.
        txn.sign_by_receiver(&self.keypair.private_key, self.keypair.public_key.clone())?;
        Ok(txn)
    }

    pub fn get_address(&self) -> AccountAddress {
        self.account_address
    }

    pub async fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<(SignedTransaction,TransactionOutput)> {
        debug!("submit_transaction {}", signed_transaction.raw_txn().hash());
        let watch_future = self.do_watch_transaction(&signed_transaction);
        let _resp = self.client.submit_transaction(signed_transaction)?;
        let tx_return = watch_future.compat().await;
        Ok(tx_return?)
    }

    fn do_watch_transaction(&self, signed_transaction: &SignedTransaction) -> SubmitTransactionFuture {
        let tx_hash = signed_transaction.raw_txn().hash();
        debug!("watch_transaction {}", signed_transaction.raw_txn().hash());
        let (tx, rx) = channel(1);
        let watch_future = SubmitTransactionFuture::new(rx);
        self.txn_processor.lock().unwrap().add_future(tx_hash, tx);
        watch_future
    }

    pub async fn watch_transaction(&self, signed_transaction: &SignedTransaction) -> Result<(SignedTransaction,TransactionOutput)> {
        let watch_future = self.do_watch_transaction(&signed_transaction);
        let tx_return = watch_future.compat().await;
        Ok(tx_return?)
    }

}

impl<C> TransactionSigner for Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    fn sign_txn(&self, raw_txn: RawTransaction) -> Result<SignedTransaction> {
        assert_eq!(self.account_address, raw_txn.sender());
        self.keypair.sign_txn(raw_txn)
    }
}

impl<C> ChannelPayloadSigner for  Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    fn sign_bytes(&self, bytes: Vec<u8>) -> Result<Ed25519Signature> {
        self.keypair.sign_bytes(bytes)
    }
}