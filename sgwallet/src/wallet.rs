use std::sync::{Arc, Mutex};

use atomic_refcell::AtomicRefCell;
use futures::{sync::mpsc::channel};
use protobuf::Message;
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
use local_state_storage::LocalStateStorage;
use local_vm::LocalVM;
use logger::prelude::*;
use star_types::{account_resource_ext, transaction_output_helper};
use star_types::change_set::ChangeSet;
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
use types::write_set::WriteSet;
use std::collections::{HashMap, HashSet};

lazy_static! {
    pub static ref DEFAULT_ASSET:StructTag = coin_struct_tag();
}

pub struct Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    account_address: AccountAddress,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    client: Arc<C>,
    storage: Arc<AtomicRefCell<LocalStateStorage<C>>>,
    vm: LocalVM<LocalStateStorage<C>>,
    script_registry: AssetScriptRegistry,
    txn_processor: Arc<Mutex<TransactionProcessor>>,
    //TODO save write_sets with channel state.
    witness_data: Arc<AtomicRefCell<HashMap<AccountAddress,(ChannelWriteSetPayload, Ed25519Signature)>>>,
    //TODO save channels with channel state.
    channels: Arc<AtomicRefCell<HashSet<AccountAddress>>>,
}

impl<C> Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    const TXN_EXPIRATION: i64 = 1000 * 60;
    const MAX_GAS_AMOUNT: u64 = 1000000;
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
        let storage = Arc::new(AtomicRefCell::new(LocalStateStorage::new(account_address, client.clone())?));
        let vm = LocalVM::new(storage.clone());
        let script_registry = AssetScriptRegistry::build()?;
        let transaction_processor = Arc::new(Mutex::new(TransactionProcessor::new()));
        start_processor(client.clone(), account_address, transaction_processor.clone())?;
        Ok(Self {
            account_address,
            keypair,
            client,
            storage,
            vm,
            script_registry,
            txn_processor: transaction_processor,
            witness_data: Arc::new(AtomicRefCell::new(HashMap::new())),
            channels: Arc::new(AtomicRefCell::new(HashSet::new())),
        })
    }

    fn watch_address(&self,account_address:AccountAddress)->Result<()>{
        start_processor(self.client.clone(), account_address, self.txn_processor.clone())
    }

    pub fn default_asset() -> StructTag {
        DEFAULT_ASSET.clone()
    }

    fn execute_transaction(&self, transaction: SignedTransaction) -> Result<TransactionOutput> {
        let tx_hash = transaction.raw_txn().hash();
        let output = self.vm.execute_transaction(transaction);
        debug!("execute txn:{} output: {}", tx_hash, output);
        match output.status() {
            TransactionStatus::Discard(vm_status) => bail!("transaction execute fail for: {:#?}", vm_status),
            _ => {
                //continue
            }
        };
        Ok(output)
    }

    pub fn validate_transaction(&self, transaction: SignedTransaction) -> Option<VMStatus> {
        self.vm.validate_transaction(transaction)
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
        //TODO read sequence number from channel state.
        let channel_sequence_number = 0;
        let txn = self.create_signed_script_txn(channel_sequence_number, receiver, program)?;
        let output = self.execute_transaction(txn.clone())?;
        //TODO handle travel txn
        let write_set = output.write_set();
        let witness_payload = ChannelWriteSetPayload::new(channel_sequence_number, write_set.clone(), receiver);
        let signature = self.sign_write_set_payload(&witness_payload)?;
        Ok(ChannelTransaction::new(txn, witness_payload, signature))
    }

    /// Verify channel participant's txn
    pub fn verify_txn(&self, channel_txn: &ChannelTransaction) -> Result<ChannelTransaction> {
        debug!("verify_txn {}", channel_txn.txn().raw_txn().hash());
        ensure!(channel_txn.receiver() == self.account_address, "check receiver fail.");
        let sender = channel_txn.txn.sender();
        if !self.channels.borrow().contains(&sender){
            self.channels.borrow_mut().insert(sender);
            self.watch_address(sender)?;
        }
        let mut txn = channel_txn.txn().clone();
        let txn_signature = self.sign_script_payload(channel_txn.channel_script_payload().ok_or(format_err!("txn must be channel script txn."))?)?;
        txn.set_receiver_public_key_and_signature(self.keypair.public_key.clone(), txn_signature);

        let output = self.execute_transaction(txn.clone())?;
        let write_set = output.write_set();
        let sender_payload = channel_txn.witness_payload();
        ensure!(write_set == &sender_payload.write_set, "check write_set fail.");
        let witness_payload = ChannelWriteSetPayload::new(sender_payload.channel_sequence_number, write_set.clone(), sender);
        let witness_signature = self.sign_write_set_payload(&witness_payload)?;

        Ok(ChannelTransaction::new(txn, witness_payload, witness_signature))
    }

    /// Open channel and deposit default asset.
    pub fn open(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.open receiver:{}, sender_amount:{}, receiver_amount:{}", receiver, sender_amount, receiver_amount);
        if self.channels.borrow().contains(&receiver){
            bail!("Channel with address {} exist.", receiver);
        }
        //TODO watch when channel is establish.
        self.channels.borrow_mut().insert(receiver);
        self.watch_address(receiver)?;
        self.execute_script(self.script_registry.open_script(), receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.deposit asset_tag:{:?}, receiver:{}, sender_amount:{}, receiver_amount:{}", &asset_tag, receiver, sender_amount, receiver_amount);
        self.execute_asset_op(&asset_tag, ChannelOp::Deposit, receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit_default(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        self.deposit(Self::default_asset(), receiver, sender_amount, receiver_amount)
    }

    pub fn transfer(&self, asset_tag: StructTag, receiver: AccountAddress, amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.deposit asset_tag:{:?}, receiver:{}, amount:{}", &asset_tag, receiver, amount);
        self.execute_asset_op(&asset_tag, ChannelOp::Transfer, receiver, vec![
            TransactionArgument::U64(amount),
        ])
    }

    pub fn transfer_default(&self, receiver: AccountAddress, amount: u64) -> Result<ChannelTransaction> {
        self.transfer(Self::default_asset(), receiver, amount)
    }

    pub fn withdraw(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        info!("wallet.withdraw asset_tag:{:?}, receiver:{}, sender_amount:{}, receiver_amount:{}", &asset_tag, receiver, sender_amount, receiver_amount);
        self.execute_asset_op(&asset_tag, ChannelOp::Withdraw, receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn withdraw_default(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        self.withdraw(Self::default_asset(), receiver, sender_amount, receiver_amount)
    }

    pub fn close(&self, receiver: AccountAddress) -> Result<ChannelTransaction> {
        //TODO implements script.
        self.execute_script(self.script_registry.close_script(), receiver, vec![])
    }

    fn clear_witness_data(&self, participant: AccountAddress) {
        let mut witness_data = self.witness_data.borrow_mut();
        witness_data.remove(&participant);
    }

    fn get_witness_data(&self, participant: AccountAddress) -> Option<(ChannelWriteSetPayload,Ed25519Signature)> {
        let witness_data = self.witness_data.borrow();
        witness_data.get(&participant).cloned()
    }

    fn set_witness_data(&self, participant: AccountAddress, witness_payload: ChannelWriteSetPayload, witness_signature: Ed25519Signature){
        let mut witness_data = self.witness_data.borrow_mut();
        witness_data.insert(participant, (witness_payload, witness_signature));
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
        let output = if txn.is_travel_txn() {
            let (_,output) = if txn_sender == self.account_address {
                // sender submit transaction to channel.
                self.submit_transaction(txn.txn.clone()).await?
            }else{
                self.watch_transaction(txn.txn()).await?
            };
            self.clear_witness_data(participant);
            output
        } else {
            self.set_witness_data(participant, txn.witness_payload.clone(), txn.witness_signature.clone());
            TransactionOutput::new_with_write_set(txn.witness_payload.write_set.clone())
        };
        self.apply_output(&output)?;
        Ok(output)
    }

    fn apply_output(&self, output:&TransactionOutput) -> Result<()>{
        info!("apply_output: {}", output);
        if let TransactionStatus::Discard(vm_status) = output.status() {
            bail!("transaction execute fail for: {:#?}", vm_status)
        }
        self.storage.borrow().apply_libra_output(output)?;
        Ok(())
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.storage.borrow().get_by_path(path)
    }

    pub fn get_account_state(&self) -> Vec<u8> {
        self.storage.borrow().get_account_state()
    }

    pub fn account_resource(&self) -> AccountResource {
        // account_resource must exist.
        self.get(&account_resource_path())
            .and_then(|value| account_resource_ext::from_bytes(&value).ok())
            .unwrap()
    }

    pub fn sequence_number(&self) -> u64 {
        self.account_resource().sequence_number()
    }

    //TODO support more asset type
    pub fn balance(&self) -> u64 {
        self.account_resource().balance()
    }

    pub fn get_resource(&self, access_path: &AccessPath) -> Result<Option<Resource>> {
        self.storage.borrow().get_resource(&access_path)
    }

    pub fn get_channel_resource(&self, participant: AccountAddress, resource_tag: StructTag) -> Result<Option<Resource>> {
        let access_path = AccessPath::channel_resource_access_path(self.account_address, participant, resource_tag);
        self.get_resource(&access_path)
    }

    pub fn channel_balance_default(&self, participant: AccountAddress) -> Result<u64> {
        self.channel_balance(participant, Self::default_asset())
    }

    pub fn channel_balance(&self, participant: AccountAddress, asset_tag: StructTag) -> Result<u64> {
        let access_path = AccessPath::channel_resource_access_path(self.account_address, participant, asset_tag.clone());
        self.get_channel_resource(participant, asset_tag.clone())
            .and_then(|resource| match resource {
                Some(resource) => resource.assert_balance().ok_or(format_err!("resource {:?} not asset.", asset_tag)),
                //if channel or resource not exist, take default value 0
                None => Ok(0)
            })
    }

    /// Craft a transaction request.
    fn create_signed_script_txn(
        &self,
        channel_sequence_number: u64,
        receiver: AccountAddress,
        script: Script,
    ) -> Result<SignedTransaction> {
        let write_set = match self.get_witness_data(receiver){
            Some((payload,_)) => payload.write_set,
            None => WriteSet::default(),
        };
        let channel_script = ChannelScriptPayload::new(channel_sequence_number, write_set, receiver, script);
        let txn = types::transaction_helpers::create_signed_payload_txn(
            self,
            TransactionPayload::ChannelScript(channel_script),
            self.account_address,
            self.sequence_number(),
            Self::MAX_GAS_AMOUNT,
            Self::GAS_UNIT_PRICE,
            Self::TXN_EXPIRATION,
        )?;
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