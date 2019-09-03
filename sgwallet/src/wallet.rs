use std::sync::{Arc, Mutex};

use atomic_refcell::AtomicRefCell;
use futures::{
    sync::mpsc::channel,
};
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
    ChannelTransaction, TransactionOutput, TransactionOutputSigner,
};
use star_types::resource::Resource;
use state_store::{StateStore, StateViewPlus};
use types::access_path::AccessPath;
use types::account_address::AccountAddress;
use types::account_config::{account_resource_path, AccountResource, coin_struct_tag};
use types::language_storage::StructTag;
use types::transaction::{Program, RawTransaction, SignedTransaction, TransactionArgument, TransactionStatus};
use types::transaction_helpers::TransactionSigner;
use types::vm_error::*;

use crate::scripts::*;
use crate::transaction_processor::{start_processor, SubmitTransactionFuture, TransactionProcessor};

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
    merged_change_set: Arc<AtomicRefCell<ChangeSet>>,
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
        executor: TaskExecutor,
        account_address: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        client: Arc<C>,
    ) -> Result<Self> {
        let storage = Arc::new(AtomicRefCell::new(LocalStateStorage::new(account_address, client.clone())?));
        let vm = LocalVM::new(storage.clone());
        let script_registry = AssetScriptRegistry::build()?;
        let transaction_processor = Arc::new(Mutex::new(TransactionProcessor::new()));
        start_processor(client.clone(), account_address, transaction_processor.clone());
        Ok(Self {
            account_address,
            keypair,
            client,
            storage,
            vm,
            script_registry,
            txn_processor: transaction_processor,
            merged_change_set: Arc::new(AtomicRefCell::new(ChangeSet::empty())),
        })
    }

    pub fn default_asset() -> StructTag {
        DEFAULT_ASSET.clone()
    }

    fn execute_transaction(&self, transaction: SignedTransaction) -> TransactionOutput {
        let libra_output = self.vm.execute_transaction(transaction);
        TransactionOutput::new(
            self.storage.borrow().write_set_to_change_set(libra_output.write_set()).unwrap(),
            libra_output.events().to_vec(),
            //TODO offchain vm and onchain vm gas.
            0,
            libra_output.status().clone(),
        )
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
        let program = script.encode_program(args);
        let txn = self.create_signed_txn(receiver, program)?;
        let output = self.execute_transaction(txn.clone());
        match output.status() {
            TransactionStatus::Discard(vm_status) => bail!("transaction execute fail for: {:#?}", vm_status),
            _ => {
                //continue
            }
        };
        let output_signature = self.sign_txn_output(&output)?;
        Ok(ChannelTransaction::new(txn, receiver, output, output_signature, self.merged_change_set.borrow().clone()))
    }

    /// Open channel and deposit default asset.
    pub fn open(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        self.execute_script(self.script_registry.open_script(), receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        self.execute_asset_op(&asset_tag, ChannelOp::Deposit, receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit_default(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
        self.deposit(Self::default_asset(), receiver, sender_amount, receiver_amount)
    }

    pub fn transfer(&self, asset_tag: StructTag, receiver: AccountAddress, amount: u64) -> Result<ChannelTransaction> {
        self.execute_asset_op(&asset_tag, ChannelOp::Transfer, receiver, vec![
            TransactionArgument::U64(amount),
        ])
    }

    pub fn transfer_default(&self, receiver: AccountAddress, amount: u64) -> Result<ChannelTransaction> {
        self.transfer(Self::default_asset(), receiver, amount)
    }

    pub fn withdraw(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransaction> {
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

    fn clear_merged_change_set(&self) {
        let mut change_set = self.merged_change_set.borrow_mut();
        *change_set = ChangeSet::empty();
    }

    fn merge_change_set(&self, new_change_set: &ChangeSet) -> Result<()> {
        let mut change_set = self.merged_change_set.borrow_mut();
        *change_set = ChangeSet::merge(&*change_set, new_change_set)?;
        Ok(())
    }

    pub async fn apply_txn(&self, txn: &ChannelTransaction) -> Result<()> {
        //TODO verify signature
        if txn.is_travel_txn() {
            self.submit_channel_transaction(txn.clone()).await?;
            self.clear_merged_change_set();
            self.storage.borrow().apply_txn(txn)?;
        } else {
            self.merge_change_set(txn.output().change_set())?;
            self.storage.borrow().apply_txn(txn)?;
        }
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
    fn create_signed_txn(
        &self,
        receiver: AccountAddress,
        program: Program,
    ) -> Result<SignedTransaction> {
        let mut txn = types::transaction_helpers::create_signed_txn(
            self,
            program,
            self.account_address,
            self.sequence_number(),
            Self::MAX_GAS_AMOUNT,
            Self::GAS_UNIT_PRICE,
            Self::TXN_EXPIRATION,
        )?;
        txn.set_receiver(receiver);
        Ok(txn)
    }

    pub fn get_address(&self) -> AccountAddress {
        self.account_address
    }

    pub async fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<SignedTransaction> {
        let raw_tx = signed_transaction.clone().into_raw_transaction();
        let tx_hash = raw_tx.hash();

        let _resp = self.client.submit_transaction(signed_transaction)?;

        let (tx, rx) = channel(1);
        let watch_future = SubmitTransactionFuture::new(rx);

        self.txn_processor.lock().unwrap().add_future(tx_hash, tx);

        let tx_return = watch_future.compat().await;

        Ok(tx_return.unwrap())
    }

    pub async fn submit_channel_transaction(&self, channel_transaction: ChannelTransaction) -> Result<SignedTransaction> {
        let raw_tx = channel_transaction.txn().clone().into_raw_transaction();
        let tx_hash = raw_tx.hash();

        let _resp = self.client.submit_channel_transaction(channel_transaction)?;

        let (tx, rx) = channel(1);
        let watch_future = SubmitTransactionFuture::new(rx);

        self.txn_processor.lock().unwrap().add_future(tx_hash, tx);

        let tx_return = watch_future.compat().await;
        Ok(tx_return.unwrap())
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

impl<C> TransactionOutputSigner for Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    fn sign_txn_output(&self, txn_output: &TransactionOutput) -> Result<Ed25519Signature> {
        let bytes = transaction_output_helper::into_pb(txn_output.clone()).unwrap().write_to_bytes()?;
        //TODO use another hash.
        let mut hasher = TestOnlyHasher::default();
        hasher.write(bytes.as_slice());
        let hash = hasher.finish();
        let signature = self.keypair.private_key.sign_message(&hash);
        Ok(signature)
    }
}
