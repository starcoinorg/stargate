use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use atomic_refcell::AtomicRefCell;
use futures::{sync::mpsc::channel};
use tokio::{runtime::TaskExecutor};

use canonical_serialization::SimpleSerializer;
use chain_client::{ChainClient, RpcChainClient, StarClient};
use config::config::VMConfig;
use crypto::{HashValue, SigningKey, VerifyingKey};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crypto::hash::{CryptoHash, CryptoHasher, TestOnlyHasher};
use crypto::test_utils::KeyPair;
use failure::prelude::*;
use lazy_static::lazy_static;
use local_state_storage::{Channel, LocalStateStorage, WitnessData};
use logger::prelude::*;
use star_types::{account_resource_ext, transaction_output_helper};
use star_types::channel_transaction::{ChannelOp, ChannelTransactionRequest, ChannelTransactionRequestAndOutput, ChannelTransactionRequestPayload, ChannelTransactionResponse, ChannelTransactionResponsePayload, Witness};
use star_types::message::{ErrorMessage, SgError};
use star_types::resource::Resource;
use star_types::resource_type::resource_def::StructDefResolve;
use star_types::sg_error::SgErrorCode;
use state_store::{StateStore, StateViewPlus};
use state_view::StateView;
use types::access_path::{AccessPath, DataPath};
use types::account_address::AccountAddress;
use types::account_config::{account_resource_path, AccountResource, coin_struct_tag};
use types::channel_account::{channel_account_resource_path, channel_account_struct_tag, ChannelAccountResource};
use types::language_storage::StructTag;
use types::proof::{AccumulatorProof, SignedTransactionProof};
use types::transaction::{ChannelScriptPayload, ChannelWriteSetPayload, Program, RawTransaction, Script, SignedTransaction, SignedTransactionWithProof, TransactionArgument, TransactionInfo, TransactionOutput, TransactionPayload, TransactionStatus, Version};
use types::transaction_helpers::{ChannelPayloadSigner, TransactionSigner};
use types::vm_error::*;
use types::write_set::{WriteOp, WriteSet};
use vm_runtime::{MoveVM, VMExecutor};

use std::time::{Duration, Instant};
use tokio::timer::{Interval,Delay};

use {
    futures_03::{
        compat::{Future01CompatExt,Stream01CompatExt},
        future::{FutureExt, TryFutureExt},
        stream::{StreamExt},
    },
};

use crate::scripts::*;
use crate::transaction_processor::{start_processor, SubmitTransactionFuture, TransactionProcessor};

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
    storage: Arc<AtomicRefCell<LocalStateStorage<C>>>,
    script_registry: AssetScriptRegistry,
    txn_processor: Arc<Mutex<TransactionProcessor>>,
    lock: futures_locks::Mutex<u64>,
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
    ) -> Result<Wallet<StarClient>> {
        let client = Arc::new(StarClient::new(rpc_host, rpc_port));
        Wallet::new_with_client(executor, account_address, keypair, client)
    }

    pub fn new_with_client(
        _executor: TaskExecutor,
        account_address: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        client: Arc<C>,
    ) -> Result<Self> {
        let storage = Arc::new(AtomicRefCell::new(LocalStateStorage::new(account_address, client.clone())?));
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
            lock: futures_locks::Mutex::new(1),
        })
    }

    fn watch_address(&self, account_address: AccountAddress) -> Result<()> {
        start_processor(self.client.clone(), account_address, self.txn_processor.clone())
    }

    pub fn default_asset() -> StructTag {
        DEFAULT_ASSET.clone()
    }

    fn execute_transaction(&self, state_view: &dyn StateView, transaction: SignedTransaction) -> Result<TransactionOutput> {
        let tx_hash = transaction.raw_txn().hash();
        let output = MoveVM::execute_block(vec![transaction], &VM_CONFIG, state_view).pop().unwrap();
        debug!("execute txn:{} output: {}", tx_hash, output);
        match output.status() {
            TransactionStatus::Discard(vm_status) => bail!("transaction execute fail for: {:#?}", vm_status),
            TransactionStatus::Keep(vm_status) => match vm_status.major_status {
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

    fn execute_asset_op(&self, channel: &Channel, asset_tag: &StructTag, op: ChannelOp, receiver: AccountAddress, args: Vec<TransactionArgument>) -> Result<ChannelTransactionRequest> {
        let scripts = self.script_registry.get_scripts(&asset_tag).ok_or(format_err!("Unsupported asset {:?}", asset_tag))?;
        let script = scripts.get_script(op);
        self.execute_script(channel, script, receiver, args)
    }

    fn execute_script(&self, channel: &Channel, script: &ScriptCode, receiver: AccountAddress, args: Vec<TransactionArgument>) -> Result<ChannelTransactionRequest> {
        let program = script.encode_script(args);
        let channel_sequence_number = channel.channel_sequence_number();
        let txn = self.create_signed_script_txn(channel, receiver, program)?;
        let storage = self.storage.borrow();
        let state_view = storage.new_state_view(None, &receiver)?;
        let output = self.execute_transaction(&state_view, txn.clone())?;

        let payload = if output.is_travel_txn() {
            let write_set_bytes: Vec<u8> = SimpleSerializer::serialize(output.write_set())?;
            let txn_write_set_hash = HashValue::from_sha3_256(write_set_bytes.as_slice());
            let txn_signature = txn.signature();
            ChannelTransactionRequestPayload::Travel { txn_write_set_hash, txn_signature }
        } else {
            let witness_payload = ChannelWriteSetPayload::new(channel_sequence_number, output.write_set().clone(), receiver);
            let witness_signature = self.sign_write_set_payload(&witness_payload)?;
            let witness = Witness {
                witness_payload,
                witness_signature,
            };
            ChannelTransactionRequestPayload::Offchain(witness)
        };
        let version = state_view.version();
        let request = ChannelTransactionRequest::new(version, script.script_type(), txn.raw_txn().clone(), payload, self.keypair.public_key.clone());
        channel.append_txn_request(ChannelTransactionRequestAndOutput::new(request.clone(), output))?;
        Ok(request)
    }

    /// Verify channel participant's txn
    pub fn verify_txn(&self, txn_request: &ChannelTransactionRequest) -> Result<ChannelTransactionResponse> {
        let txn_hash = txn_request.txn().hash();
        debug!("verify_txn {}", txn_hash);
        ensure!(txn_request.receiver() == self.account_address, "check receiver fail.");
        let sender = txn_request.sender();
        if txn_request.operator().is_open() {
            if self.storage.borrow().exist_channel(&sender) {
                bail!("Channel with address {} exist.", sender);
            }
            self.storage.borrow_mut().new_channel(sender);
            self.watch_address(sender)?;
        }

        let storage = self.storage.borrow();
        let channel = storage.get_channel(&sender)?;

        ensure!(channel.channel_sequence_number() == txn_request.channel_sequence_number(), "check channel_sequence_number fail.");
        let signed_txn = self.mock_signature(txn_request.txn().clone())?;
        let version = txn_request.version();
        let state_view = storage.new_state_view(Some(version), &sender)?;
        let txn_payload_signature = signed_txn.receiver_signature().expect("signature must exist.");
        let output = self.execute_transaction(&state_view, signed_txn)?;
        //TODO verify output.
        channel.append_txn_request(ChannelTransactionRequestAndOutput::new(txn_request.clone(), output.clone()))?;
        let write_set = output.write_set();
        //TODO check public_key match with sender address.
        let payload = match txn_request.payload() {
            ChannelTransactionRequestPayload::Offchain(sender_witness) => {
                let sender_payload = &sender_witness.witness_payload;
                ensure!(write_set == &sender_payload.write_set, "check write_set fail.");
                txn_request.public_key()
                    .verify_signature(&sender_payload.hash(), &sender_witness.witness_signature)?;
                let witness_payload = ChannelWriteSetPayload::new(sender_payload.channel_sequence_number, write_set.clone(), self.account_address);
                let witness_signature = self.sign_write_set_payload(&witness_payload)?;
                let new_witness = Witness {
                    witness_payload,
                    witness_signature,
                };
                ChannelTransactionResponsePayload::Offchain(new_witness)
            }
            ChannelTransactionRequestPayload::Travel { txn_write_set_hash, txn_signature } => {
                let write_set_bytes: Vec<u8> = SimpleSerializer::serialize(output.write_set())?;
                let new_txn_write_set_hash = HashValue::from_sha3_256(write_set_bytes.as_slice());
                ensure!(txn_write_set_hash == &new_txn_write_set_hash, "check write_set fail");
                txn_request.public_key()
                    .verify_signature(&txn_hash, txn_signature)?;
                ChannelTransactionResponsePayload::Travel { txn_payload_signature }
            }
        };
        Ok(ChannelTransactionResponse::new(txn_request.request_id(), txn_request.channel_sequence_number(), payload, self.keypair.public_key.clone()))
    }

    /// Open channel and deposit default asset.
    pub fn open(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransactionRequest> {
        info!("wallet.open receiver:{}, sender_amount:{}, receiver_amount:{}", receiver, sender_amount, receiver_amount);
        if self.storage.borrow().exist_channel(&receiver) {
            bail!("Channel with address {} exist.", receiver);
        }
        self.storage.borrow_mut().new_channel(receiver);
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        //TODO watch when channel is establish and track watch thead.
        self.watch_address(receiver)?;
        self.execute_script(channel, self.script_registry.open_script(), receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit_by_tag(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransactionRequest> {
        info!("wallet.deposit asset_tag:{:?}, receiver:{}, sender_amount:{}, receiver_amount:{}", &asset_tag, receiver, sender_amount, receiver_amount);
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute_asset_op(channel, &asset_tag, ChannelOp::Deposit, receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn deposit(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransactionRequest> {
        self.deposit_by_tag(Self::default_asset(), receiver, sender_amount, receiver_amount)
    }

    pub fn transfer_by_tag(&self, asset_tag: StructTag, receiver: AccountAddress, amount: u64) -> Result<ChannelTransactionRequest> {
        info!("wallet.deposit asset_tag:{:?}, receiver:{}, amount:{}", &asset_tag, receiver, amount);
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute_asset_op(channel, &asset_tag, ChannelOp::Transfer, receiver, vec![
            TransactionArgument::U64(amount),
        ])
    }

    pub fn transfer(&self, receiver: AccountAddress, amount: u64) -> Result<ChannelTransactionRequest> {
        self.transfer_by_tag(Self::default_asset(), receiver, amount)
    }

    pub fn withdraw_by_tag(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransactionRequest> {
        info!("wallet.withdraw asset_tag:{:?}, receiver:{}, sender_amount:{}, receiver_amount:{}", &asset_tag, receiver, sender_amount, receiver_amount);
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute_asset_op(channel, &asset_tag, ChannelOp::Withdraw, receiver, vec![
            TransactionArgument::U64(sender_amount),
            TransactionArgument::U64(receiver_amount),
        ])
    }

    pub fn withdraw(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<ChannelTransactionRequest> {
        self.withdraw_by_tag(Self::default_asset(), receiver, sender_amount, receiver_amount)
    }

    pub fn close(&self, receiver: AccountAddress) -> Result<ChannelTransactionRequest> {
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute_script(channel, self.script_registry.close_script(), receiver, vec![])
    }

    pub async fn apply_txn(&self, participant: AccountAddress, response: &ChannelTransactionResponse) -> Result<u64> {
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&participant)?;
        let (request, output) = match channel.pending_txn_request() {
            Some(ChannelTransactionRequestAndOutput { request, output }) => (request, output),
            //TODO(jole) can not find request has such reason:
            // 1. txn is expire.
            // 2. txn is invalid.
            None => bail!("pending_txn_request must exist at stage:{:?}", channel.stage())
        };
        let raw_txn_hash = request.txn().hash();
        info!("apply_txn: {}", raw_txn_hash);
        ensure!(request.channel_sequence_number() == response.channel_sequence_number(), "check channel_sequence_number fail.");
        let gas = match (request.payload(), response.payload()) {
            (ChannelTransactionRequestPayload::Travel { txn_write_set_hash, txn_signature },
                ChannelTransactionResponsePayload::Travel { txn_payload_signature }) => {
                let mut signed_txn = SignedTransaction::new(request.txn().clone(), request.public_key().clone(), txn_signature.clone());
                signed_txn.set_receiver_public_key_and_signature(response.public_key().clone(), txn_payload_signature.clone());
                let txn_with_proof = if request.sender() == self.account_address {
                    // sender submit transaction to chain.
                    self.submit_transaction(signed_txn).await?
                } else {
                    self.watch_transaction_loop(signed_txn.sequence_number()).await?
                };
                //self.check_output(&output)?;
                let gas = txn_with_proof.proof.transaction_info().gas_used();
//                let version = txn_with_proof.version;
//                let account_state = self.storage.borrow().get_account_state(self.account_address, Some(version))?;
//                let participant_state = self.storage.borrow().get_account_state(participant, Some(version))?;
//                let account_channel_state = account_state.filter_channel_state().remove(&participant).unwrap();
//                let participant_channel_state = participant_state.filter_channel_state().remove(&self.account_address).unwrap();
//                channel.apply_state(account_channel_state, participant_channel_state)?;
                channel.apply_output(output)?;
                gas
            }
            (ChannelTransactionRequestPayload::Offchain(sender_witness),
                ChannelTransactionResponsePayload::Offchain(receiver_witness)) => {
                if request.sender() == self.account_address {
                    channel.apply_witness(receiver_witness.witness_payload.clone(), receiver_witness.witness_signature.clone())?;
                } else {
                    channel.apply_witness(sender_witness.witness_payload.clone(), sender_witness.witness_signature.clone())?;
                }
                0
            }
            _ => bail!("ChannelTransaction request and response type not match.")
        };
        Ok(gas)
    }

    fn check_output(&self, output: &TransactionOutput) -> Result<()> {
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
        let data_path = DataPath::from(path)?;
        self.storage.borrow().get(&data_path)
    }

    pub fn account_resource(&self) -> Result<AccountResource> {
        // account_resource must exist.
        //TODO handle unwrap
        self.get(&account_resource_path())
            .and_then(|value| account_resource_ext::from_bytes(&value.unwrap()))
    }

    pub fn channel_account_resource(&self, participant: AccountAddress) -> Result<Option<ChannelAccountResource>> {
        self.get(&channel_account_resource_path(participant)).and_then(|value| match value {
            Some(value) => Ok(Some(ChannelAccountResource::make_from(value)?)),
            None => Ok(None),
        })
    }

    pub fn channel_sequence_number(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self.channel_account_resource(participant)?.map(|account| account.channel_sequence_number()).unwrap_or(0))
    }

    pub fn sequence_number(&self) -> Result<u64> {
        Ok(self.account_resource()?.sequence_number())
    }

    //TODO support more asset type
    pub fn balance(&self) -> Result<u64> {
        self.account_resource().map(|r| r.balance())
    }

    fn get_resource(&self, path: &DataPath) -> Result<Option<Resource>> {
        let storage = self.storage.borrow();
        storage.get_resource(path)
    }

    fn get_channel_resource(&self, participant: AccountAddress, resource_tag: StructTag) -> Result<Option<Resource>> {
        let data_path = DataPath::channel_resource_path(participant, resource_tag);
        self.get_resource(&data_path)
    }

    pub fn channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self.channel_account_resource(participant)?.map(|account| account.balance()).unwrap_or(0))
    }

    pub fn channel_balance_by_tag(&self, participant: AccountAddress, asset_tag: StructTag) -> Result<u64> {
        if asset_tag == Self::default_asset() {
            self.channel_balance(participant)
        } else {
            self.get_channel_resource(participant, asset_tag.clone())
                .and_then(|resource| match resource {
                    Some(resource) => resource.asset_balance().ok_or(format_err!("resource {:?} not asset.", asset_tag)),
                    //if channel or resource not exist, take default value 0
                    None => Ok(0)
                })
        }
    }

    /// Craft a transaction request.
    fn create_signed_script_txn(
        &self,
        channel: &Channel,
        receiver: AccountAddress,
        script: Script,
    ) -> Result<SignedTransaction> {
        let WitnessData { channel_sequence_number: _, write_set, signature: _ } = channel.witness_data();
        let channel_script = ChannelScriptPayload::new(channel.channel_sequence_number(), write_set, receiver, script);
        let txn = types::transaction_helpers::create_unsigned_payload_txn(
            TransactionPayload::ChannelScript(channel_script),
            self.account_address,
            self.sequence_number()?,
            Self::MAX_GAS_AMOUNT,
            Self::GAS_UNIT_PRICE,
            Self::TXN_EXPIRATION,
        );
        let signed_txn = self.mock_signature(txn)?;
        Ok(signed_txn)
    }

    fn mock_signature(&self, txn: RawTransaction) -> Result<SignedTransaction> {
        // execute txn on offchain vm, should mock sender and receiver signature with a local keypair.
        // the vm will skip signature check on offchain vm.
        let mut signed_txn = self.sign_txn(txn)?;
        signed_txn.sign_by_receiver(&self.keypair.private_key, self.keypair.public_key.clone())?;
        Ok(signed_txn)
    }

    pub fn get_address(&self) -> AccountAddress {
        self.account_address
    }

    pub async fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<SignedTransactionWithProof> {
        let raw_txn_hash = signed_transaction.raw_txn().hash();
        debug!("submit_transaction {}", raw_txn_hash);
        let seq_number = signed_transaction.sequence_number();
        let _resp = self.client.submit_transaction(signed_transaction)?;
        let watch_future = self.watch_transaction_loop(seq_number);
        watch_future.await
        //Ok(Self::convert(txn,output))
    }

    fn do_watch_transaction(&self, raw_txn_hash: HashValue) -> SubmitTransactionFuture {
        debug!("watch_transaction {}", raw_txn_hash);
        let (tx, rx) = channel(1);
        let watch_future = SubmitTransactionFuture::new(rx);
        self.txn_processor.lock().unwrap().add_future(raw_txn_hash, tx);
        watch_future
    }

    pub async fn watch_transaction(&self, raw_tx_hash: HashValue) -> Result<SignedTransactionWithProof> {
        let watch_future = self.do_watch_transaction(raw_tx_hash);
        let (txn, output) = watch_future.compat().await?;
        Ok(Self::convert(txn,output))
    }

    fn convert(txn: SignedTransaction, output: TransactionOutput) -> SignedTransactionWithProof {
        let major_status = match output.status() {
            TransactionStatus::Keep(status) => status.major_status,
            TransactionStatus::Discard(status) => status.major_status,
        };
        let txn_hash = txn.hash();
        SignedTransactionWithProof {
            version: 0,
            signed_transaction: txn,
            events: None,
            proof: SignedTransactionProof::new(AccumulatorProof::new(vec![]), TransactionInfo::new(
                txn_hash, HashValue::random(), HashValue::random(), output.gas_used(), major_status,
            )),
        }
    }

    pub async fn watch_transaction_loop(&self, seq:u64) -> Result<SignedTransactionWithProof> {
        loop {
            let timeout_time = Instant::now() + Duration::from_millis(1000);
            if let Ok(_) = Delay::new(timeout_time).compat().await {
                info!("seq number is {}",seq);
                let result=self.client.get_transaction_by_seq_num(&self.account_address,seq);
                info!("result is {:?}",result);
                match result {
                    Ok(None) =>{
                        continue;
                    },
                    Ok(Some(t))=>{
                        return Ok(t);
                    },
                    Err(e) => {
                        return Err(e);
                    }
                    _ => {}
                }
            };
        }
    }

}

impl<C> TransactionSigner for Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    fn sign_txn(&self, raw_txn: RawTransaction) -> Result<SignedTransaction> {
        self.keypair.sign_txn(raw_txn)
    }
}

impl<C> ChannelPayloadSigner for Wallet<C>
    where
        C: ChainClient + Send + Sync + 'static,
{
    fn sign_bytes(&self, bytes: Vec<u8>) -> Result<Ed25519Signature> {
        self.keypair.sign_bytes(bytes)
    }
}