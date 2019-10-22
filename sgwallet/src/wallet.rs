// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::scripts::*;
use atomic_refcell::AtomicRefCell;
use canonical_serialization::SimpleSerializer;
use chrono::Utc;
use config::config::VMConfig;
use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, VerifyingKey,
};
use failure::prelude::*;
use lazy_static::lazy_static;
use libra_types::write_set::WriteSet;
use libra_types::{
    access_path::DataPath,
    account_address::AccountAddress,
    account_config::{account_resource_path, coin_struct_tag, AccountResource},
    channel_account::{channel_account_resource_path, ChannelAccountResource},
    language_storage::StructTag,
    transaction::{
        ChannelScriptPayload, ChannelWriteSetPayload, Module, RawTransaction, SignedTransaction,
        SignedTransactionWithProof, TransactionArgument, TransactionOutput, TransactionPayload,
        TransactionStatus,
    },
    transaction_helpers::{create_signed_payload_txn, ChannelPayloadSigner, TransactionSigner},
    vm_error::*,
};
use local_state_storage::LocalStateStorage;
use logger::prelude::*;
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use sgtypes::{
    account_resource_ext,
    channel::{Channel, WitnessData},
    channel_transaction::{
        ChannelOp, ChannelTransactionRequest, ChannelTransactionRequestAndOutput,
        ChannelTransactionRequestPayload, ChannelTransactionResponse,
        ChannelTransactionResponsePayload,
    },
    resource::Resource,
    script_package::{ChannelScriptPackage, ScriptCode},
};
use state_view::StateView;
use std::{sync::Arc, time::Duration};
use vm::gas_schedule::GasAlgebra;
use vm_runtime::{MoveVM, VMExecutor};

lazy_static! {
    pub static ref DEFAULT_ASSET: StructTag = coin_struct_tag();
    static ref VM_CONFIG: VMConfig = VMConfig::offchain();
}

pub struct Wallet<C>
where
    C: ChainClient + Send + Sync + 'static,
{
    account: AccountAddress,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    client: Arc<C>,
    storage: Arc<AtomicRefCell<LocalStateStorage<C>>>,
    script_registry: PackageRegistry,
    offchain_transactions: Arc<AtomicRefCell<Vec<(HashValue, ChannelTransactionRequest, u8)>>>,
}

impl<C> Wallet<C>
where
    C: ChainClient + Send + Sync + 'static,
{
    const TXN_EXPIRATION: Duration = Duration::from_secs(24 * 60 * 60);
    const MAX_GAS_AMOUNT_OFFCHAIN: u64 = std::u64::MAX;
    const MAX_GAS_AMOUNT_ONCHAIN: u64 = 1_000_000;
    const GAS_UNIT_PRICE: u64 = 1;
    // const RETRY_INTERVAL: u64 = 1000;

    pub fn new(
        account: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        rpc_host: &str,
        rpc_port: u32,
    ) -> Result<Wallet<StarChainClient>> {
        let chain_client = StarChainClient::new(rpc_host, rpc_port as u32);
        let client = Arc::new(chain_client);
        Wallet::new_with_client(account, keypair, client)
    }

    pub fn new_with_client(
        account: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        client: Arc<C>,
    ) -> Result<Self> {
        let storage = Arc::new(AtomicRefCell::new(LocalStateStorage::new(
            account,
            client.clone(),
        )?));
        let script_registry = PackageRegistry::build()?;
        Ok(Self {
            account,
            keypair,
            client,
            storage,
            script_registry,
            offchain_transactions: Arc::new(AtomicRefCell::new(Vec::new())),
        })
    }

    pub fn account(&self) -> AccountAddress {
        self.account
    }

    pub fn client(&self) -> &dyn ChainClient {
        &*self.client
    }

    pub fn default_asset() -> StructTag {
        DEFAULT_ASSET.clone()
    }

    fn execute_transaction(
        state_view: &dyn StateView,
        transaction: SignedTransaction,
    ) -> Result<TransactionOutput> {
        let tx_hash = transaction.raw_txn().hash();
        let output = MoveVM::execute_block(vec![transaction], &VM_CONFIG, state_view)
            .pop()
            .unwrap();
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

    pub fn get_resources() -> Vec<Resource> {
        unimplemented!()
    }

    fn execute(
        &self,
        channel_op: ChannelOp,
        channel: &Channel,
        receiver: AccountAddress,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        let channel_sequence_number = channel.channel_sequence_number();
        let txn = self.create_signed_script_txn(channel, receiver, &channel_op, args.clone())?;
        let storage = self.storage.borrow();
        let state_view = storage.new_channel_view(None, &receiver)?;
        let output = Self::execute_transaction(&state_view, txn.clone())?;
        let gas_used = output.gas_used();
        if gas_used > vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get() {
            warn!(
                "GasUsed {} > gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS {}",
                gas_used,
                vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get()
            );
        }

        //TODO need add a buffer to max_gas_amount? such as 10%?
        let max_gas_amount = gas_used;
        let sender = txn.sender();
        let sequence_number = txn.sequence_number();
        let gas_fixed_txn = RawTransaction::new(
            sender,
            sequence_number,
            txn.payload().clone(),
            max_gas_amount,
            txn.gas_unit_price(),
            txn.expiration_time(),
        );
        debug!("gas fixed txn: {}", gas_fixed_txn.hash());
        let gas_fixed_signed_txn = self.sign_txn(gas_fixed_txn.clone())?;
        let payload = if output.is_travel_txn() {
            let write_set_bytes: Vec<u8> = SimpleSerializer::serialize(output.write_set())?;
            let txn_write_set_hash = HashValue::from_sha3_256(write_set_bytes.as_slice());
            let txn_signature = gas_fixed_signed_txn.signature();
            ChannelTransactionRequestPayload::Travel {
                txn_write_set_hash,
                txn_signature,
            }
        } else {
            let witness_payload = ChannelWriteSetPayload::new(
                channel_sequence_number,
                output.write_set().clone(),
                receiver,
            );
            let witness_signature = self.sign_write_set_payload(&witness_payload)?;
            ChannelTransactionRequestPayload::Offchain {
                witness_hash: witness_payload.hash(),
                witness_signature,
            }
        };
        let version = state_view.version();
        let request = ChannelTransactionRequest::new(
            version,
            channel_op.clone(),
            sender,
            sequence_number,
            receiver,
            channel_sequence_number,
            gas_fixed_signed_txn.expiration_time(),
            payload,
            self.keypair.public_key.clone(),
            args,
            gas_fixed_signed_txn.max_gas_amount(),
            gas_fixed_signed_txn.gas_unit_price(),
        );
        channel.append_txn_request(ChannelTransactionRequestAndOutput::new(
            request.clone(),
            output,
            gas_fixed_txn,
        ))?;
        Ok(request)
    }

    /// Verify channel participant's txn
    pub fn verify_txn(
        &self,
        txn_request: &ChannelTransactionRequest,
    ) -> Result<ChannelTransactionResponse> {
        let id = txn_request.request_id();
        debug!("verify_txn id:{}", id);
        ensure!(
            txn_request.receiver() == self.account,
            "check receiver fail."
        );
        let sender = txn_request.sender();
        if txn_request.operator().is_open() {
            if self.storage.borrow().exist_channel(&sender) {
                bail!("Channel with address {} exist.", sender);
            }
            self.storage.borrow_mut().new_channel(sender);
        }

        let receiver = txn_request.receiver();

        let storage = self.storage.borrow();
        let channel = storage.get_channel(&sender)?;
        let my_channel_sequence_number = channel.channel_sequence_number();
        ensure!(
            my_channel_sequence_number == txn_request.channel_sequence_number(),
            "check channel_sequence_number fail."
        );
        let WitnessData { write_set, .. } = channel.witness_data();
        //TODO refactor this with verify flow strategy.
        let raw_txn = self.build_txn_with_op(
            sender,
            receiver,
            txn_request.sequence_number(),
            txn_request.channel_sequence_number(),
            write_set,
            txn_request.operator(),
            txn_request.args().to_vec(),
            txn_request.max_gas_amount(),
            txn_request.gas_unit_price(),
            txn_request.expiration_time(),
        )?;
        let txn_hash = raw_txn.hash();
        debug!("verify_txn txn_hash:{}", txn_hash);
        //TODO refactor receiver's travis txn signature do not need to mock.
        let signed_txn = self.mock_signature(raw_txn.clone())?;
        let version = txn_request.version();
        let state_view = storage.new_channel_view(Some(version), &sender)?;
        let txn_payload_signature = signed_txn
            .receiver_signature()
            .expect("signature must exist.");
        let output = Self::execute_transaction(&state_view, signed_txn)?;
        //TODO verify output.
        channel.append_txn_request(ChannelTransactionRequestAndOutput::new(
            txn_request.clone(),
            output.clone(),
            raw_txn,
        ))?;
        let write_set = output.write_set();

        //TODO check public_key match with sender address.
        let payload = match txn_request.payload() {
            ChannelTransactionRequestPayload::Offchain {
                witness_hash: sender_witness_hash,
                witness_signature: sender_witness_signature,
            } => {
                let my_witness_payload = ChannelWriteSetPayload::new(
                    my_channel_sequence_number,
                    write_set.clone(),
                    self.account,
                );
                let my_witness_hash = my_witness_payload.hash();
                ensure!(
                    my_witness_hash == *sender_witness_hash,
                    "check witeness hash fail"
                );
                txn_request
                    .public_key()
                    .verify_signature(&sender_witness_hash, &sender_witness_signature)?;

                let witness_signature = self.sign_write_set_payload(&my_witness_payload)?;
                ChannelTransactionResponsePayload::Offchain {
                    witness_payload_signature: witness_signature,
                }
            }
            ChannelTransactionRequestPayload::Travel {
                txn_write_set_hash,
                txn_signature,
            } => {
                let write_set_bytes: Vec<u8> = SimpleSerializer::serialize(output.write_set())?;
                let new_txn_write_set_hash = HashValue::from_sha3_256(write_set_bytes.as_slice());
                ensure!(
                    txn_write_set_hash == &new_txn_write_set_hash,
                    "check write_set fail"
                );
                txn_request
                    .public_key()
                    .verify_signature(&txn_hash, txn_signature)?;
                ChannelTransactionResponsePayload::Travel {
                    txn_payload_signature,
                }
            }
        };
        Ok(ChannelTransactionResponse::new(
            txn_request.request_id(),
            txn_request.channel_sequence_number(),
            payload,
            self.keypair.public_key.clone(),
        ))
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
        if self.storage.borrow().exist_channel(&receiver) {
            bail!("Channel with address {} exist.", receiver);
        }
        self.storage.borrow_mut().new_channel(receiver);
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute(
            ChannelOp::Open,
            channel,
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
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute(
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "deposit".to_string(),
            },
            channel,
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
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute(
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "transfer".to_string(),
            },
            channel,
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
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute(
            ChannelOp::Execute {
                package_name: DEFAULT_PACKAGE.to_owned(),
                script_name: "withdraw".to_string(),
            },
            channel,
            receiver,
            vec![
                TransactionArgument::U64(sender_amount),
                TransactionArgument::U64(receiver_amount),
            ],
        )
    }

    pub fn close(&self, receiver: AccountAddress) -> Result<ChannelTransactionRequest> {
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute(ChannelOp::Close, channel, receiver, vec![])
    }

    pub async fn apply_txn(
        &self,
        participant: AccountAddress,
        response: &ChannelTransactionResponse,
    ) -> Result<u64> {
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&participant)?;
        let (request, output, raw_txn) = match channel.pending_txn_request() {
            Some(ChannelTransactionRequestAndOutput {
                request,
                output,
                raw_txn,
            }) => (request, output, raw_txn),
            //TODO(jole) can not find request has such reason:
            // 1. txn is expire.
            // 2. txn is invalid.
            None => bail!(
                "pending_txn_request must exist at stage:{:?}",
                channel.stage()
            ),
        };
        let raw_txn_hash = raw_txn.hash();
        info!("apply_txn: {}", raw_txn_hash);
        ensure!(
            request.channel_sequence_number() == response.channel_sequence_number(),
            "check channel_sequence_number fail."
        );
        let gas = match (request.payload(), response.payload()) {
            (
                ChannelTransactionRequestPayload::Travel { txn_signature, .. },
                ChannelTransactionResponsePayload::Travel {
                    txn_payload_signature,
                },
            ) => {
                let mut signed_txn = SignedTransaction::new(
                    raw_txn,
                    request.public_key().clone(),
                    txn_signature.clone(),
                );
                signed_txn.set_receiver_public_key_and_signature(
                    response.public_key().clone(),
                    txn_payload_signature.clone(),
                );
                let sender = &signed_txn.sender();
                let txn_with_proof = if request.sender() == self.account {
                    // sender submit transaction to chain.
                    self.submit_transaction(signed_txn).await?
                } else {
                    let watch_future = self
                        .client
                        .watch_transaction(sender, signed_txn.sequence_number());
                    // FIXME: should not panic here, handle timeout situation.
                    watch_future.await?.0.expect("proof is none.")
                };
                //self.check_output(&output)?;
                let gas = txn_with_proof.proof.transaction_info().gas_used();
                //                let version = txn_with_proof.version;
                //                let account_state =
                // self.storage.borrow().get_account_state(self.account, Some(version))?;
                //                let participant_state =
                // self.storage.borrow().get_account_state(participant, Some(version))?;
                //                let account_channel_state =
                // account_state.filter_channel_state().remove(&participant).unwrap();
                //                let participant_channel_state =
                // participant_state.filter_channel_state().remove(&self.account).unwrap();
                //                channel.apply_state(account_channel_state,
                // participant_channel_state)?;
                channel.apply_output(output)?;
                gas
            }
            (
                ChannelTransactionRequestPayload::Offchain {
                    witness_signature: sender_witness_signature,
                    witness_hash,
                },
                ChannelTransactionResponsePayload::Offchain {
                    witness_payload_signature: receiver_witness_signature,
                },
            ) => {
                // rebuild payload from scratch
                let channel_write_set_payload = ChannelWriteSetPayload {
                    channel_sequence_number: response.channel_sequence_number(),
                    write_set: output.write_set().clone(),
                    receiver: request.receiver(),
                };
                // now, it's the final chance to validate the whole transaction flows.
                ensure!(
                    *witness_hash == channel_write_set_payload.hash(),
                    "check payload hash fail"
                );
                response.public_key().verify_signature(
                    &channel_write_set_payload.hash(),
                    receiver_witness_signature,
                )?;
                request.public_key().verify_signature(
                    &channel_write_set_payload.hash(),
                    sender_witness_signature,
                )?;

                // apply the other's witness payload to use his signature.
                if request.sender() == self.account {
                    channel.apply_witness(
                        channel_write_set_payload,
                        receiver_witness_signature.clone(),
                    )?;
                } else {
                    channel.apply_witness(
                        channel_write_set_payload,
                        sender_witness_signature.clone(),
                    )?;
                }
                self.offchain_transactions
                    .borrow_mut()
                    .push((response.request_id(), request, 1));
                0
            }
            _ => bail!("ChannelTransaction request and response type not match."),
        };
        info!("success apply txn: {}", raw_txn_hash);
        Ok(gas)
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
        let storage = self.storage.borrow();
        let channel = storage.get_channel(&receiver)?;
        self.execute(
            ChannelOp::Execute {
                package_name: package_name.to_string(),
                script_name: script_name.to_string(),
            },
            channel,
            receiver,
            args,
        )
    }

    pub fn install_package(&self, package: ChannelScriptPackage) -> Result<()> {
        //TODO(jole) package should limit channel?
        self.script_registry.install_package(package)?;
        Ok(())
    }

    /// Deploy a module to Chain
    pub async fn deploy_module(
        &self,
        module_byte_code: Vec<u8>,
    ) -> Result<SignedTransactionWithProof> {
        let payload = TransactionPayload::Module(Module::new(module_byte_code));
        //TODO pre execute deploy module txn on local , and get real gas used to set max_gas_amount.
        let txn = create_signed_payload_txn(
            self,
            payload,
            self.account,
            self.sequence_number()?,
            Self::MAX_GAS_AMOUNT_ONCHAIN,
            Self::GAS_UNIT_PRICE,
            Self::TXN_EXPIRATION.as_secs() as i64,
        )?;
        //TODO need execute at local vm for check?
        self.submit_transaction(txn).await
    }

    pub fn get_script(&self, package_name: &str, script_name: &str) -> Option<ScriptCode> {
        self.script_registry.get_script(package_name, script_name)
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

    pub fn channel_account_resource(
        &self,
        participant: AccountAddress,
    ) -> Result<Option<ChannelAccountResource>> {
        self.get(&channel_account_resource_path(participant))
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

    pub fn sequence_number(&self) -> Result<u64> {
        Ok(self.account_resource()?.sequence_number())
    }

    //TODO support more asset type
    pub fn balance(&self) -> Result<u64> {
        self.account_resource().map(|r| r.balance())
    }

    pub fn channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        Ok(self
            .channel_account_resource(participant)?
            .map(|account| account.balance())
            .unwrap_or(0))
    }

    fn build_txn_with_op(
        &self,
        sender: AccountAddress,
        receiver: AccountAddress,
        sequence_number: u64,
        channel_sequence_number: u64,
        write_set: WriteSet,
        channel_op: &ChannelOp,
        args: Vec<TransactionArgument>,
        max_gas_amount: u64,
        gas_unit_price: u64,
        txn_expiration: Duration,
    ) -> Result<RawTransaction> {
        let script_code = match &channel_op {
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
        let channel_script =
            ChannelScriptPayload::new(channel_sequence_number, write_set, receiver, script);
        Ok(RawTransaction::new_payload_txn(
            sender,
            sequence_number,
            TransactionPayload::ChannelScript(channel_script),
            max_gas_amount,
            gas_unit_price,
            txn_expiration,
        ))
    }

    fn txn_expiration() -> Duration {
        std::time::Duration::new(
            (Utc::now().timestamp() + Self::TXN_EXPIRATION.as_secs() as i64) as u64,
            0,
        )
    }

    /// Craft a transaction request.
    fn create_signed_script_txn(
        &self,
        channel: &Channel,
        receiver: AccountAddress,
        channel_op: &ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<SignedTransaction> {
        let WitnessData { write_set, .. } = channel.witness_data();
        let txn = self.build_txn_with_op(
            self.account,
            receiver,
            self.sequence_number()?,
            channel.channel_sequence_number(),
            write_set,
            channel_op,
            args,
            Self::MAX_GAS_AMOUNT_OFFCHAIN,
            Self::GAS_UNIT_PRICE,
            Self::txn_expiration(),
        )?;
        let signed_txn = self.mock_signature(txn)?;
        Ok(signed_txn)
    }

    fn mock_signature(&self, txn: RawTransaction) -> Result<SignedTransaction> {
        // execute txn on offchain vm, should mock sender and receiver signature with a local
        // keypair. the vm will skip signature check on offchain vm.
        let mut signed_txn = self.sign_txn(txn)?;
        signed_txn.sign_by_receiver(&self.keypair.private_key, self.keypair.public_key.clone())?;
        Ok(signed_txn)
    }

    pub async fn submit_transaction(
        &self,
        signed_transaction: SignedTransaction,
    ) -> Result<SignedTransactionWithProof> {
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

    pub fn find_offchain_txn(
        &self,
        hash: Option<HashValue>,
        count: u32,
    ) -> Result<Vec<(HashValue, ChannelTransactionRequest, u8)>> {
        let tnxs = self.offchain_transactions.borrow();
        let mut count_num = count;
        let mut find_data = false;
        let mut data = Vec::new();
        match hash {
            Some(hash) => {
                for (hash_item, request, res) in tnxs.iter() {
                    debug!("hash_item:{}", hash_item);
                    if hash.eq(hash_item) {
                        find_data = true;
                        continue;
                    }
                    if find_data && count_num > 0 {
                        data.push((*hash_item, request.clone(), *res));
                        count_num = count_num - 1;
                        if count_num == 0 {
                            break;
                        }
                    }
                }
            }
            None => {
                for (hash_item, request, res) in tnxs.iter() {
                    debug!("hash_item:{}", hash_item);
                    data.push((*hash_item, request.clone(), *res));
                    count_num = count_num - 1;
                    if count_num == 0 {
                        break;
                    }
                }
            }
        }
        Ok(data)
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
