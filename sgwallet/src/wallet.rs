// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::scripts::*;
use atomic_refcell::AtomicRefCell;
use chrono::Utc;
use config::config::VMConfig;
use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, SigningKey, VerifyingKey,
};
use failure::prelude::*;
use lazy_static::lazy_static;
use libra_types::{
    access_path::DataPath,
    account_address::AccountAddress,
    account_config::{account_resource_path, coin_struct_tag, AccountResource},
    channel_account::{channel_account_resource_path, ChannelAccountResource},
    language_storage::StructTag,
    transaction::{
        ChannelScriptBody, ChannelTransactionPayload, ChannelTransactionPayloadBody,
        ChannelWriteSetBody, Module, RawTransaction, Script, SignedTransaction,
        SignedTransactionWithProof, TransactionArgument, TransactionOutput, TransactionPayload,
        TransactionStatus,
    },
    transaction_helpers::{create_signed_payload_txn, ChannelPayloadSigner, TransactionSigner},
    vm_error::*,
};
use local_state_storage::channel::Channel;
use local_state_storage::LocalStateStorage;
use logger::prelude::*;
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use sgconfig::config::WalletConfig;
use sgtypes::channel_transaction_sigs::{ChannelTransactionSigs, TxnSignature};
use sgtypes::{
    account_resource_ext,
    channel_transaction::{
        ChannelOp, ChannelTransaction, ChannelTransactionRequest,
        ChannelTransactionRequestAndOutput, ChannelTransactionResponse,
    },
    resource::Resource,
    script_package::{ChannelScriptPackage, ScriptCode},
};
use state_view::StateView;
use std::path::Path;
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
    storage: LocalStateStorage<C>,
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
        Wallet::new_with_client(account, keypair, client, WalletConfig::default().store_dir)
    }

    pub fn new_with_client<P: AsRef<Path>>(
        account: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        client: Arc<C>,
        store_dir: P,
    ) -> Result<Self> {
        let storage = LocalStateStorage::new(account, store_dir, client.clone())?;
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

    fn get_channel_transaction_payload_body(
        raw_txn: &RawTransaction,
    ) -> Result<ChannelTransactionPayloadBody> {
        match raw_txn.payload() {
            TransactionPayload::Channel(payload) => Ok(payload.body.clone()),
            _ => bail!("raw txn must a Channel Transaction"),
        }
    }

    fn execute(
        &self,
        channel_op: ChannelOp,
        receiver: AccountAddress,
        args: Vec<TransactionArgument>,
    ) -> Result<ChannelTransactionRequest> {
        let channel = self.storage.get_channel(&receiver)?;
        let state_view = channel.channel_view(None, &*self.client)?;

        // build channel_transaction first
        let channel_transaction = ChannelTransaction::new(
            state_view.version(),
            channel_op,
            channel.account().address(),
            self.sequence_number()?,
            receiver,
            channel.channel_sequence_number(),
            Self::txn_expiration(),
            args,
        );

        // create mocked txn to execute
        let txn = self.create_mocked_signed_script_txn(&channel, &channel_transaction)?;
        let output = Self::execute_transaction(&state_view, txn.clone())?;

        // check output gas
        let gas_used = output.gas_used();
        if gas_used > vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get() {
            warn!(
                "GasUsed {} > gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS {}",
                gas_used,
                vm::gas_schedule::MAXIMUM_NUMBER_OF_GAS_UNITS.get()
            );
        }

        let channel_write_set = ChannelWriteSetBody::new(
            channel_transaction.channel_sequence_number(),
            output.write_set().clone(),
            channel_transaction.sender(),
        );
        let channel_write_set_hash = channel_write_set.hash();
        let channel_write_set_signature = self
            .keypair
            .private_key
            .sign_message(&channel_write_set_hash);
        let channel_txn_hash = channel_transaction.hash();
        let channel_txn_signature = self.keypair.private_key.sign_message(&channel_txn_hash);

        let channel_txn_sigs = ChannelTransactionSigs::new(
            self.keypair.public_key.clone(),
            TxnSignature::SenderSig {
                channel_txn_signature,
            },
            channel_write_set_hash,
            channel_write_set_signature,
        );

        let channel_txn_request = ChannelTransactionRequest::new(
            channel_transaction,
            channel_txn_sigs,
            output.is_travel_txn(),
        );
        channel.append_txn_request(ChannelTransactionRequestAndOutput::new(
            channel_txn_request.clone(),
            output,
            None,
        ))?;
        Ok(channel_txn_request)
    }

    /// called by reciever to verify sender's channel_txn.
    fn verify_channel_txn(
        &self,
        channel: &Channel,
        channel_txn: &ChannelTransaction,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<()> {
        let channel_sequence_number = channel.channel_sequence_number();
        ensure!(
            channel_sequence_number == channel_txn.channel_sequence_number(),
            "check channel_sequence_number fail."
        );
        match &channel_txn_sigs.signature {
            TxnSignature::SenderSig {
                channel_txn_signature,
            } => {
                channel_txn_sigs
                    .public_key
                    .verify_signature(&channel_txn.hash(), channel_txn_signature)?;
            }
            _ => bail!("not support"),
        }
        //TODO check public_key match with sender address.
        Ok(())
    }

    // called by both of sender and reciver, to verify participant's witness payload
    fn verify_channel_witness(
        &self,
        channel: &Channel,
        output: &TransactionOutput,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<ChannelTransactionPayload> {
        let write_set_body = ChannelWriteSetBody::new(
            channel.channel_sequence_number(),
            output.write_set().clone(),
            channel.participant().address(),
        );
        let write_set_body_hash = write_set_body.hash();
        ensure!(
            write_set_body_hash == channel_txn_sigs.write_set_payload_hash.clone(),
            "channel output hash mismatched"
        );
        channel_txn_sigs.public_key.verify_signature(
            &write_set_body_hash,
            &channel_txn_sigs.write_set_payload_signature,
        )?;

        Ok(ChannelTransactionPayload::new_with_write_set(
            write_set_body,
            channel_txn_sigs.public_key.clone(),
            channel_txn_sigs.write_set_payload_signature.clone(),
        ))
    }

    /// Verify channel participant's txn
    pub fn verify_txn(
        &self,
        txn_request: &ChannelTransactionRequest,
    ) -> Result<ChannelTransactionResponse> {
        let id = txn_request.request_id();
        let channel_txn = txn_request.channel_txn();
        let channel_txn_sigs = txn_request.channel_txn_sigs();

        // get channel
        debug!("verify_txn id:{}", id);
        ensure!(
            channel_txn.receiver() == self.account,
            "check receiver fail."
        );
        let sender = channel_txn.sender();
        if channel_txn.operator().is_open() {
            if self.storage.exist_channel(&sender) {
                bail!("Channel with address {} exist.", sender);
            }
            self.storage.new_channel(sender);
        }

        let channel = self.storage.get_channel(&sender)?;

        self.verify_channel_txn(&channel, channel_txn, channel_txn_sigs)?;

        let signed_txn = self.create_mocked_signed_script_txn(&channel, channel_txn)?;
        let txn_payload_signature = signed_txn
            .receiver_signature()
            .expect("signature must exist.");

        let version = channel_txn.version();
        let output = {
            let state_view = channel.channel_view(Some(version), &*self.client)?;
            Self::execute_transaction(&state_view, signed_txn)?
        };

        let verified_participant_witness_payload =
            self.verify_channel_witness(&channel, &output, channel_txn_sigs)?;

        channel.append_txn_request(ChannelTransactionRequestAndOutput::new(
            txn_request.clone(),
            output.clone(),
            Some(verified_participant_witness_payload),
        ))?;

        // build signatures sent to sender
        let write_set_body = ChannelWriteSetBody::new(
            channel.channel_sequence_number(),
            output.write_set().clone(),
            channel.account().address(),
        );
        let witness_hash = write_set_body.hash();
        let witness_signature = self.keypair.private_key.sign_message(&witness_hash);

        let channel_txn_sigs = ChannelTransactionSigs::new(
            self.keypair.public_key.clone(),
            TxnSignature::ReceiverSig {
                channel_script_body_signature: txn_payload_signature,
            },
            witness_hash,
            witness_signature,
        );
        Ok(ChannelTransactionResponse::new(
            txn_request.request_id(),
            channel_txn_sigs,
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
        if self.storage.exist_channel(&receiver) {
            bail!("Channel with address {} exist.", receiver);
        }
        self.storage.new_channel(receiver);

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

    pub async fn receiver_apply_txn(
        &self,
        participant: AccountAddress,
        response: &ChannelTransactionResponse,
    ) -> Result<u64> {
        let (request, output, verified_participant_witness_payload) = {
            let channel = self.storage.get_channel(&participant)?;
            match channel.pending_txn_request() {
                Some(ChannelTransactionRequestAndOutput {
                    request,
                    output,
                    verified_participant_witness_payload,
                }) => (request, output, verified_participant_witness_payload),
                //TODO(jole) can not find request has such reason:
                // 1. txn is expire.
                // 2. txn is invalid.
                None => bail!(
                    "pending_txn_request must exist at stage:{:?}",
                    channel.stage()
                ),
            }
        };
        ensure!(
            request.request_id() == response.request_id(),
            "request id mismatch, request: {}, response: {}",
            request.request_id(),
            response.request_id()
        );
        let request_id = request.request_id();

        let channel_txn = request.channel_txn();

        let gas = if !output.is_travel_txn() {
            self.offchain_transactions.borrow_mut().push((
                response.request_id(),
                request.clone(),
                1,
            ));
            0
        } else {
            let txn_sender = channel_txn.sender();
            let watch_future = self
                .client
                .watch_transaction(&txn_sender, channel_txn.sequence_number());
            // FIXME: should not panic here, handle timeout situation.
            let txn_with_proof = watch_future.await?.0.expect("proof is none.");

            let gas = txn_with_proof.proof.transaction_info().gas_used();
            gas
        };

        {
            let mut channel = self.storage.get_channel_mut(&participant)?;
            // save to db
            channel.apply(
                channel_txn,
                request.channel_txn_sigs(),
                response.channel_txn_sigs(),
                &output,
                verified_participant_witness_payload
                    .expect("receiver should have verified participant witness data"),
            )?;
        }

        info!("success apply channel request: {}", request_id);
        Ok(gas)
    }

    /// called by sender, to verify receiver's response
    fn verify_response(
        &self,
        channel: &Channel,
        channel_txn: &ChannelTransaction,
        output: &TransactionOutput,
        response: &ChannelTransactionResponse,
    ) -> Result<(ChannelTransactionPayload, ChannelTransactionPayload)> {
        info!("verify channel response: {}", response.request_id());
        let channel_txn_sigs = response.channel_txn_sigs();
        let verified_channel_txn_payload =
            self.verify_channel_txn_payload(channel, channel_txn, channel_txn_sigs)?;
        let verified_participant_witness_payload =
            self.verify_channel_witness(channel, &output, channel_txn_sigs)?;
        Ok((
            verified_channel_txn_payload,
            verified_participant_witness_payload,
        ))
    }

    // called by sender, to verify receiver's channel txn payload signature
    fn verify_channel_txn_payload(
        &self,
        channel: &Channel,
        channel_txn: &ChannelTransaction,
        channel_txn_sigs: &ChannelTransactionSigs,
    ) -> Result<ChannelTransactionPayload> {
        let raw_txn = self.build_raw_txn_from_channel_txn(channel, channel_txn, None)?;
        let verified_channel_txn_payload = match &channel_txn_sigs.signature {
            TxnSignature::ReceiverSig {
                channel_script_body_signature,
            } => {
                let channel_payload = Self::get_channel_transaction_payload_body(&raw_txn)?;
                channel_payload
                    .verify(&channel_txn_sigs.public_key, channel_script_body_signature)?;
                ChannelTransactionPayload::new(
                    channel_payload,
                    channel_txn_sigs.public_key.clone(),
                    channel_script_body_signature.clone(),
                )
            }
            _ => bail!("should not happen"),
        };
        Ok(verified_channel_txn_payload)
    }

    pub async fn sender_apply_txn(
        &self,
        participant: AccountAddress,
        response: &ChannelTransactionResponse,
    ) -> Result<u64> {
        let (request, output) = {
            let channel = self.storage.get_channel(&participant)?;
            match channel.pending_txn_request() {
                Some(ChannelTransactionRequestAndOutput {
                    request, output, ..
                }) => (request, output),
                //TODO(jole) can not find request has such reason:
                // 1. txn is expire.
                // 2. txn is invalid.
                None => bail!(
                    "pending_txn_request must exist at stage:{:?}",
                    channel.stage()
                ),
            }
        };

        ensure!(
            request.request_id() == response.request_id(),
            "request id mismatch, request: {}, response: {}",
            request.request_id(),
            response.request_id()
        );
        let request_id = request.request_id();

        let channel_txn = request.channel_txn();
        let (verified_participant_script_payload, verified_participant_witness_payload) = {
            let channel = self.storage.get_channel(&participant)?;
            self.verify_response(&channel, channel_txn, &output, response)?
        };

        let gas = if !output.is_travel_txn() {
            // TODO: remove
            self.offchain_transactions.borrow_mut().push((
                response.request_id(),
                request.clone(),
                1,
            ));
            0
        } else {
            // construct onchain tx
            let max_gas_amount = std::cmp::min(
                (output.gas_used() as f64 * 1.1) as u64,
                Self::MAX_GAS_AMOUNT_ONCHAIN,
            );
            let new_raw_txn = RawTransaction::new_channel(
                channel_txn.sender(),
                channel_txn.sequence_number(),
                verified_participant_script_payload,
                max_gas_amount,
                Self::GAS_UNIT_PRICE,
                channel_txn.expiration_time(),
            );

            debug!("prepare to submit txn to chain, {:?}", &new_raw_txn);

            let txn_with_proof = {
                let signed_txn = self.mock_signature(new_raw_txn)?;
                // sender submit transaction to chain.
                self.submit_transaction(signed_txn).await?
            };
            let gas = txn_with_proof.proof.transaction_info().gas_used();
            gas
        };

        {
            let mut channel = self.storage.get_channel_mut(&participant)?;
            // save to db
            channel.apply(
                channel_txn,
                request.channel_txn_sigs(),
                response.channel_txn_sigs(),
                &output,
                verified_participant_witness_payload,
            )?;
        }

        info!("success apply channel request: {}", request_id);
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

        self.execute(
            ChannelOp::Execute {
                package_name: package_name.to_string(),
                script_name: script_name.to_string(),
            },
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
        self.storage.get(&data_path)
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

    fn build_raw_txn_from_channel_txn(
        &self,
        channel: &Channel,
        channel_txn: &ChannelTransaction,
        payload_key_and_signature: Option<(Ed25519PublicKey, Ed25519Signature)>,
    ) -> Result<RawTransaction> {
        let script =
            self.channel_op_to_script(channel_txn.operator(), channel_txn.args().to_vec())?;
        let write_set = channel.witness_data().unwrap_or_default();
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
            Self::MAX_GAS_AMOUNT_OFFCHAIN,
            Self::GAS_UNIT_PRICE,
            channel_txn.expiration_time(),
        ))
    }

    fn txn_expiration() -> Duration {
        std::time::Duration::new(
            (Utc::now().timestamp() + Self::TXN_EXPIRATION.as_secs() as i64) as u64,
            0,
        )
    }

    /// Craft a mocked transaction request.
    fn create_mocked_signed_script_txn(
        &self,
        channel: &Channel,
        channel_txn: &ChannelTransaction,
    ) -> Result<SignedTransaction> {
        let txn = self.build_raw_txn_from_channel_txn(channel, channel_txn, None)?;
        let signed_txn = self.mock_signature(txn)?;
        Ok(signed_txn)
    }

    fn mock_signature(&self, txn: RawTransaction) -> Result<SignedTransaction> {
        // execute txn on offchain vm, should mock sender and receiver signature with a local
        // keypair. the vm will skip signature check on offchain vm.
        let signed_txn = self.sign_txn(txn)?;
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
