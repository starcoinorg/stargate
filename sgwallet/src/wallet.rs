// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::{
    chain_watcher::{ChainWatcher, ChainWatcherHandle},
    channel::{
        ApplyCoSignedTxn, ApplyPendingTxn, ApplySoloTxn, CancelPendingTxn, Channel, ChannelEvent,
        ChannelHandle, CollectProposalWithSigs, Execute, GrantProposal,
    },
    scripts::*,
};
use anyhow::{bail, ensure, format_err, Error, Result};
use async_trait::async_trait;
use chrono::Utc;
use coerce_rt::actor::{
    context::{ActorContext, ActorHandlerContext, ActorStatus},
    message::{Handler, Message},
    Actor, ActorRef,
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

#[derive(Clone)]
pub struct WalletHandle {
    actor_ref: ActorRef<Wallet>,
    shared: Shared,
    sgdb: Arc<SgStorage>,
}

impl WalletHandle {
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
    pub fn keypair(&self) -> Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> {
        self.shared.keypair.clone()
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

impl WalletHandle {
    /// enable channel for this wallet, return gas_used
    pub async fn enable_channel(&self) -> Result<u64> {
        self.actor_ref.clone().send(EnableChannel).await?
    }

    pub async fn is_channel_feature_enabled(&self) -> Result<bool> {
        Ok(self.actor_ref.clone().send(IsChannelFeatureEnabled).await?)
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

        if !grant {
            channel
                .channel_ref()
                .send(CancelPendingTxn {
                    channel_txn_id: request_id,
                })
                .await??;
            return Ok(None);
        }

        let resp = channel
            .channel_ref()
            .send(GrantProposal {
                channel_txn_id: request_id,
            })
            .await??;

        Ok(Some(ChannelTransactionResponse::new(proposal, resp)))
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

        let (txn_sender, seq_number) = channel
            .channel_ref()
            .send(ApplyPendingTxn)
            .await??
            .ok_or(format_err!("already travelling"))?;

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

        let (_proposal, _) = txn_response.clone().into();

        let option_watch = channel.channel_ref().send(ApplyPendingTxn).await??;
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
            // TODO: recheck the condition.
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
        self.actor_ref
            .clone()
            .send(DeployModule { module_byte_code })
            .await?
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
        self.actor_ref.clone().send(GetAllChannels).await?
    }

    pub async fn stop(&self) -> Result<()> {
        if let Err(_) = self.actor_ref.clone().stop().await {
            warn!("actor {:?} already stopped", &self.actor_ref);
        }
        Ok(())
    }

    async fn spawn_new_channel(
        &self,
        channel_address: AccountAddress,
        participants: BTreeSet<AccountAddress>,
    ) -> Result<Arc<ChannelHandle>> {
        self.actor_ref
            .clone()
            .send(SpawnNewChannel {
                channel_address,
                participants,
            })
            .await?
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

    async fn get_channel(&self, channel_address: AccountAddress) -> Result<Arc<ChannelHandle>> {
        self.actor_ref
            .clone()
            .send(GetChannel { channel_address })
            .await?
    }
}

pub struct Wallet {
    inner: Shared,
    channel_enabled: bool,
    channels: HashMap<AccountAddress, Arc<ChannelHandle>>,
    sgdb: Arc<SgStorage>,
    chain_txn_handle: Option<ChainWatcherHandle>,
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
        let sgdb = Arc::new(SgStorage::new(account, store_dir));
        let script_registry = Arc::new(PackageRegistry::build()?);

        let shared = Shared {
            account,
            keypair,
            client,
            script_registry,
        };
        let wallet = Wallet {
            inner: shared.clone(),
            channel_enabled: false,
            channels: HashMap::new(),
            sgdb: sgdb.clone(),
            chain_txn_handle: None,
        };
        Ok(wallet)
    }

    pub async fn start(self) -> Result<WalletHandle> {
        // TODO: should keep actor context
        let mut actor_context = ActorContext::new();
        let shared = self.inner.clone();
        let sgdb = self.sgdb.clone();
        let actor_ref = actor_context.new_actor(self).await?;
        Ok(WalletHandle {
            actor_ref,
            shared,
            sgdb,
        })
    }
}

#[async_trait]
impl Actor for Wallet {
    async fn started(&mut self, ctx: &mut ActorHandlerContext) {
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
            .start(ctx.actor_context_mut().clone())
            .await
            .expect("start chain watcher should ok");
        self.chain_txn_handle = Some(chain_txn_handle);

        if let Some(blob) =
            account_state.get_state(&DataPath::onchain_resource_path(user_channels_struct_tag()))
        {
            self.channel_enabled = true;
            let user_channels: UserChannelsResource =
                make_resource(blob.as_slice()).expect("parse user channels should work");
            let channels = self
                .refresh_channels(user_channels, account_state.version())
                .await;
            match channels {
                Ok(c) => {
                    for (channel_address, (participants, channel_state)) in c.into_iter() {
                        self.spawn_channel(channel_address, participants, channel_state, ctx)
                            .await;
                    }
                }
                Err(_e) => {
                    error!("fail to get channel states from chain");
                    ctx.set_status(ActorStatus::Stopping);
                }
            }
        } else {
            self.channel_enabled = false;
            warn!("channel feature is not enabled for this wallet account");
        }
    }

    async fn stopped(&mut self, _ctx: &mut ActorHandlerContext) {
        for (a, c) in self.channels.iter() {
            if let Err(e) = c.stop().await {
                error!("stop channel {} error: {}", a, e);
            }
        }
        self.channels.clear();

        if let Some(h) = self.chain_txn_handle.take() {
            h.stop().await;
        }
        crit!("wallet {} task stopped", self.inner.account);
    }
}

struct IsChannelFeatureEnabled;
impl Message for IsChannelFeatureEnabled {
    type Result = bool;
}
#[async_trait]
impl Handler<IsChannelFeatureEnabled> for Wallet {
    async fn handle(
        &mut self,
        _message: IsChannelFeatureEnabled,
        _ctx: &mut ActorHandlerContext,
    ) -> <IsChannelFeatureEnabled as Message>::Result {
        self.channel_enabled
    }
}

struct EnableChannel;
impl Message for EnableChannel {
    type Result = Result<u64>;
}

#[async_trait]
impl Handler<EnableChannel> for Wallet {
    async fn handle(
        &mut self,
        _message: EnableChannel,
        _ctx: &mut ActorHandlerContext,
    ) -> <EnableChannel as Message>::Result {
        self.enable_channel().await
    }
}

struct SpawnNewChannel {
    pub channel_address: AccountAddress,
    pub participants: BTreeSet<AccountAddress>,
}
impl Message for SpawnNewChannel {
    type Result = Result<Arc<ChannelHandle>>;
}
#[async_trait]
impl Handler<SpawnNewChannel> for Wallet {
    async fn handle(
        &mut self,
        message: SpawnNewChannel,
        ctx: &mut ActorHandlerContext,
    ) -> <SpawnNewChannel as Message>::Result {
        let SpawnNewChannel {
            channel_address,
            participants,
        } = message;
        self.spawn_channel(channel_address, participants, AccountState::new(), ctx)
            .await;
        let channel = self.get_channel(&channel_address);
        channel
    }
}

struct GetChannel {
    pub channel_address: AccountAddress,
}
impl Message for GetChannel {
    type Result = Result<Arc<ChannelHandle>>;
}
#[async_trait]
impl Handler<GetChannel> for Wallet {
    async fn handle(
        &mut self,
        message: GetChannel,
        _ctx: &mut ActorHandlerContext,
    ) -> <GetChannel as Message>::Result {
        let GetChannel { channel_address } = message;
        self.get_channel(&channel_address)
    }
}

struct GetAllChannels;
impl Message for GetAllChannels {
    type Result = Result<HashSet<AccountAddress>>;
}
#[async_trait]
impl Handler<GetAllChannels> for Wallet {
    async fn handle(
        &mut self,
        _message: GetAllChannels,
        _ctx: &mut ActorHandlerContext,
    ) -> <GetAllChannels as Message>::Result {
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
        Ok(all_channels)
    }
}

struct DeployModule {
    pub module_byte_code: Vec<u8>,
}
impl Message for DeployModule {
    type Result = Result<TransactionWithProof>;
}
#[async_trait]
impl Handler<DeployModule> for Wallet {
    async fn handle(
        &mut self,
        message: DeployModule,
        _ctx: &mut ActorHandlerContext,
    ) -> <DeployModule as Message>::Result {
        let DeployModule { module_byte_code } = message;
        self.deploy_module(module_byte_code).await
    }
}

struct StopChannel {
    pub participant: AccountAddress,
}
impl Message for StopChannel {
    type Result = Result<()>;
}

#[async_trait]
impl Handler<StopChannel> for Wallet {
    async fn handle(
        &mut self,
        message: StopChannel,
        _ctx: &mut ActorHandlerContext,
    ) -> <StopChannel as Message>::Result {
        let StopChannel { participant } = message;
        let (generated_channel_address, _participants) =
            generate_channel_address(participant, self.inner.account);
        if let Some(c) = self.channels.remove(&generated_channel_address) {
            c.stop().await
        } else {
            Ok(())
        }
    }
}

pub(crate) struct ChannelNotifyEvent {
    pub channel_event: ChannelEvent,
}

impl Message for ChannelNotifyEvent {
    type Result = ();
}

#[async_trait]
impl Handler<ChannelNotifyEvent> for Wallet {
    async fn handle(
        &mut self,
        message: ChannelNotifyEvent,
        _ctx: &mut ActorHandlerContext,
    ) -> <ChannelNotifyEvent as Message>::Result {
        let ChannelNotifyEvent { channel_event } = message;
        match channel_event {
            ChannelEvent::Stopped { channel_address } => {
                self.channels.remove(&channel_address);
            }
        }
    }
}

impl Wallet {
    async fn refresh_channels(
        &mut self,
        user_channels: UserChannelsResource,
        version: u64,
    ) -> Result<HashMap<AccountAddress, (BTreeSet<AccountAddress>, AccountState)>> {
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
        Ok(channel_states)
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

    async fn actor_ref(ctx: &mut ActorHandlerContext) -> ActorRef<Self> {
        let actor_id = ctx.actor_id().clone();
        ctx.actor_context_mut()
            .get_actor::<Self>(actor_id)
            .await
            .expect("get self actor ref should be ok")
    }

    async fn spawn_channel(
        &mut self,
        channel_address: AccountAddress,
        participants: BTreeSet<AccountAddress>,
        channel_account_state: AccountState,
        ctx: &mut ActorHandlerContext,
    ) {
        let my_actor_ref = Self::actor_ref(ctx).await;

        let channel = Channel::load(
            channel_address,
            self.inner.account,
            participants,
            ChannelState::new(channel_address, channel_account_state),
            self.get_channel_db(channel_address),
            self.chain_txn_handle.as_ref().unwrap().clone(),
            my_actor_ref,
            self.inner.keypair.clone(),
            self.inner.script_registry.clone(),
            self.inner.client.clone(),
        );

        let channel_handle = channel.start(ctx.actor_context_mut().clone()).await;

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

impl TransactionSigner for WalletHandle {
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

fn generate_channel_address(
    p1: AccountAddress,
    p2: AccountAddress,
) -> (AccountAddress, BTreeSet<AccountAddress>) {
    let mut addresses = BTreeSet::new();
    addresses.insert(p1);
    addresses.insert(p2);
    (AccountAddress::from(&addresses), addresses)
}
