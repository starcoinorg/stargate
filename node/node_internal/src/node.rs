// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use futures::{
    compat::{Future01CompatExt, Stream01CompatExt},
    prelude::*,
};
use futures_timer::Delay;
use std::{sync::Arc, time::Duration};
use tokio::runtime::{Handle, Runtime};

use anyhow::{bail, ensure, Error, Result};
use libra_crypto::HashValue;

use libra_logger::prelude::*;
use libra_types::transaction::TransactionArgument;
use libra_types::{account_address::AccountAddress, account_config::AccountResource};
use network::{NetworkMessage, NetworkService};
use node_proto::{
    DeployModuleResponse, DepositResponse, EmptyResponse, ExecuteScriptResponse,
    GetChannelTransactionProposalResponse, OpenChannelResponse, PayResponse, WithdrawResponse,
};
use sgtypes::script_package::ChannelScriptPackage;
use sgtypes::{
    channel_transaction::{ChannelTransactionRequest, ChannelTransactionResponse},
    message::*,
    system_event::Event,
};
use sgwallet::{utils::*, wallet::WalletHandle};

use crate::message_processor::{MessageFuture, MessageProcessor};

use crate::invoice::{Invoice, InvoiceManager};
use crate::node_command::NodeMessage;
use futures_01::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};
use router::Router;
use sgtypes::sg_error::{SgError, SgErrorCode};
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use stats::PayEnum;
use std::convert::TryInto;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Node {
    executor: Handle,
    node_inner: Option<NodeInner>,
    event_sender: UnboundedSender<Event>,
    network_event_sender: UnboundedSender<Event>,
    command_sender: UnboundedSender<NodeMessage>,
    default_max_deposit: u64,
    network_service: NetworkService,
    receiver: Option<UnboundedReceiver<NetworkMessage>>,
    event_receiver: Option<UnboundedReceiver<Event>>,
    network_event_receiver: Option<UnboundedReceiver<Event>>,
    command_receiver: Option<UnboundedReceiver<NodeMessage>>,
    network_service_close_tx: Option<oneshot::Sender<()>>,
    router_message_receiver:
        Option<futures::channel::mpsc::UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>>,
    wallet: Arc<WalletHandle>,
    invoice_mgr: InvoiceManager,
}

struct NodeInner {
    wallet: Arc<WalletHandle>,
    executor: Handle,
    sender: UnboundedSender<NetworkMessage>,
    message_processor: MessageProcessor<u64>,
    default_future_timeout: AtomicU64,
    network_service: NetworkService,
    auto_approve: bool,
    invoice_mgr: InvoiceManager,
    router_message_sender:
        futures::channel::mpsc::UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
    router: Box<dyn Router>,
}

impl Node {
    pub fn new(
        executor: Handle,
        wallet: Arc<WalletHandle>,
        network_service: NetworkService,
        sender: UnboundedSender<NetworkMessage>,
        receiver: UnboundedReceiver<NetworkMessage>,
        router_message_sender: futures::channel::mpsc::UnboundedSender<(
            AccountAddress,
            RouterNetworkMessage,
        )>,
        router_message_receiver: futures::channel::mpsc::UnboundedReceiver<(
            AccountAddress,
            RouterNetworkMessage,
        )>,
        net_close_tx: oneshot::Sender<()>,
        auto_approve: bool,
        default_future_timeout: u64,
        router: Box<dyn Router>,
    ) -> Self {
        let executor_clone = executor.clone();
        let (event_sender, event_receiver) = futures_01::sync::mpsc::unbounded();
        let (network_event_sender, network_event_receiver) = futures_01::sync::mpsc::unbounded();

        let (command_sender, command_receiver) = futures_01::sync::mpsc::unbounded();

        let invoice_mgr = InvoiceManager::new();

        let node_inner = NodeInner {
            executor: executor_clone,
            wallet: wallet.clone(),
            sender,
            message_processor: MessageProcessor::new(),
            default_future_timeout: AtomicU64::new(default_future_timeout),
            network_service: network_service.clone(),
            auto_approve,
            invoice_mgr: invoice_mgr.clone(),
            router_message_sender,
            router,
        };
        Self {
            network_service,
            executor,
            node_inner: Some(node_inner),
            event_sender,
            network_event_sender,
            default_max_deposit: 10000000,
            command_sender,
            receiver: Some(receiver),
            event_receiver: Some(event_receiver),
            network_event_receiver: Some(network_event_receiver),
            command_receiver: Some(command_receiver),
            network_service_close_tx: Some(net_close_tx),
            router_message_receiver: Some(router_message_receiver),
            wallet,
            invoice_mgr,
        }
    }

    pub async fn open_channel_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<OpenChannelResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = match self
            .open_channel_async(receiver, sender_amount, receiver_amount)
            .await
        {
            Ok(msg_future) => msg_future,
            Err(e) => {
                resp_sender
                    .send(Err(Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };
        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(OpenChannelResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(Error::from(e)))
                .expect("Failed to send error message."),
        };
        resp_receiver
    }

    pub async fn open_channel_async(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<MessageFuture<u64>> {
        if receiver_amount > self.default_max_deposit {
            bail!("deposit coin amount too big")
        }
        if receiver_amount > sender_amount {
            bail!("sender amount should bigger than receiver amount.")
        }
        let is_receiver_connected = self.network_service.is_connected(receiver);
        if !is_receiver_connected {
            bail!("could not connect to receiver")
        }

        let (responder, resp_receiver) = futures::channel::oneshot::channel();
        self.command_sender
            .unbounded_send(NodeMessage::OpenChannel {
                receiver,
                sender_amount,
                receiver_amount,
                responder,
            })?;

        resp_receiver.await?
    }

    pub async fn deposit_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<DepositResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = match self.deposit_async(receiver, sender_amount).await {
            Ok(msg_future) => msg_future,
            Err(e) => {
                resp_sender
                    .send(Err(Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };
        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(DepositResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(Error::from(e)))
                .expect("Failed to send error message."),
        };
        resp_receiver
    }

    pub async fn deposit_async(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
    ) -> Result<MessageFuture<u64>> {
        let is_receiver_connected = self.network_service.is_connected(receiver);
        if !is_receiver_connected {
            bail!("could not connect to receiver")
        }
        let (responder, resp_receiver) = futures::channel::oneshot::channel();
        self.command_sender.unbounded_send(NodeMessage::Deposit {
            receiver,
            sender_amount,
            responder,
        })?;

        resp_receiver.await?
    }

    pub async fn withdraw_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<WithdrawResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = match self.withdraw_async(receiver, sender_amount).await {
            Ok(msg_future) => msg_future,
            Err(e) => {
                resp_sender
                    .send(Err(Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };

        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(WithdrawResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(Error::from(e)))
                .expect("Failed to send error message."),
        };
        resp_receiver
    }

    pub async fn withdraw_async(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
    ) -> Result<MessageFuture<u64>> {
        let is_receiver_connected = self.network_service.is_connected(receiver);
        if !is_receiver_connected {
            bail!("could not connect to receiver")
        }
        info!("start to withdraw with {:?} {} ", receiver, sender_amount);

        let (responder, resp_receiver) = futures::channel::oneshot::channel();
        self.command_sender.unbounded_send(NodeMessage::Withdraw {
            receiver,
            sender_amount,
            responder,
        })?;

        resp_receiver.await?
    }

    pub async fn off_chain_pay_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<PayResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();

        let f = match self.off_chain_pay_async(receiver, sender_amount).await {
            Ok(msg_future) => msg_future,
            Err(e) => {
                resp_sender
                    .send(Err(Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };

        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(PayResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(Error::from(e)))
                .expect("Failed to send error message."),
        };
        resp_receiver
    }

    pub async fn off_chain_pay_async(
        &self,
        receiver_address: AccountAddress,
        amount: u64,
    ) -> Result<MessageFuture<u64>> {
        let is_receiver_connected = self.network_service.is_connected(receiver_address);
        if !is_receiver_connected {
            bail!("could not connect to receiver")
        }

        let (responder, resp_receiver) = futures::channel::oneshot::channel();
        self.command_sender
            .unbounded_send(NodeMessage::ChannelPay {
                receiver_address,
                amount,
                responder,
            })?;

        resp_receiver.await?
    }

    pub async fn off_chain_pay_htlc_async_string(
        &self,
        encoded_invoice: String,
    ) -> Result<MessageFuture<u64>> {
        let invoice: Result<Invoice> = encoded_invoice.try_into();
        match invoice {
            Ok(invoice) => {
                self.off_chain_pay_htlc_async(
                    invoice.receiver,
                    invoice.amount,
                    invoice.r_hash,
                    20000,
                )
                .await
            }
            Err(e) => Err(e),
        }
    }

    pub async fn off_chain_pay_htlc_async(
        &self,
        receiver_address: AccountAddress,
        amount: u64,
        hash_lock: Vec<u8>,
        timeout: u64,
    ) -> Result<MessageFuture<u64>> {
        let is_receiver_connected = self.network_service.is_connected(receiver_address);
        if !is_receiver_connected {
            bail!("could not connect to receiver")
        }

        let (responder, resp_receiver) = futures::channel::oneshot::channel();
        self.command_sender
            .unbounded_send(NodeMessage::ChannelPayHTLC {
                receiver_address,
                amount,
                hash_lock,
                timeout,
                responder,
            })?;

        resp_receiver.await?
    }

    pub fn start_server(&mut self, rt: &mut Runtime) {
        let receiver = self.receiver.take().expect("receiver already taken");
        let event_receiver = self.event_receiver.take().expect("receiver already taken");
        let network_event_receiver = self
            .network_event_receiver
            .take()
            .expect("receiver already taken");

        let command_receiver = self
            .command_receiver
            .take()
            .expect("receiver already taken");

        let network_service_close_tx = self
            .network_service_close_tx
            .take()
            .expect("tx already taken");

        let router_message_rx = self
            .router_message_receiver
            .take()
            .expect("receiver already taken.");

        let node_inner = self.node_inner.take().expect("node inner already taken");

        let f = async {
            match node_inner.init().await {
                Ok(_) => {
                    info!("node init success");
                }
                Err(e) => {
                    panic!("init node error ,{}", e);
                }
            };
        };
        rt.block_on(f);

        let node_inner = Arc::new(node_inner);
        self.executor.spawn(Self::start_network(
            self.executor.clone(),
            node_inner.clone(),
            network_event_receiver,
            receiver,
            router_message_rx,
        ));

        self.executor.spawn(Self::start_command(
            self.executor.clone(),
            node_inner,
            event_receiver,
            command_receiver,
            network_service_close_tx,
        ));
    }

    pub async fn local_balance(&self) -> Result<AccountResource> {
        let (responder, receiver) = futures::channel::oneshot::channel();

        self.command_sender
            .unbounded_send(NodeMessage::ChainBalance { responder })?;

        receiver.await?
    }

    pub async fn channel_balance_async(&self, participant: AccountAddress) -> Result<u64> {
        let (responder, receiver) = futures::channel::oneshot::channel();

        self.command_sender
            .unbounded_send(NodeMessage::ChannelBalance {
                participant,
                responder,
            })?;

        receiver.await?
    }

    pub fn set_default_timeout(&self, timeout: u64) -> Result<()> {
        self.command_sender
            .unbounded_send(NodeMessage::SetTimeout {
                default_future_timeout: timeout,
            })?;
        Ok(())
    }

    pub fn shutdown(&self) -> Result<()> {
        debug!("node send shutdown event");
        self.event_sender.unbounded_send(Event::SHUTDOWN)?;
        self.network_event_sender.unbounded_send(Event::SHUTDOWN)?;
        Ok(())
    }

    pub fn install_package(&self, channel_script_package: ChannelScriptPackage) -> Result<()> {
        let (responder, receiver) = futures::channel::oneshot::channel();

        self.command_sender.unbounded_send(NodeMessage::Install {
            channel_script_package,
            responder,
        })?;

        let f = async {
            receiver.await.unwrap().unwrap();
        };

        self.executor.spawn(f);

        Ok(())
    }

    pub fn deploy_package_oneshot(
        &self,
        module_code: Vec<u8>,
    ) -> futures::channel::oneshot::Receiver<Result<DeployModuleResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();

        self.command_sender
            .unbounded_send(NodeMessage::DeployModule {
                module_code,
                responder: resp_sender,
            })
            .unwrap();

        resp_receiver
    }

    pub async fn execute_script_oneshot(
        &self,
        receiver_address: AccountAddress,
        package_name: String,
        script_name: String,
        transaction_args: Vec<TransactionArgument>,
    ) -> Result<futures::channel::oneshot::Receiver<Result<ExecuteScriptResponse>>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let (responder, receiver) = futures::channel::oneshot::channel();

        self.command_sender.unbounded_send(NodeMessage::Execute {
            receiver_address,
            package_name,
            script_name,
            transaction_args,
            responder,
        })?;

        let result = receiver.await??;

        match result.compat().await {
            Ok(id) => resp_sender
                .send(Ok(ExecuteScriptResponse::new(id)))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(Error::from(e)))
                .expect("Failed to send error message."),
        };
        Ok(resp_receiver)
    }

    pub async fn get_txn_by_channel_sequence_number(
        &self,
        participant_address: AccountAddress,
        channel_seq_number: u64,
    ) -> Result<SignedChannelTransaction> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();

        self.command_sender.unbounded_send(NodeMessage::TxnBySn {
            participant_address,
            channel_seq_number,
            responder: resp_sender,
        })?;

        resp_receiver.await?
    }

    pub async fn get_channel_transaction_proposal_async(
        &self,
        participant_address: AccountAddress,
    ) -> Result<GetChannelTransactionProposalResponse> {
        let proposal = self
            .wallet
            .get_waiting_proposal(participant_address)
            .await?;
        match proposal {
            Some(t) => Ok(GetChannelTransactionProposalResponse::new(Some(
                t.channel_txn,
            ))),
            None => {
                return Ok(GetChannelTransactionProposalResponse::new(None));
            }
        }
    }

    pub async fn get_channel_transaction_proposal_oneshot(
        &self,
        participant_address: AccountAddress,
    ) -> futures::channel::oneshot::Receiver<Result<GetChannelTransactionProposalResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        match self
            .get_channel_transaction_proposal_async(participant_address)
            .await
        {
            Ok(msg_future) => resp_sender
                .send(Ok(msg_future))
                .expect("Did open channel processor thread panic?"),
            Err(e) => {
                resp_sender
                    .send(Err(Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };
        resp_receiver
    }

    pub async fn channel_transaction_proposal_async(
        &self,
        participant_address: AccountAddress,
        transaction_hash: HashValue,
        approve: bool,
    ) -> Result<EmptyResponse> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();

        self.command_sender
            .unbounded_send(NodeMessage::ChannelTransactionProposal {
                participant_address,
                transaction_hash,
                approve,
                responder: resp_sender,
            })
            .unwrap();

        match resp_receiver.await? {
            Ok(_) => {
                info!(
                    "approve txn {} with {} ",
                    transaction_hash, participant_address
                );
                return Ok(EmptyResponse::new());
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    pub async fn add_invoice(&self, amount: u64) -> Result<Invoice> {
        Ok(self
            .invoice_mgr
            .new_invoice(amount, self.wallet.account())
            .await)
    }

    async fn start_network(
        executor: Handle,
        node_inner: Arc<NodeInner>,
        event_receiver: UnboundedReceiver<Event>,
        receiver: UnboundedReceiver<NetworkMessage>,
        mut router_message_receiver: futures::channel::mpsc::UnboundedReceiver<(
            AccountAddress,
            RouterNetworkMessage,
        )>,
    ) {
        info!("start receive message");
        let mut receiver = receiver.compat().fuse();
        let mut event_receiver = event_receiver.compat().fuse();
        //let mut router_message_receiver = router_message_receiver.compat().fuse();

        loop {
            futures::select! {
                message = receiver.select_next_some() => {
                    match message {
                        Ok(msg) => {
                            let node_inner = node_inner.clone();
                            executor.spawn(NodeInner::handle_network_msg(node_inner,msg));
                        },
                        Err(_) => {
                        }
                    }
                },
                (peer_id,message) = router_message_receiver.select_next_some() => {
                       node_inner.send_router_message(peer_id,message).await.unwrap();
                },
                _ = event_receiver.select_next_some() => {
                    debug!("To shutdown network");
                    break;
                }
            }
        }
        info!("shutdown network listener");
    }

    async fn start_command(
        executor: Handle,
        node_inner: Arc<NodeInner>,
        event_receiver: UnboundedReceiver<Event>,
        command_receiver: UnboundedReceiver<NodeMessage>,
        network_service_close_tx: oneshot::Sender<()>,
    ) {
        info!("start receive command");
        let mut event_receiver = event_receiver.compat().fuse();
        let mut command_receiver = command_receiver.compat().fuse();

        loop {
            futures::select! {
                node_message = command_receiver.select_next_some()=>{
                    match node_message {
                        Ok(msg) => {
                            let node_inner = node_inner.clone();
                            executor.spawn(NodeInner::handle_node_msg(node_inner,msg));
                        },
                        Err(_) => {}
                    }
                },
                _ = event_receiver.select_next_some() => {
                    debug!("To shutdown command ");
                    let _ = network_service_close_tx.send(());
                    node_inner.shutdown().await;
                    break;
                }
                complete => {
                    warn!("all stream are complete");
                    break;
                }
            }
        }
        info!("shutdown command listener");
    }
}

impl Node {
    pub fn wallet(&self) -> Arc<WalletHandle> {
        self.wallet.clone()
    }
}

impl NodeInner {
    async fn shutdown(&self) {
        if let Err(e) = self.wallet.stop().await {
            error!("fail to stop wallet, {}", e);
        }
        //        match self.router.shutdown().await {
        //            Ok(_) => {
        //                info!("shutdown router succ");
        //            }
        //            Err(e) => {
        //                warn!("check shutdown router error,{}", e);
        //            }
        //        }
    }

    async fn send_router_message(
        &self,
        peer_id: AccountAddress,
        msg: RouterNetworkMessage,
    ) -> Result<()> {
        let data = msg.into_proto_bytes()?;
        let msg = add_message_type(data, MessageType::RouterMessage);
        self.sender.unbounded_send(NetworkMessage {
            peer_id,
            data: msg.to_vec(),
        })?;
        Ok(())
    }

    async fn handle_network_msg(node_inner: Arc<NodeInner>, msg: NetworkMessage) {
        let peer_id = msg.peer_id;
        info!("receive message from {}", peer_id);
        let data = bytes::Bytes::from(msg.data);
        let msg_type = parse_message_type(&data);
        info!("message type is {:?}", msg_type);
        match msg_type {
            MessageType::OpenChannelNodeNegotiateMessage => {}
            MessageType::ChannelTransactionRequest => node_inner
                .handle_receiver_channel(data[2..].to_vec(), peer_id)
                .await
                .unwrap(),
            MessageType::ChannelTransactionResponse => node_inner
                .handle_sender_channel(data[2..].to_vec(), peer_id)
                .await
                .unwrap(),
            MessageType::ErrorMessage => node_inner.handle_error_message(data[2..].to_vec()),
            MessageType::MultiHopChannelTransactionRequest => node_inner
                .handle_multi_hop_receiver_channel(data[2..].to_vec(), peer_id)
                .await
                .unwrap(),
            MessageType::RouterMessage => node_inner
                .handle_router_msg(peer_id, data[2..].to_vec())
                .await
                .unwrap(),
        };
    }

    async fn handle_router_msg(&self, peer_id: AccountAddress, data: Vec<u8>) -> Result<()> {
        let msg = RouterNetworkMessage::from_proto_bytes(data)?;
        self.router_message_sender.unbounded_send((peer_id, msg))?;
        Ok(())
    }

    async fn handle_node_msg(node_inner: Arc<NodeInner>, msg: NodeMessage) {
        match msg {
            NodeMessage::Install {
                channel_script_package,
                responder,
            } => {
                node_inner
                    .install_package(channel_script_package, responder)
                    .await;
            }
            NodeMessage::Execute {
                receiver_address,
                package_name,
                script_name,
                transaction_args,
                responder,
            } => {
                node_inner
                    .execute_script(
                        receiver_address,
                        package_name,
                        script_name,
                        transaction_args,
                        responder,
                    )
                    .await;
            }
            NodeMessage::Deposit {
                receiver,
                sender_amount,
                responder,
            } => {
                node_inner.deposit(receiver, sender_amount, responder).await;
            }
            NodeMessage::OpenChannel {
                receiver,
                sender_amount,
                receiver_amount,
                responder,
            } => {
                info!("get open channel message");
                node_inner
                    .open_channel(receiver, sender_amount, receiver_amount, responder)
                    .await;
            }
            NodeMessage::Withdraw {
                receiver,
                sender_amount,
                responder,
            } => {
                node_inner
                    .withdraw(receiver, sender_amount, responder)
                    .await;
            }
            NodeMessage::ChannelPay {
                receiver_address,
                amount,
                responder,
            } => {
                node_inner
                    .off_chain_pay(receiver_address, amount, responder)
                    .await
                    .unwrap();
            }
            NodeMessage::ChannelPayHTLC {
                receiver_address,
                amount,
                hash_lock,
                timeout,
                responder,
            } => {
                node_inner
                    .off_chain_pay_htlc(receiver_address, amount, hash_lock, timeout, responder)
                    .await
                    .unwrap();
            }
            NodeMessage::ChannelBalance {
                participant,
                responder,
            } => {
                node_inner.channel_balance(participant, responder).await;
            }
            NodeMessage::DeployModule {
                module_code,
                responder,
            } => {
                node_inner.deploy_module(module_code, responder).await;
            }
            NodeMessage::ChainBalance { responder } => {
                node_inner.chain_balance(responder).await;
            }
            NodeMessage::TxnBySn {
                participant_address,
                channel_seq_number,
                responder,
            } => {
                node_inner
                    .tnx_by_sn(participant_address, channel_seq_number, responder)
                    .await;
            }
            NodeMessage::SetTimeout {
                default_future_timeout,
            } => {
                node_inner.set_timeout(default_future_timeout);
            }
            NodeMessage::ChannelTransactionProposal {
                participant_address,
                transaction_hash,
                approve,
                responder,
            } => {
                node_inner
                    .channel_transaction_proposal(
                        participant_address,
                        transaction_hash,
                        approve,
                        responder,
                    )
                    .await;
            }
        }
    }

    async fn handle_multi_hop_receiver_channel(
        &self,
        data: Vec<u8>,
        peer_id: AccountAddress,
    ) -> Result<()> {
        info!("handle_multi_hop_receiver_channel");
        let mut open_channel_message = MultiHopChannelRequest::from_proto_bytes(data)?;

        self.handle_channel_transaction_request(peer_id, &open_channel_message.request)
            .await?;

        info!("hops is {:?}", open_channel_message.hops);
        if open_channel_message.hops.len() > 0 {
            let operator = open_channel_message.request.channel_txn().operator();
            let hop = open_channel_message.hops.remove(0);
            if is_htlc_transfer(operator) {
                let payment =
                    parse_htlc_payment(open_channel_message.request.channel_txn().args())?;
                let request = self
                    .wallet
                    .send_payment(
                        hop.remote_addr.clone(),
                        hop.amount,
                        payment.hash_lock().to_vec(),
                        payment.timeout(),
                    )
                    .await?;
                let multi_request = MultiHopChannelRequest::new(request, open_channel_message.hops);
                self.send_multi_hop_channel_request(
                    hop.remote_addr,
                    multi_request,
                    MessageType::MultiHopChannelTransactionRequest,
                )?;
                self.invoice_mgr
                    .add_previous_hop(payment.hash_lock().clone(), peer_id)
                    .await;
            } else {
                warn!("should be a htlc transfer");
            }
        }
        Ok(())
    }

    async fn handle_receiver_channel(&self, data: Vec<u8>, peer_id: AccountAddress) -> Result<()> {
        info!("receive channel");
        let open_channel_message = ChannelTransactionRequest::from_proto_bytes(data)?;

        self.handle_channel_transaction_request(peer_id, &open_channel_message)
            .await?;

        Ok(())
    }

    async fn handle_channel_transaction_request(
        &self,
        peer_id: AccountAddress,
        open_channel_message: &ChannelTransactionRequest,
    ) -> Result<()> {
        // sign message ,verify messsage,no send back
        let request_id = open_channel_message.request_id();
        let operator = open_channel_message.channel_txn().operator();
        let receiver_open_txn: ChannelTransactionResponse;
        match self.wallet.verify_txn(peer_id, &open_channel_message).await {
            Ok(tx) => {
                match tx {
                    Some(t) => receiver_open_txn = t,
                    None => {
                        if self.auto_approve {
                            receiver_open_txn =
                                self.wallet.approve_txn(peer_id, request_id).await.unwrap()
                        } else {
                            info!("need approved by user");
                            return Ok(()); // it means user approval is needed.
                        }
                    }
                }
            }
            Err(e) => {
                warn!("verify error {}", e);
                self.sender
                    .unbounded_send(NetworkMessage {
                        peer_id,
                        data: error_message(e, request_id).to_vec(),
                    })
                    .unwrap();
                return Ok(());
            }
        }
        self.apply_txn(peer_id, request_id, receiver_open_txn).await;
        if is_htlc_transfer(operator) {
            let payment = parse_htlc_payment(open_channel_message.channel_txn().args())?;
            match self.invoice_mgr.get_preimage(payment.hash_lock()).await {
                Some(preimage) => {
                    let request = self.wallet.receive_payment(peer_id, preimage).await?;
                    info!("last hop generate request");
                    self.send_channel_request(
                        peer_id,
                        request,
                        MessageType::ChannelTransactionRequest,
                    )?;
                }
                None => {
                    info!(
                        "could not find preimage by rhash {},wait for timeout",
                        payment.hash_lock()
                    );
                }
            }
        }
        if is_htlc_receive(operator) {
            let preimage = parse_htlc_preimage(open_channel_message.channel_txn().args())?;
            match self
                .invoice_mgr
                .get_previous_hop(preimage.clone().to_vec())
                .await
            {
                Some(previous_addr) => {
                    info!(
                        "get router receive payment message from {} to {}",
                        peer_id, previous_addr
                    );
                    let request = self
                        .wallet
                        .receive_payment(previous_addr.clone(), preimage.to_vec())
                        .await?;
                    self.send_channel_request(
                        previous_addr,
                        request,
                        MessageType::ChannelTransactionRequest,
                    )?;
                }
                None => {
                    info!(
                        "could not find privous addr by preimage {},wait for timeout",
                        preimage
                    );
                }
            }
        }
        Ok(())
    }

    async fn apply_txn(
        &self,
        peer_id: AccountAddress,
        request_id: HashValue,
        receiver_open_txn: ChannelTransactionResponse,
    ) {
        let msg = add_message_type(
            receiver_open_txn.clone().into_proto_bytes().unwrap(),
            MessageType::ChannelTransactionResponse,
        );
        debug!("send msg to {:?}", peer_id);
        self.sender
            .unbounded_send(NetworkMessage {
                peer_id,
                data: msg.to_vec(),
            })
            .unwrap();
        match self.wallet.apply_txn(peer_id, &receiver_open_txn).await {
            Ok(_) => {}
            Err(e) => {
                warn!("apply tx fail, err: {:?}", &e);
                self.sender
                    .unbounded_send(NetworkMessage {
                        peer_id,
                        data: error_message(e, request_id).to_vec(),
                    })
                    .unwrap();
                return;
            }
        };
    }

    async fn handle_sender_channel(&self, data: Vec<u8>, peer_id: AccountAddress) -> Result<()> {
        debug!("sender channel");
        let open_channel_message = ChannelTransactionResponse::from_proto_bytes(&data)?;

        self.wallet
            .verify_txn_response(peer_id, &open_channel_message)
            .await?;

        self.wallet
            .apply_txn(peer_id, &open_channel_message)
            .await?;

        let channel_seq_number = self.wallet.channel_sequence_number(peer_id).await?;

        self.message_processor
            .send_response(open_channel_message.request_id(), channel_seq_number)?;

        self.router.stats(
            (self.wallet.account(), peer_id),
            (open_channel_message.request_id(), 0, PayEnum::Payed),
        )
    }

    fn handle_error_message(&self, data: Vec<u8>) {
        debug!("off error message");
        match ErrorMessage::from_proto_bytes(&data) {
            Ok(msg) => {
                self.message_processor.future_error(msg).unwrap();
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }
    }

    fn send_channel_request(
        &self,
        peer_id: AccountAddress,
        open_channel_message: ChannelTransactionRequest,
        msg_type: MessageType,
    ) -> Result<MessageFuture<u64>> {
        let hash_value = open_channel_message.request_id();
        let msg = add_message_type(open_channel_message.into_proto_bytes().unwrap(), msg_type);
        self.sender.unbounded_send(NetworkMessage {
            peer_id,
            data: msg.to_vec(),
        })?;
        let (tx, rx) = futures_01::sync::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor.add_future(hash_value.clone(), tx);
        self.future_timeout(
            hash_value,
            self.default_future_timeout.load(Ordering::Relaxed),
        );

        Ok(message_future)
    }

    fn send_multi_hop_channel_request(
        &self,
        peer_id: AccountAddress,
        open_channel_message: MultiHopChannelRequest,
        msg_type: MessageType,
    ) -> Result<MessageFuture<u64>> {
        let hash_value = open_channel_message.request.request_id();
        let msg = add_message_type(open_channel_message.into_proto_bytes().unwrap(), msg_type);
        self.sender.unbounded_send(NetworkMessage {
            peer_id,
            data: msg.to_vec(),
        })?;
        let (tx, rx) = futures_01::sync::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor.add_future(hash_value.clone(), tx);
        self.future_timeout(
            hash_value,
            self.default_future_timeout.load(Ordering::Relaxed),
        );

        Ok(message_future)
    }

    async fn off_chain_pay(
        &self,
        receiver_address: AccountAddress,
        amount: u64,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) -> Result<()> {
        match self.wallet.transfer(receiver_address, amount).await {
            Ok(off_chain_pay_tx) => {
                self.router.stats(
                    (self.wallet.account(), receiver_address),
                    (off_chain_pay_tx.request_id(), amount, PayEnum::Paying),
                )?;
                respond_with(
                    responder,
                    self.send_channel_request(
                        receiver_address,
                        off_chain_pay_tx,
                        MessageType::ChannelTransactionRequest,
                    ),
                );
            }
            Err(e) => respond_with(responder, Err(e)),
        }
        Ok(())
    }

    async fn off_chain_pay_htlc(
        &self,
        receiver_address: AccountAddress,
        amount: u64,
        hash_lock: Vec<u8>,
        timeout: u64,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) -> Result<()> {
        self.router.stats(
            (self.wallet.account(), receiver_address),
            (
                HashValue::from_sha3_256(&hash_lock),
                amount,
                PayEnum::Paying,
            ),
        )?;

        let path = self
            .router
            .find_path_by_addr(self.wallet.account(), receiver_address)
            .await;
        match path {
            Ok(v) => {
                info!("path is {:?}", v);
                let is_balance_enough = self.check_balance(&v, amount)?;
                info!("is balance enough is {}", is_balance_enough);
                if is_balance_enough == false {
                    let err = SgError::new(
                        SgErrorCode::BALANCE_NOT_ENOUGH,
                        format!(
                            "path balance is not enough ,from {} to {}",
                            self.wallet.account(),
                            receiver_address
                        ),
                    );
                    respond_with(responder, Err(err.into()));
                    return Ok(());
                }
                let v = self.balance_response_to_address(&v)?;
                match self
                    .get_multi_hop_request(v, amount, hash_lock, timeout)
                    .await
                {
                    Ok((off_chain_pay_tx, next_addr)) => respond_with(
                        responder,
                        self.send_multi_hop_channel_request(
                            next_addr,
                            off_chain_pay_tx,
                            MessageType::MultiHopChannelTransactionRequest,
                        ),
                    ),
                    Err(e) => respond_with(responder, Err(e)),
                };
            }
            _ => {
                let err = SgError::new(
                    SgErrorCode::NOT_PATH,
                    format!(
                        "could not find path ,from {} to {}",
                        self.wallet.account(),
                        receiver_address
                    ),
                );
                respond_with(responder, Err(err.into()));
                return Ok(());
            }
        };
        Ok(())
    }

    fn check_balance(&self, path: &Vec<BalanceQueryResponse>, amount: u64) -> Result<bool> {
        for response in path {
            if response.local_balance < amount {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn balance_response_to_address(
        &self,
        response_list: &Vec<BalanceQueryResponse>,
    ) -> Result<Vec<AccountAddress>> {
        let mut result = Vec::new();
        ensure!(response_list.len() >= 1, "should have at least 1 hops");
        result.push(
            response_list
                .get(0)
                .expect("should have")
                .local_addr
                .clone(),
        );
        for response in response_list {
            result.push(response.remote_addr.clone());
        }
        Ok(result)
    }

    // vertexes contains node self. need pop self out
    async fn get_multi_hop_request(
        &self,
        mut vertexes: Vec<AccountAddress>,
        amount: u64,
        hash_lock: Vec<u8>,
        timeout: u64,
    ) -> Result<(MultiHopChannelRequest, AccountAddress)> {
        let len = vertexes.len();
        ensure!(len >= 2, "should have at least 2 hops");
        let mut hops = Vec::new();
        let first_addr = vertexes.remove(0);
        info!(
            "first hop is {:?},my account addr is {}",
            first_addr,
            self.wallet.account()
        );
        if self.wallet.account() == first_addr {
            let receiver_address = vertexes.remove(0);
            for (index, _vertex) in vertexes.iter().enumerate() {
                let next_hop = NextHop::new(
                    vertexes.get(index).take().expect("should have").clone(),
                    amount,
                );
                hops.push(next_hop);
            }
            let request = self
                .wallet
                .send_payment(receiver_address.clone(), amount, hash_lock, timeout)
                .await?;
            return Ok((MultiHopChannelRequest::new(request, hops), receiver_address));
        } else {
            bail!("can't gen multi hop request")
        }
    }

    async fn execute_script(
        &self,
        receiver_address: AccountAddress,
        package_name: String,
        script_name: String,
        transaction_args: Vec<TransactionArgument>,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        match self
            .wallet
            .execute_script(
                receiver_address,
                &package_name,
                &script_name,
                transaction_args,
            )
            .await
        {
            Ok(script_transaction) => {
                let f = self.send_channel_request(
                    receiver_address,
                    script_transaction,
                    MessageType::ChannelTransactionRequest,
                );
                respond_with(responder, f);
            }
            Err(e) => {
                respond_with(responder, Err(e));
            }
        }
    }

    async fn install_package(
        &self,
        channel_script_package: ChannelScriptPackage,
        responder: futures::channel::oneshot::Sender<Result<()>>,
    ) {
        respond_with(
            responder,
            self.wallet.install_package(channel_script_package).await,
        );
    }

    fn future_timeout(&self, hash: HashValue, timeout: u64) {
        if timeout == 0 {
            return;
        }
        let processor = self.message_processor.clone();
        let task = async move {
            Delay::new(Duration::from_millis(timeout)).await;
            processor.remove_future(hash);
        };
        self.executor.spawn(task);
    }

    async fn init(&self) -> Result<()> {
        let all_channels = self.wallet.get_all_channels().await?;
        for participant in all_channels.iter() {
            match self
                .wallet
                .get_pending_txn_request(participant.clone())
                .await
            {
                Ok(Some(tx_request)) => {
                    if !self.network_service.is_connected(participant.clone()) {
                        warn!(
                            "skip recovery channel with {} for participant is offline",
                            participant
                        );
                        continue;
                    }
                    match self.send_channel_request(
                        participant.clone(),
                        tx_request,
                        MessageType::ChannelTransactionRequest,
                    ) {
                        Ok(f) => {
                            f.compat().await?;
                        }
                        Err(e) => {
                            warn!("send pending txn request err ,{}", e);
                        }
                    }
                }
                Ok(None) => {
                    info!("no pending request with {}", participant);
                }
                Err(e) => {
                    warn!("get pending txn request err ,{}", e);
                }
            }
        }
        Ok(())
    }

    async fn open_channel(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        info!("start open channel ");
        let channel_txn = self
            .wallet
            .open(receiver, sender_amount, receiver_amount)
            .await
            .unwrap();
        info!("get open channel txn");
        let result = self.send_channel_request(
            receiver,
            channel_txn,
            MessageType::ChannelTransactionRequest,
        );
        respond_with(responder, result);
    }

    async fn deposit(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        info!("start deposit ");
        let channel_txn = self.wallet.deposit(receiver, sender_amount).await.unwrap();
        info!("get deposit txn");
        let result = self.send_channel_request(
            receiver,
            channel_txn,
            MessageType::ChannelTransactionRequest,
        );
        respond_with(responder, result);
    }

    async fn withdraw(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        info!("start withdraw ");
        let channel_txn = self.wallet.withdraw(receiver, sender_amount).await.unwrap();
        info!("get withdraw txn");
        let result = self.send_channel_request(
            receiver,
            channel_txn,
            MessageType::ChannelTransactionRequest,
        );
        respond_with(responder, result);
    }

    async fn channel_balance(
        &self,
        participant: AccountAddress,
        responder: futures::channel::oneshot::Sender<Result<u64>>,
    ) {
        let result = self.wallet.channel_balance(participant).await;
        respond_with(responder, result);
    }

    async fn deploy_module(
        &self,
        module_code: Vec<u8>,
        responder: futures::channel::oneshot::Sender<Result<DeployModuleResponse>>,
    ) {
        match self.wallet.deploy_module(module_code).await {
            Ok(proof) => respond_with(responder, Ok(DeployModuleResponse::new(proof))),
            Err(e) => respond_with(responder, Err(e)),
        }
    }

    async fn chain_balance(
        &self,
        responder: futures::channel::oneshot::Sender<Result<AccountResource>>,
    ) {
        responder.send(self.wallet.account_resource()).unwrap();
    }

    async fn tnx_by_sn(
        &self,
        participant_address: AccountAddress,
        channel_seq_number: u64,
        responder: futures::channel::oneshot::Sender<Result<SignedChannelTransaction>>,
    ) {
        responder
            .send(
                self.wallet
                    .get_txn_by_channel_sequence_number(participant_address, channel_seq_number),
            )
            .unwrap();
    }

    pub fn set_timeout(&self, timeout: u64) {
        self.default_future_timeout.swap(timeout, Ordering::Relaxed);
    }

    async fn channel_transaction_proposal(
        &self,
        participant_address: AccountAddress,
        transaction_hash: HashValue,
        approve: bool,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        if approve {
            match self
                .wallet
                .approve_txn(participant_address, transaction_hash)
                .await
            {
                Ok(t) => {
                    self.apply_txn(participant_address, transaction_hash, t)
                        .await;
                }
                Err(e) => {
                    warn!("approve txn {} failed,{}", e, transaction_hash);
                    self.sender
                        .unbounded_send(NetworkMessage {
                            peer_id: participant_address,
                            data: error_message(e, transaction_hash).to_vec(),
                        })
                        .unwrap();
                }
            }
        } else {
            match self
                .wallet
                .reject_txn(participant_address, transaction_hash)
                .await
            {
                Ok(_) => {
                    info!("reject txn {} succ ", transaction_hash);
                    self.sender
                        .unbounded_send(NetworkMessage {
                            peer_id: participant_address,
                            data: error_message(
                                SgError::new(
                                    SgErrorCode::REJECT,
                                    "transaction reject by participant".to_string(),
                                )
                                .into(),
                                transaction_hash,
                            )
                            .to_vec(),
                        })
                        .unwrap();
                }
                Err(e) => {
                    warn!("reject txn {} failed,{}", e, transaction_hash);
                    self.sender
                        .unbounded_send(NetworkMessage {
                            peer_id: participant_address,
                            data: error_message(e, transaction_hash).to_vec(),
                        })
                        .unwrap();
                }
            }
        }

        let (tx, rx) = futures_01::sync::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor
            .add_future(transaction_hash.clone(), tx);
        self.future_timeout(
            transaction_hash,
            self.default_future_timeout.load(Ordering::Relaxed),
        );

        respond_with(responder, Ok(message_future));
    }
}

fn parse_message_type(data: &bytes::Bytes) -> MessageType {
    let data_slice = &data[0..2];
    let type_u16 = u16::from_be_bytes([data_slice[0], data_slice[1]]);
    MessageType::from_type(type_u16).unwrap()
}

fn add_message_type(data: Vec<u8>, messaget_type: MessageType) -> bytes::Bytes {
    let len = u16::to_be_bytes(messaget_type.get_type());
    let mut result_vec = Vec::new();
    result_vec.extend_from_slice(&len);
    result_vec.extend_from_slice(&data);
    bytes::Bytes::from(result_vec)
}

fn error_message(e: Error, hash_value: HashValue) -> bytes::Bytes {
    let error_message: ErrorMessage;
    if let Some(err) = e.downcast_ref::<SgError>() {
        info!("this is a sg error");
        error_message = ErrorMessage::new(hash_value, err.clone());
    } else {
        info!("this is a common error");
        error_message = ErrorMessage::new(
            hash_value,
            SgError::new(sgtypes::sg_error::SgErrorCode::UNKNOWN, format!("{:?}", e)),
        );
    }
    let msg = add_message_type(
        error_message.into_proto_bytes().unwrap(),
        MessageType::ErrorMessage,
    );
    msg
}

fn respond_with<T>(responder: futures::channel::oneshot::Sender<T>, msg: T) {
    if let Err(_t) = responder.send(msg) {
        error!("fail to send back response, receiver is dropped",);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    use futures_timer::Delay;

    #[test]
    fn test_delay() {
        let mut rt = Runtime::new().unwrap();

        let task = async {
            Delay::new(Duration::from_millis(1000)).await;
            println!("ok");
        };
        rt.block_on(task);
    }
}
