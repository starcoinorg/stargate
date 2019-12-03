// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use futures::{
    compat::{Future01CompatExt, Stream01CompatExt},
    prelude::*,
};
use futures_timer::Delay;
use std::{sync::Arc, time::Duration};
use tokio::runtime::TaskExecutor;

use failure::prelude::*;
use libra_crypto::{hash::CryptoHash, HashValue};

use libra_logger::prelude::*;
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
use sgwallet::wallet::Wallet;

use crate::message_processor::{MessageFuture, MessageProcessor};

use crate::node_command::NodeMessage;
use futures_01::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};
use sgtypes::sg_error::SgError;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;

pub struct Node {
    executor: TaskExecutor,
    node_inner: Option<NodeInner>,
    event_sender: UnboundedSender<Event>,
    command_sender: UnboundedSender<NodeMessage>,
    default_max_deposit: u64,
    network_service: NetworkService,
    receiver: Option<UnboundedReceiver<NetworkMessage>>,
    event_receiver: Option<UnboundedReceiver<Event>>,
    command_receiver: Option<UnboundedReceiver<NodeMessage>>,
    network_service_close_tx: Option<oneshot::Sender<()>>,
    wallet: Arc<Wallet>,
}

struct NodeInner {
    wallet: Arc<Wallet>,
    executor: TaskExecutor,
    sender: UnboundedSender<NetworkMessage>,
    message_processor: MessageProcessor<u64>,
    network_processor: MessageProcessor<NodeNetworkMessage>,
    default_future_timeout: u64,
    network_service: NetworkService,
}

impl Node {
    pub fn new(
        executor: TaskExecutor,
        wallet: Wallet,
        network_service: NetworkService,
        sender: UnboundedSender<NetworkMessage>,
        receiver: UnboundedReceiver<NetworkMessage>,
        net_close_tx: oneshot::Sender<()>,
    ) -> Self {
        let executor_clone = executor.clone();
        let (event_sender, event_receiver) = futures_01::sync::mpsc::unbounded();
        let (command_sender, command_receiver) = futures_01::sync::mpsc::unbounded();

        let wallet_arc = Arc::new(wallet);
        let node_inner = NodeInner {
            executor: executor_clone,
            wallet: wallet_arc.clone(),
            sender,
            message_processor: MessageProcessor::new(),
            network_processor: MessageProcessor::new(),
            default_future_timeout: 20000,
            network_service: network_service.clone(),
        };
        Self {
            network_service,
            executor,
            node_inner: Some(node_inner),
            event_sender,
            default_max_deposit: 10000000,
            command_sender,
            receiver: Some(receiver),
            event_receiver: Some(event_receiver),
            command_receiver: Some(command_receiver),
            network_service_close_tx: Some(net_close_tx),
            wallet: wallet_arc,
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
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };
        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(OpenChannelResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(failure::Error::from(e)))
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
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };
        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(DepositResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(failure::Error::from(e)))
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
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };

        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(WithdrawResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(failure::Error::from(e)))
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
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };

        match f.compat().await {
            Ok(_sender) => resp_sender
                .send(Ok(PayResponse {}))
                .expect("Did open channel processor thread panic?"),
            Err(e) => resp_sender
                .send(Err(failure::Error::from(e)))
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

    pub fn start_server(&mut self) {
        let receiver = self.receiver.take().expect("receiver already taken");
        let event_receiver = self.event_receiver.take().expect("receiver already taken");

        let command_receiver = self
            .command_receiver
            .take()
            .expect("receiver already taken");

        let network_service_close_tx = self
            .network_service_close_tx
            .take()
            .expect("tx already taken");

        let node_inner = self.node_inner.take().expect("node inner already taken");

        self.executor.spawn(Self::start(
            node_inner,
            receiver,
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
        transaction_args: Vec<Vec<u8>>,
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
                .send(Err(failure::Error::from(e)))
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
                    .send(Err(failure::Error::from(e)))
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

    async fn start(
        mut node_inner: NodeInner,
        receiver: UnboundedReceiver<NetworkMessage>,
        event_receiver: UnboundedReceiver<Event>,
        command_receiver: UnboundedReceiver<NodeMessage>,
        network_service_close_tx: oneshot::Sender<()>,
    ) {
        info!("start receive message");
        let mut receiver = receiver.compat().fuse();
        let mut event_receiver = event_receiver.compat().fuse();
        let mut command_receiver = command_receiver.compat().fuse();
        match node_inner.init().await {
            Ok(_) => {
                info!("node init success");
            }
            Err(e) => {
                panic!("init node error ,{}", e);
            }
        };

        loop {
            futures::select! {
                message = receiver.select_next_some() => {
                    match message {
                        Ok(msg) => node_inner.handle_network_msg(msg).await,
                        Err(_) => {}
                    }
                },
                node_message = command_receiver.select_next_some()=>{
                    match node_message {
                        Ok(msg) => node_inner.handle_node_msg(msg).await,
                        Err(_) => {}
                    }
                },
                _ = event_receiver.select_next_some() => {
                    debug!("To shutdown network");
                    let _ = network_service_close_tx.send(());
                    break;
                }
            }
        }
        info!("shutdown server listener");
    }
}

impl Node {
    pub fn wallet(&self) -> Arc<Wallet> {
        self.wallet.clone()
    }
}

impl NodeInner {
    async fn handle_network_msg(&mut self, msg: NetworkMessage) {
        info!("receive message ");
        let peer_id = msg.peer_id;
        let data = bytes::Bytes::from(msg.data);
        let msg_type = parse_message_type(&data);
        debug!("message type is {:?}", msg_type);
        match msg_type {
            MessageType::OpenChannelNodeNegotiateMessage => {}
            MessageType::ChannelTransactionRequest => {
                self.handle_receiver_channel(data[2..].to_vec(), peer_id)
            }
            MessageType::ChannelTransactionResponse => {
                self.handle_sender_channel(data[2..].to_vec(), peer_id)
            }
            MessageType::ErrorMessage => self.handle_error_message(data[2..].to_vec()),
            MessageType::BalanceQueryResponse => {
                self.handle_balance_query_response(data[2..].to_vec())
            }
            MessageType::BalanceQueryRequest => {
                self.handle_balance_query_request(data[2..].to_vec(), peer_id)
            }
        };
    }

    async fn handle_node_msg(&mut self, msg: NodeMessage) {
        match msg {
            NodeMessage::Install {
                channel_script_package,
                responder,
            } => {
                self.install_package(channel_script_package, responder)
                    .await;
            }
            NodeMessage::Execute {
                receiver_address,
                package_name,
                script_name,
                transaction_args,
                responder,
            } => {
                self.execute_script(
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
                self.deposit(receiver, sender_amount, responder).await;
            }
            NodeMessage::OpenChannel {
                receiver,
                sender_amount,
                receiver_amount,
                responder,
            } => {
                info!("get open channel message");
                self.open_channel(receiver, sender_amount, receiver_amount, responder)
                    .await;
            }
            NodeMessage::Withdraw {
                receiver,
                sender_amount,
                responder,
            } => {
                self.withdraw(receiver, sender_amount, responder).await;
            }
            NodeMessage::ChannelPay {
                receiver_address,
                amount,
                responder,
            } => {
                self.off_chain_pay(receiver_address, amount, responder)
                    .await;
            }
            NodeMessage::ChannelBalance {
                participant,
                responder,
            } => {
                self.channel_balance(participant, responder).await;
            }
            NodeMessage::DeployModule {
                module_code,
                responder,
            } => {
                self.deploy_module(module_code, responder).await;
            }
            NodeMessage::ChainBalance { responder } => {
                self.chain_balance(responder).await;
            }
            NodeMessage::TxnBySn {
                participant_address,
                channel_seq_number,
                responder,
            } => {
                self.tnx_by_sn(participant_address, channel_seq_number, responder)
                    .await;
            }
            NodeMessage::SetTimeout {
                default_future_timeout,
            } => {
                self.set_timeout(default_future_timeout);
            }
            NodeMessage::ChannelTransactionProposal {
                participant_address,
                transaction_hash,
                approve,
                responder,
            } => {
                self.channel_transaction_proposal(
                    participant_address,
                    transaction_hash,
                    approve,
                    responder,
                )
                .await;
            }
        }
    }

    fn handle_receiver_channel(&self, data: Vec<u8>, peer_id: AccountAddress) {
        debug!("receive channel");
        let open_channel_message: ChannelTransactionRequest;
        //TODO refactor error handle.
        match ChannelTransactionRequest::from_proto_bytes(data) {
            Ok(msg) => {
                open_channel_message = msg;
            }
            Err(e) => {
                warn!("get wrong message: {}", e);
                return;
            }
        }

        // sign message ,verify messsage,no send back
        let wallet = self.wallet.clone();
        let sender = self.sender.clone();
        let request_id = open_channel_message.request_id();
        let f = async move {
            let receiver_open_txn: ChannelTransactionResponse;
            match wallet.verify_txn(peer_id, &open_channel_message).await {
                Ok(tx) => {
                    match tx {
                        Some(t) => receiver_open_txn = t,
                        None => {
                            receiver_open_txn =
                                wallet.approve_txn(peer_id, request_id).await.unwrap()
                        } // it means user approval is needed.
                    }
                }
                Err(e) => {
                    warn!("verify error {}", e);
                    sender
                        .unbounded_send(NetworkMessage {
                            peer_id,
                            data: error_message(e, request_id).to_vec(),
                        })
                        .unwrap();
                    return;
                }
            }

            Self::apply_txn(peer_id, request_id, receiver_open_txn, sender, wallet).await;
        };

        self.executor.spawn(f);
    }

    async fn apply_txn(
        peer_id: AccountAddress,
        request_id: HashValue,
        receiver_open_txn: ChannelTransactionResponse,
        sender: UnboundedSender<NetworkMessage>,
        wallet: Arc<Wallet>,
    ) {
        let msg = add_message_type(
            receiver_open_txn.clone().into_proto_bytes().unwrap(),
            MessageType::ChannelTransactionResponse,
        );
        debug!("send msg to {:?}", peer_id);
        sender
            .unbounded_send(NetworkMessage {
                peer_id,
                data: msg.to_vec(),
            })
            .unwrap();
        match wallet.apply_txn(peer_id, &receiver_open_txn).await {
            Ok(_) => {}
            Err(e) => {
                warn!("apply tx fail, err: {:?}", &e);
                sender
                    .unbounded_send(NetworkMessage {
                        peer_id,
                        data: error_message(e, request_id).to_vec(),
                    })
                    .unwrap();
                return;
            }
        };
    }

    fn handle_sender_channel(&self, data: Vec<u8>, peer_id: AccountAddress) {
        debug!("sender channel");
        let open_channel_message: ChannelTransactionResponse;

        match ChannelTransactionResponse::from_proto_bytes(&data) {
            Ok(msg) => {
                open_channel_message = msg;
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }

        let wallet = self.wallet.clone();
        let mut message_processor = self.message_processor.clone();
        let f = async move {
            match wallet
                .verify_txn_response(peer_id, &open_channel_message)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "verify txn response failure, peer {:?}, error: {:?}",
                        peer_id, e
                    );
                    return;
                }
            };
            match wallet.apply_txn(peer_id, &open_channel_message).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("apply tx fail, err: {:?}", e);
                    return;
                }
            };
            let channel_seq_number = match wallet.channel_sequence_number(peer_id).await {
                Ok(n) => n,
                Err(e) => {
                    error!("fail to get channel sequence number, err: {:?}", e);
                    return;
                }
            };
            message_processor
                .send_response(open_channel_message.request_id(), channel_seq_number)
                .unwrap();
        };
        self.executor.spawn(f);
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

    fn handle_balance_query_request(&self, data: Vec<u8>, sender_addr: AccountAddress) {
        debug!("off balance query request message");
        match BalanceQueryRequest::from_proto_bytes(&data) {
            Ok(msg) => {
                let response = BalanceQueryResponse::new(msg.local_addr, msg.remote_addr, 0, 0);
                let msg = add_message_type(
                    response.into_proto_bytes().unwrap(),
                    MessageType::BalanceQueryResponse,
                );
                self.sender
                    .unbounded_send(NetworkMessage {
                        peer_id: sender_addr.clone(),
                        data: msg.to_vec(),
                    })
                    .unwrap();
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }
    }

    fn handle_balance_query_response(&mut self, data: Vec<u8>) {
        debug!("off balance query request message");
        match BalanceQueryResponse::from_proto_bytes(&data) {
            Ok(msg) => {
                self.network_processor
                    .send_response(
                        (&msg.local_addr).hash(),
                        NodeNetworkMessage::BalanceQueryResponseEnum(msg),
                    )
                    .unwrap();
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }
    }

    fn channel_txn_onchain(
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
        self.future_timeout(hash_value, self.default_future_timeout);

        Ok(message_future)
    }

    async fn off_chain_pay(
        &self,
        receiver_address: AccountAddress,
        amount: u64,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        match self.wallet.transfer(receiver_address, amount).await {
            Ok(off_chain_pay_tx) => respond_with(
                responder,
                self.send_channel_request(receiver_address, off_chain_pay_tx),
            ),
            Err(e) => respond_with(responder, Err(e)),
        }
    }

    fn send_channel_request(
        &self,
        receiver_address: AccountAddress,
        off_chain_pay_tx: ChannelTransactionRequest,
    ) -> Result<MessageFuture<u64>> {
        let hash_value = off_chain_pay_tx.request_id();
        let msg = add_message_type(
            off_chain_pay_tx.into_proto_bytes().unwrap(),
            MessageType::ChannelTransactionRequest,
        );
        self.sender.unbounded_send(NetworkMessage {
            peer_id: receiver_address,
            data: msg.to_vec(),
        })?;
        let (tx, rx) = futures_01::sync::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor
            .add_future(hash_value.clone(), tx.clone());
        self.future_timeout(hash_value, self.default_future_timeout);
        Ok(message_future)
    }

    async fn execute_script(
        &self,
        receiver_address: AccountAddress,
        package_name: String,
        script_name: String,
        transaction_args: Vec<Vec<u8>>,
        responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        let mut trans_args = Vec::new();
        for arg in transaction_args {
            match lcs::from_bytes(arg.as_slice()) {
                Ok(transaction_arg) => trans_args.push(transaction_arg),
                Err(e) => {
                    respond_with(responder, Err(e.into()));
                    return;
                }
            }
        }

        match self
            .wallet
            .execute_script(receiver_address, &package_name, &script_name, trans_args)
            .await
        {
            Ok(script_transaction) => {
                let f = self.send_channel_request(receiver_address, script_transaction);
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
                    match self.send_channel_request(participant.clone(), tx_request) {
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
        let result = self.channel_txn_onchain(
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
        let result = self.channel_txn_onchain(
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
        let result = self.channel_txn_onchain(
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

    async fn _query_balance(
        &self,
        channel_vec: Vec<(AccountAddress, AccountAddress)>,
    ) -> Result<Vec<BalanceQueryResponse>> {
        let mut result = Vec::new();
        for (local_addr, remote_addr) in channel_vec.iter() {
            let request = BalanceQueryRequest::new(local_addr.clone(), remote_addr.clone());
            let msg = add_message_type(
                request.into_proto_bytes().unwrap(),
                MessageType::BalanceQueryRequest,
            );
            self.sender.unbounded_send(NetworkMessage {
                peer_id: local_addr.clone(),
                data: msg.to_vec(),
            })?;
            let (tx, rx) = futures_01::sync::mpsc::channel(1);
            let message_future = MessageFuture::new(rx);
            self.network_processor
                .add_future(local_addr.hash(), tx.clone());
            let response = message_future.compat().await?;
            match response {
                NodeNetworkMessage::BalanceQueryResponseEnum(data) => {
                    result.push(data);
                }
            }
        }

        Ok(result)
    }

    pub fn set_timeout(&mut self, timeout: u64) {
        self.default_future_timeout = timeout;
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
                    Self::apply_txn(
                        participant_address,
                        transaction_hash,
                        t,
                        self.sender.clone(),
                        self.wallet.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    warn!("approve txn {} failed,{}", e, transaction_hash);
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
                }
                Err(e) => {
                    warn!("reject txn {} failed,{}", e, transaction_hash);
                }
            }
        }

        let (tx, rx) = futures_01::sync::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor
            .add_future(transaction_hash.clone(), tx);
        self.future_timeout(transaction_hash, self.default_future_timeout);

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
        let rt = Runtime::new().unwrap();

        let task = async {
            Delay::new(Duration::from_millis(1000)).await;
            println!("ok");
        };
        rt.block_on(task);
    }
}
