// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use futures::{
    compat::{Future01CompatExt, Stream01CompatExt},
    prelude::*,
};
use futures_timer::Delay;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::runtime::TaskExecutor;

use failure::prelude::*;
use libra_crypto::HashValue;
use libra_logger::prelude::*;
use libra_types::transaction::TransactionArgument;
use libra_types::{account_address::AccountAddress, account_config::AccountResource};
use network::{NetworkMessage, NetworkService};
use node_proto::{
    DeployModuleResponse, DepositResponse, ExecuteScriptResponse, OpenChannelResponse, PayResponse,
    WithdrawResponse,
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
    node_inner: Arc<Mutex<NodeInner>>,
    event_sender: UnboundedSender<Event>,
    command_sender: UnboundedSender<NodeMessage>,
    default_max_deposit: u64,
    network_service: NetworkService,
}

struct NodeInner {
    wallet: Arc<Wallet>,
    executor: TaskExecutor,
    network_service_close_tx: Option<oneshot::Sender<()>>,
    sender: UnboundedSender<NetworkMessage>,
    receiver: Option<UnboundedReceiver<NetworkMessage>>,
    event_receiver: Option<UnboundedReceiver<Event>>,
    command_receiver: Option<UnboundedReceiver<NodeMessage>>,
    message_processor: MessageProcessor<u64>,
    default_future_timeout: u64,
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

        let node_inner = NodeInner {
            executor: executor_clone,
            wallet: Arc::new(wallet),
            network_service_close_tx: Some(net_close_tx),
            sender,
            receiver: Some(receiver),
            event_receiver: Some(event_receiver),
            message_processor: MessageProcessor::new(),
            default_future_timeout: 20000,
            command_receiver: Some(command_receiver),
        };
        Self {
            network_service,
            executor,
            node_inner: Arc::new(Mutex::new(node_inner)),
            event_sender,
            default_max_deposit: 10000000,
            command_sender,
        }
    }

    pub fn open_channel_negotiate(
        &self,
        negotiate_message: OpenChannelNodeNegotiateMessage,
    ) -> Result<()> {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .open_channel_negotiate(negotiate_message)
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
            });

        resp_receiver.await?
    }

    pub async fn deposit_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<DepositResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = match self
            .deposit_async(receiver, sender_amount, receiver_amount)
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
        self.command_sender.unbounded_send(NodeMessage::Deposit {
            receiver,
            sender_amount,
            receiver_amount,
            responder,
        });

        resp_receiver.await?
    }

    pub async fn withdraw_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<WithdrawResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = match self
            .withdraw_async(receiver, sender_amount, receiver_amount)
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
        receiver_amount: u64,
    ) -> Result<MessageFuture<u64>> {
        if receiver_amount < sender_amount {
            bail!("sender amount should smaller than receiver amount.")
        }

        let is_receiver_connected = self.network_service.is_connected(receiver);
        if !is_receiver_connected {
            bail!("could not connect to receiver")
        }
        info!(
            "start to withdraw with {:?} {} {}",
            receiver, sender_amount, receiver_amount
        );

        let (responder, resp_receiver) = futures::channel::oneshot::channel();
        self.command_sender.unbounded_send(NodeMessage::Withdraw {
            receiver,
            sender_amount,
            receiver_amount,
            responder,
        });

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
        self.command_sender.unbounded_send(NodeMessage::ChannelPay {
            receiver_address,
            amount,
            responder,
        });

        resp_receiver.await?
    }

    pub fn start_server(&self) {
        let receiver = self
            .node_inner
            .lock()
            .unwrap()
            .receiver
            .take()
            .expect("receiver already taken");
        let event_receiver = self
            .node_inner
            .lock()
            .unwrap()
            .event_receiver
            .take()
            .expect("receiver already taken");

        let command_receiver = self
            .node_inner
            .lock()
            .unwrap()
            .command_receiver
            .take()
            .expect("receiver already taken");

        self.executor.spawn(Self::start(
            self.node_inner.clone(),
            receiver,
            event_receiver,
            command_receiver,
        ));
    }

    pub async fn local_balance(&self) -> Result<AccountResource> {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .wallet
            .account_resource()
    }

    pub async fn channel_balance_async(&self, participant: AccountAddress) -> Result<u64> {
        let (responder, receiver) = futures::channel::oneshot::channel();

        self.command_sender
            .unbounded_send(NodeMessage::ChannelBalance {
                participant,
                responder,
            });

        receiver.await?
    }

    pub fn set_default_timeout(&self, timeout: u64) {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .default_future_timeout = timeout;
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
        });

        let f = async {
            let result = receiver.await.unwrap().unwrap();

            match result.compat().await {
                Ok(id) => {}
                Err(e) => {}
            }
        };
        self.executor.spawn(f);

        Ok(())
    }

    pub fn deploy_package_oneshot(
        &self,
        module_code: Vec<u8>,
    ) -> futures::channel::oneshot::Receiver<Result<DeployModuleResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let wallet = self.node_inner.clone().lock().unwrap().wallet.clone();
        let f = async move {
            let proof = wallet.deploy_module(module_code).await.unwrap();
            resp_sender
                .send(Ok(DeployModuleResponse::new(proof)))
                .unwrap();
        };
        self.executor.spawn(f);
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

    pub fn execute_script_with_argument(
        &self,
        receiver_address: AccountAddress,
        package_name: String,
        script_name: String,
        transaction_args: Vec<TransactionArgument>,
    ) -> Result<MessageFuture<u64>> {
        unimplemented!()
    }

    pub fn get_txn_by_channel_sequence_number(
        &self,
        participant_address: AccountAddress,
        channel_seq_number: u64,
    ) -> Result<SignedChannelTransaction> {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .get_txn_by_channel_sequence_number(participant_address, channel_seq_number)
    }

    async fn start(
        node_inner: Arc<Mutex<NodeInner>>,
        receiver: UnboundedReceiver<NetworkMessage>,
        event_receiver: UnboundedReceiver<Event>,
        command_receiver: UnboundedReceiver<NodeMessage>,
    ) {
        info!("start receive message");
        let mut receiver = receiver.compat().fuse();
        let mut event_receiver = event_receiver.compat().fuse();
        let mut command_receiver = command_receiver.compat().fuse();
        let net_close_tx = node_inner
            .clone()
            .lock()
            .unwrap()
            .network_service_close_tx
            .take();

        loop {
            futures::select! {
                message = receiver.select_next_some() => {
                    info!("receive message ");
                    match message {
                        Ok(msg)=>{
                            let peer_id = msg.peer_id;
                            let data = bytes::Bytes::from(msg.data);
                            let msg_type=parse_message_type(&data);
                            debug!("message type is {:?}",msg_type);
                            match msg_type {
                                MessageType::OpenChannelNodeNegotiateMessage => {},
                                MessageType::ChannelTransactionRequest => node_inner.clone().lock().unwrap().handle_receiver_channel(data[2..].to_vec()),
                                MessageType::ChannelTransactionResponse => node_inner.clone().lock().unwrap().handle_sender_channel(data[2..].to_vec(),peer_id),
                                MessageType::ErrorMessage => node_inner.clone().lock().unwrap().handle_error_message(data[2..].to_vec()),
                                MessageType::StateSyncMessageRequest => {node_inner.clone().lock().unwrap().handle_state_sync_request(data[2..].to_vec())},
                                MessageType::StateSyncMessageResponse => {node_inner.clone().lock().unwrap().handle_state_sync_response(data[2..].to_vec())},
                                MessageType::SyncTransactionMessageRequest => {node_inner.clone().lock().unwrap().handle_sync_transaction_request(data[2..].to_vec())},
                                MessageType::SyncTransactionMessageResponse => {node_inner.clone().lock().unwrap().handle_sync_transaction_response(data[2..].to_vec())},
                                _=>warn!("message type not found {:?}",msg_type),
                            };
                        },
                        Err(e)=>{

                        }
                    }
                },
                node_message = command_receiver.select_next_some()=>{
                    match node_message{
                        Ok(msg) => {
                            match msg {
                                NodeMessage::Install{
                                    channel_script_package,
                                    responder,
                                } =>{
                                    node_inner.clone().lock().unwrap().install_package(channel_script_package);
                                },
                                NodeMessage::Execute{
                                    receiver_address,
                                    package_name,
                                    script_name,
                                    transaction_args,
                                    responder,
                                } =>{
                                    node_inner.clone().lock().unwrap().execute_script(receiver_address,package_name,script_name,transaction_args);
                                },
                                NodeMessage::Deposit {
                                    receiver,
                                    sender_amount,
                                    receiver_amount,
                                    responder,
                                }=> {

                                },
                                NodeMessage::OpenChannel {
                                    receiver,
                                    sender_amount,
                                    receiver_amount,
                                    responder,
                                }=> {
                                    node_inner.clone().lock().unwrap().open_channel(receiver,sender_amount,receiver_amount,responder);
                                },
                                NodeMessage::Withdraw {
                                    receiver,
                                    sender_amount,
                                    receiver_amount,
                                    responder,
                                }=> {

                                },
                                NodeMessage::ChannelPay {
                                    receiver_address,
                                    amount,
                                    responder,
                                }=> {

                                },
                                NodeMessage::ChannelBalance {
                                    participant,
                                    responder,
                                }=> {

                                },
                            }
                        },
                        Err(e) => {

                        }
                    }
                },
                _ = event_receiver.select_next_some() => {
                    if let Some(sender) = net_close_tx{
                       debug!("To shutdown network");
                       let _ = sender.send(());
                    }
                    break;
                }
            }
        }
        info!("shutdown server listener");
    }
}

impl NodeInner {
    fn handle_receiver_channel(&mut self, data: Vec<u8>) {
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
        let sender_addr = open_channel_message.sender();
        if open_channel_message.receiver() == self.wallet.account() {
            // sign message ,verify messsage,no send back
            let wallet = self.wallet.clone();
            let sender = self.sender.clone();
            let request_id = open_channel_message.request_id();
            let f = async move {
                let receiver_open_txn: ChannelTransactionResponse;
                match wallet.verify_txn(&open_channel_message).await {
                    Ok(tx) => {
                        receiver_open_txn = tx;
                    }
                    Err(e) => {
                        sender
                            .unbounded_send(NetworkMessage {
                                peer_id: sender_addr,
                                data: error_message(e, request_id).to_vec(),
                            })
                            .unwrap();
                        return;
                    }
                }
                let msg = add_message_type(
                    receiver_open_txn.clone().into_proto_bytes().unwrap(),
                    MessageType::ChannelTransactionResponse,
                );
                debug!("send msg to {:?}", sender_addr);
                sender
                    .unbounded_send(NetworkMessage {
                        peer_id: sender_addr,
                        data: msg.to_vec(),
                    })
                    .unwrap();
                match wallet.apply_txn(sender_addr, &receiver_open_txn).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("apply tx fail, err: {:?}", &e);
                        sender
                            .unbounded_send(NetworkMessage {
                                peer_id: sender_addr,
                                data: error_message(e, request_id).to_vec(),
                            })
                            .unwrap();
                        return;
                    }
                };
            };
            self.executor.spawn(f);
        }
    }

    fn handle_sender_channel(&mut self, data: Vec<u8>, receiver_addr: AccountAddress) {
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
            match wallet.apply_txn(receiver_addr, &open_channel_message).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("apply tx fail, err: {:?}", e);
                    return;
                }
            };
            let channel_seq_number = match wallet.channel_sequence_number(receiver_addr).await {
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

    fn handle_error_message(&mut self, data: Vec<u8>) {
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

    fn handle_state_sync_request(&mut self, data: Vec<u8>) {
        let sync_state_message_request: SyncStateMessageRequest;

        match SyncStateMessageRequest::from_proto_bytes(&data) {
            Ok(msg) => {
                sync_state_message_request = msg;
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }

        let wallet = self.wallet.clone();
        let sender = self.sender.clone();
        let f = async move {
            match wallet
                .channel_account_resource(sync_state_message_request.participant)
                .await
            {
                Ok(Some(resouce)) => {
                    let msg = add_message_type(
                        SyncStateMessageResponse::new(resouce.channel_sequence_number())
                            .into_proto_bytes()
                            .unwrap(),
                        MessageType::StateSyncMessageResponse,
                    );
                    sender
                        .unbounded_send(NetworkMessage {
                            peer_id: sync_state_message_request.participant,
                            data: msg.to_vec(),
                        })
                        .unwrap();
                }
                Ok(None) => {
                    warn!(
                        "can't find account resource by participant address {}",
                        sync_state_message_request.participant
                    );
                }
                Err(_) => {
                    warn!(
                        "can't find account resource by participant address {}",
                        sync_state_message_request.participant
                    );
                }
            };
        };
        self.executor.spawn(f);
    }

    fn handle_state_sync_response(&mut self, data: Vec<u8>) {
        let sync_state_message_response: SyncStateMessageResponse;

        match SyncStateMessageResponse::from_proto_bytes(&data) {
            Ok(msg) => {
                sync_state_message_response = msg;
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }
    }

    fn handle_sync_transaction_request(&mut self, data: Vec<u8>) {
        let sync_txn_request: SyncTransactionMessageRequest;

        match SyncTransactionMessageRequest::from_proto_bytes(&data) {
            Ok(msg) => {
                sync_txn_request = msg;
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }

        match self.wallet.get_txn_by_channel_sequence_number(
            sync_txn_request.participant,
            sync_txn_request.channel_sequence_number,
        ) {
            Ok(txn) => {
                let msg = add_message_type(
                    SyncTransactionMessageResponse::new(txn)
                        .into_proto_bytes()
                        .unwrap(),
                    MessageType::SyncTransactionMessageResponse,
                );
                self.sender
                    .unbounded_send(NetworkMessage {
                        peer_id: sync_txn_request.participant,
                        data: msg.to_vec(),
                    })
                    .unwrap();
            }
            Err(e) => {
                warn!(
                    "can't find txn by channel sequence number {} with {}, err: {:?}",
                    sync_txn_request.participant, sync_txn_request.channel_sequence_number, &e
                );
                return;
            }
        }
    }

    fn handle_sync_transaction_response(&mut self, data: Vec<u8>) {
        let sync_txn_response: SyncTransactionMessageResponse;

        match SyncTransactionMessageResponse::from_proto_bytes(&data) {
            Ok(msg) => {
                sync_txn_response = msg;
            }
            Err(_e) => {
                warn!("get wrong message");
                return;
            }
        }
    }

    fn open_channel_negotiate(
        &mut self,
        negotiate_message: OpenChannelNodeNegotiateMessage,
    ) -> Result<()> {
        let addr = negotiate_message.raw_negotiate_message.receiver_addr;
        let msg = negotiate_message.into_proto_bytes()?;
        let msg = add_message_type(msg, MessageType::OpenChannelNodeNegotiateMessage);
        self.sender.unbounded_send(NetworkMessage {
            peer_id: addr,
            data: msg.to_vec(),
        })?;
        Ok(())
    }

    fn channel_txn_onchain(
        &mut self,
        open_channel_message: ChannelTransactionRequest,
        msg_type: MessageType,
    ) -> Result<MessageFuture<u64>> {
        let hash_value = open_channel_message.request_id();
        let addr = open_channel_message.receiver().clone();
        let msg = add_message_type(open_channel_message.into_proto_bytes().unwrap(), msg_type);
        self.sender.unbounded_send(NetworkMessage {
            peer_id: addr,
            data: msg.to_vec(),
        })?;
        let (tx, rx) = futures_01::sync::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor.add_future(hash_value.clone(), tx);
        self.future_timeout(hash_value, self.default_future_timeout);

        Ok(message_future)
    }

    async fn off_chain_pay(
        &mut self,
        receiver_address: AccountAddress,
        amount: u64,
    ) -> Result<MessageFuture<u64>> {
        let off_chain_pay_tx = self.wallet.transfer(receiver_address, amount).await?;
        self.send_channel_request(receiver_address, off_chain_pay_tx)
    }

    fn send_channel_request(
        &mut self,
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
        &mut self,
        receiver_address: AccountAddress,
        package_name: String,
        script_name: String,
        transaction_args: Vec<Vec<u8>>,
    ) -> Result<MessageFuture<u64>> {
        let mut trans_args = Vec::new();
        for arg in transaction_args {
            let transaction_arg = lcs::from_bytes(arg.as_slice())?;
            trans_args.push(transaction_arg);
        }

        let script_transaction = self
            .wallet
            .execute_script(receiver_address, &package_name, &script_name, trans_args)
            .await?;
        self.send_channel_request(receiver_address, script_transaction)
    }

    async fn install_package(&self, channel_script_package: ChannelScriptPackage) -> Result<()> {
        self.wallet.install_package(channel_script_package).await
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

    pub fn get_txn_by_channel_sequence_number(
        &self,
        partipant_address: AccountAddress,
        channel_seq_number: u64,
    ) -> Result<SignedChannelTransaction> {
        self.wallet
            .get_txn_by_channel_sequence_number(partipant_address, channel_seq_number)
    }

    pub async fn init(&self) -> Result<()> {
        let all_chanels = self.wallet.get_all_channels().await?;
        Ok(())
    }

    async fn open_channel(
        &mut self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
        mut responder: futures::channel::oneshot::Sender<Result<MessageFuture<u64>>>,
    ) {
        info!("start open channel ");
        let channel_txn = self
            .wallet
            .open(receiver, sender_amount, receiver_amount)
            .await
            .unwrap();
        info!("get open channel txn");
        let result = self.channel_txn_onchain(channel_txn, MessageType::ChannelTransactionRequest);
        responder.send(result);
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
        rt.spawn(task);
        rt.shutdown_on_idle();
    }
}
