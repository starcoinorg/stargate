use std::{
    sync::{Arc, Mutex},
    thread,
    time::{self, Duration, Instant},
};

use futures::{
    compat::{Compat01As03, Future01CompatExt, Stream01CompatExt},
    executor::block_on,
    future::{err, FutureExt},
    prelude::*,
    stream::{Fuse, Stream, StreamExt},
};
use futures_01::{
    future::Future,
    sync::{
        mpsc::{channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};
use tokio::{runtime::TaskExecutor, timer::Delay};

use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, SigningKey,
};
use failure::prelude::*;
use logger::prelude::*;
use network::{Message, NetworkMessage, NetworkService};
use node_proto::{
    ChannelBalanceResponse, ConnectResponse, DepositResponse, OpenChannelResponse, PayResponse,
    WithdrawResponse,
};
use proto_conv::{FromProto, FromProtoBytes, IntoProtoBytes};
use sgchain::star_chain_client::ChainClient;
use sgwallet::wallet::Wallet;
use star_types::{
    channel_transaction::{ChannelTransactionRequest, ChannelTransactionResponse},
    message::*,
    system_event::Event,
};
use types::{account_address::AccountAddress, account_config::AccountResource};

use crate::message_processor::{MessageFuture, MessageProcessor};
use star_types::script_package::ChannelScriptPackage;

pub struct Node<C: ChainClient + Send + Sync + 'static> {
    executor: TaskExecutor,
    node_inner: Arc<Mutex<NodeInner<C>>>,
    event_sender: UnboundedSender<Event>,
    default_max_deposit: u64,
}

struct NodeInner<C: ChainClient + Send + Sync + 'static> {
    wallet: Arc<Wallet<C>>,
    executor: TaskExecutor,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    network_service: NetworkService,
    network_service_close_tx: Option<oneshot::Sender<()>>,
    sender: UnboundedSender<NetworkMessage>,
    receiver: Option<UnboundedReceiver<NetworkMessage>>,
    event_receiver: Option<UnboundedReceiver<Event>>,
    message_processor: MessageProcessor,
    default_future_timeout: u64,
}

impl<C: ChainClient + Send + Sync + 'static> Node<C> {
    pub fn new(
        executor: TaskExecutor,
        wallet: Wallet<C>,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        mut network_service: NetworkService,
        sender: UnboundedSender<NetworkMessage>,
        receiver: UnboundedReceiver<NetworkMessage>,
        net_close_tx: oneshot::Sender<()>,
    ) -> Self {
        let executor_clone = executor.clone();
        let (event_sender, event_receiver) = futures_01::sync::mpsc::unbounded();

        let node_inner = NodeInner {
            executor: executor_clone,
            keypair,
            wallet: Arc::new(wallet),
            network_service,
            network_service_close_tx: Some(net_close_tx),
            sender,
            receiver: Some(receiver),
            event_receiver: Some(event_receiver),
            message_processor: MessageProcessor::new(),
            default_future_timeout: 20000,
        };
        Self {
            executor,
            node_inner: Arc::new(Mutex::new(node_inner)),
            event_sender,
            default_max_deposit: 10000000,
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

    pub fn open_channel_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<OpenChannelResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f: MessageFuture;
        match self.open_channel_async(receiver, sender_amount, receiver_amount) {
            Ok(msg_future) => {
                f = msg_future;
            }
            Err(e) => {
                resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };

        let f_to_channel = async {
            match f.compat().await {
                Ok(sender) => resp_sender
                    .send(Ok(OpenChannelResponse {}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor
            .spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn open_channel_async(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<MessageFuture> {
        if (receiver_amount > self.default_max_deposit) {
            bail!("deposit coin amount too big")
        }
        if (receiver_amount > sender_amount) {
            bail!("sender amount should bigger than receiver amount.")
        }
        let is_receiver_connected = self
            .node_inner
            .clone()
            .lock()
            .unwrap()
            .network_service
            .is_connected(receiver);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        info!("start open channel ");
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.open(
            receiver,
            sender_amount,
            receiver_amount,
        )?;
        info!("get open channel txn");
        let open_channel_message = ChannelTransactionRequestMessage::new(channel_txn);
        let f = self.node_inner.clone().lock().unwrap().channel_txn_onchain(
            open_channel_message,
            MessageType::ChannelTransactionRequestMessage,
        );
        f
    }

    pub fn deposit_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<DepositResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f: MessageFuture;
        match self.deposit_async(receiver, sender_amount, receiver_amount) {
            Ok(msg_future) => {
                f = msg_future;
            }
            Err(e) => {
                resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };
        let f_to_channel = async {
            match f.compat().await {
                Ok(sender) => resp_sender
                    .send(Ok(DepositResponse {}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor
            .spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn deposit_async(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<MessageFuture> {
        if (receiver_amount > self.default_max_deposit) {
            bail!("deposit coin amount too big")
        }
        if (receiver_amount > sender_amount) {
            bail!("sender amount should bigger than receiver amount.")
        }
        let is_receiver_connected = self
            .node_inner
            .clone()
            .lock()
            .unwrap()
            .network_service
            .is_connected(receiver);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.deposit(
            receiver,
            sender_amount,
            receiver_amount,
        )?;
        let open_channel_message = ChannelTransactionRequestMessage::new(channel_txn);
        let f = self.node_inner.clone().lock().unwrap().channel_txn_onchain(
            open_channel_message,
            MessageType::ChannelTransactionRequestMessage,
        );
        f
    }

    pub fn withdraw_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<WithdrawResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f: MessageFuture;
        match self.withdraw_async(receiver, sender_amount, receiver_amount) {
            Ok(msg_future) => {
                f = msg_future;
            }
            Err(e) => {
                resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };

        let f_to_channel = async {
            match f.compat().await {
                Ok(sender) => resp_sender
                    .send(Ok(WithdrawResponse {}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor
            .spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn withdraw_async(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
    ) -> Result<MessageFuture> {
        if (receiver_amount < sender_amount) {
            bail!("sender amount should smaller than receiver amount.")
        }

        let is_receiver_connected = self
            .node_inner
            .clone()
            .lock()
            .unwrap()
            .network_service
            .is_connected(receiver);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        info!(
            "start to withdraw with {:?} {} {}",
            receiver, sender_amount, receiver_amount
        );
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.withdraw(
            receiver,
            sender_amount,
            receiver_amount,
        )?;
        let open_channel_message = ChannelTransactionRequestMessage::new(channel_txn);
        let f = self.node_inner.clone().lock().unwrap().channel_txn_onchain(
            open_channel_message,
            MessageType::ChannelTransactionRequestMessage,
        );
        f
    }

    pub fn off_chain_pay_oneshot(
        &self,
        receiver: AccountAddress,
        sender_amount: u64,
    ) -> futures::channel::oneshot::Receiver<Result<PayResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();

        let f: MessageFuture;
        match self.off_chain_pay_async(receiver, sender_amount) {
            Ok(msg_future) => {
                f = msg_future;
            }
            Err(e) => {
                resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message.");
                return resp_receiver;
            }
        };

        let f_to_channel = async {
            match f.compat().await {
                Ok(sender) => resp_sender
                    .send(Ok(PayResponse {}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor
            .spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn off_chain_pay_async(
        &self,
        receiver_address: AccountAddress,
        amount: u64,
    ) -> Result<MessageFuture> {
        let is_receiver_connected = self
            .node_inner
            .clone()
            .lock()
            .unwrap()
            .network_service
            .is_connected(receiver_address);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        let f = self
            .node_inner
            .clone()
            .lock()
            .unwrap()
            .off_chain_pay(receiver_address, amount);
        f
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
        self.executor.spawn(
            Self::start(self.node_inner.clone(), receiver, event_receiver)
                .boxed()
                .unit_error()
                .compat(),
        );
    }

    pub fn local_balance(&self) -> Result<AccountResource> {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .wallet
            .account_resource()
    }

    pub fn channel_balance(&self, participant: AccountAddress) -> Result<u64> {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .wallet
            .channel_balance(participant)
    }

    pub fn set_default_timeout(&self, timeout: u64) {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .default_future_timeout = timeout;
    }

    pub fn shutdown(&self) {
        debug!("node send shutdown event");
        self.event_sender.unbounded_send(Event::SHUTDOWN);
    }

    pub fn install_package(&self, channel_script_package: ChannelScriptPackage) -> Result<()> {
        self.node_inner
            .clone()
            .lock()
            .unwrap()
            .install_package(channel_script_package)
    }

    async fn start(
        node_inner: Arc<Mutex<NodeInner<C>>>,
        mut receiver: UnboundedReceiver<NetworkMessage>,
        mut event_receiver: UnboundedReceiver<Event>,
    ) {
        info!("start receive message");
        let mut receiver = receiver.compat().fuse();
        let mut event_receiver = event_receiver.compat().fuse();
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
                        MessageType::OpenChannelNodeNegotiateMessage => node_inner.clone().lock().unwrap().handle_open_channel_negotiate(data[2..].to_vec()),
                        MessageType::ChannelTransactionRequestMessage => node_inner.clone().lock().unwrap().handle_receiver_channel(data[2..].to_vec()),
                        MessageType::ChannelTransactionResponseMessage => node_inner.clone().lock().unwrap().handle_sender_channel(data[2..].to_vec(),peer_id),
                        MessageType::ErrorMessage => node_inner.clone().lock().unwrap().handle_error_message(data[2..].to_vec()),
                        _=>warn!("message type not found {:?}",msg_type),
                    };
                    },
                    Err(e)=>{

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

impl<C: ChainClient + Send + Sync + 'static> NodeInner<C> {
    fn handle_open_channel_negotiate(&self, data: Vec<u8>) {
        debug!("handle_open_channel_negotiate");
        let negotiate_message = OpenChannelNodeNegotiateMessage::from_proto_bytes(&data).unwrap();
        let raw_message = &(negotiate_message.raw_negotiate_message);
        if (raw_message.sender_addr == self.wallet.get_address()) {
            match negotiate_message.receiver_sign {
                Some(sign) => {
                    debug!("receive 2 sign");
                    // TODO send open channel msg
                }
                None => debug!("none"),
            }
        }
        if (raw_message.receiver_addr == self.wallet.get_address()) {
            // sign message ,verify messsage,send back
            debug!("receive sender neg msg")
        }
    }

    fn handle_receiver_channel(&mut self, data: Vec<u8>) {
        debug!("receive channel");
        let open_channel_message: ChannelTransactionRequestMessage;

        match ChannelTransactionRequestMessage::from_proto_bytes(&data) {
            Ok(msg) => {
                open_channel_message = msg;
            }
            Err(e) => {
                warn!("get wrong message");
                return;
            }
        }
        let sender_addr = open_channel_message.txn_request.txn().clone().sender();
        if (&open_channel_message.txn_request.receiver() == &self.wallet.get_address()) {
            // sign message ,verify messsage,no send back
            let wallet = self.wallet.clone();
            let txn = open_channel_message.txn_request.clone();
            let sender = self.sender.clone();
            let hash_value = open_channel_message.txn_request.txn().hash();
            let f = async move {
                let receiver_open_txn: ChannelTransactionResponse;
                match wallet.verify_txn(&txn) {
                    Ok(tx) => {
                        receiver_open_txn = tx;
                    }
                    Err(e) => {
                        sender.unbounded_send(NetworkMessage {
                            peer_id: sender_addr,
                            data: error_message(e, hash_value).to_vec(),
                        });
                        return;
                    }
                }
                let channel_txn_msg =
                    ChannelTransactionResponseMessage::new(receiver_open_txn.clone());
                let msg = add_message_type(
                    channel_txn_msg.into_proto_bytes().unwrap(),
                    MessageType::ChannelTransactionResponseMessage,
                );
                debug!("send msg to {:?}", sender_addr);
                sender.unbounded_send(NetworkMessage {
                    peer_id: sender_addr,
                    data: msg.to_vec(),
                });
                match wallet.apply_txn(sender_addr, &receiver_open_txn).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("apply tx fail");
                        sender.unbounded_send(NetworkMessage {
                            peer_id: sender_addr,
                            data: error_message(e, hash_value).to_vec(),
                        });
                        return;
                    }
                };
            };
            self.executor.spawn(f.boxed().unit_error().compat());
        }
    }

    fn handle_sender_channel(&mut self, data: Vec<u8>, receiver_addr: AccountAddress) {
        debug!("sender channel");
        let open_channel_message: ChannelTransactionResponseMessage;

        match ChannelTransactionResponseMessage::from_proto_bytes(&data) {
            Ok(msg) => {
                open_channel_message = msg;
            }
            Err(e) => {
                warn!("get wrong message");
                return;
            }
        }

        let wallet = self.wallet.clone();
        let txn_response = open_channel_message.txn_response;
        let mut message_processor = self.message_processor.clone();
        let f = async move {
            match wallet.apply_txn(receiver_addr, &txn_response).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("apply tx fail");
                    return;
                }
            };
            message_processor.send_response(txn_response.request_id());
        };
        self.executor.spawn(f.boxed().unit_error().compat());
    }

    fn handle_error_message(&mut self, data: Vec<u8>) {
        debug!("off error message");
        let err_message: ErrorMessage;

        match ErrorMessage::from_proto_bytes(&data) {
            Ok(msg) => {
                self.message_processor.future_error(msg);
            }
            Err(e) => {
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
        });
        Ok(())
    }

    fn channel_txn_onchain(
        &mut self,
        open_channel_message: ChannelTransactionRequestMessage,
        msg_type: MessageType,
    ) -> Result<MessageFuture> {
        let sender = self.sender.clone();

        let hash_value = open_channel_message.txn_request.request_id();
        let addr = open_channel_message.txn_request.receiver().clone();
        let msg = add_message_type(open_channel_message.into_proto_bytes().unwrap(), msg_type);
        self.sender.unbounded_send(NetworkMessage {
            peer_id: addr,
            data: msg.to_vec(),
        });
        let (tx, rx) = channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor.add_future(hash_value.clone(), tx);
        self.future_timeout(hash_value, self.default_future_timeout);

        Ok(message_future)
    }

    fn off_chain_pay(
        &mut self,
        receiver_address: AccountAddress,
        amount: u64,
    ) -> Result<MessageFuture> {
        let off_chain_pay_tx = self.wallet.transfer(receiver_address, amount)?;
        let sender = self.sender.clone();
        let hash_value = off_chain_pay_tx.request_id();
        let off_chain_pay_msg = ChannelTransactionRequestMessage {
            txn_request: off_chain_pay_tx,
        };
        let msg = add_message_type(
            off_chain_pay_msg.into_proto_bytes().unwrap(),
            MessageType::ChannelTransactionRequestMessage,
        );

        self.sender.unbounded_send(NetworkMessage {
            peer_id: receiver_address,
            data: msg.to_vec(),
        });
        let (tx, rx) = channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor
            .add_future(hash_value.clone(), tx.clone());
        self.future_timeout(hash_value, self.default_future_timeout);

        Ok(message_future)
    }

    fn install_package(&self, channel_script_package: ChannelScriptPackage) -> Result<()> {
        self.wallet.install_package(channel_script_package)
    }

    fn future_timeout(&self, hash: HashValue, timeout: u64) {
        if (timeout == 0) {
            return;
        }
        let processor = self.message_processor.clone();
        let task = Delay::new(Instant::now() + Duration::from_millis(timeout))
            .and_then(move |_| {
                processor.remove_future(hash);
                Ok(())
            })
            .map_err(|e| panic!("delay errored; err={:?}", e));
        self.executor.spawn(task);
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
            SgError::new(
                star_types::sg_error::SgErrorCode::UNKNOWN,
                format!("{:?}", e),
            ),
        );
    }
    let msg = add_message_type(
        error_message.into_proto_bytes().unwrap(),
        MessageType::ErrorMessage,
    );
    msg
}
