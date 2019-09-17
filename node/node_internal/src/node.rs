use tokio::{runtime::TaskExecutor};
use futures::{
    compat::{Stream01CompatExt, Compat01As03},
    future::FutureExt,
    stream::{Stream, Fuse, StreamExt},
    prelude::*,
    executor::block_on,
};
use std::sync::{Arc, Mutex};
use sgwallet::wallet::Wallet;
use chain_client::ChainClient;
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crypto::{SigningKey, HashValue};
use crypto::test_utils::KeyPair;
use star_types::message::{*};
use proto_conv::{IntoProtoBytes, FromProto, FromProtoBytes};
use types::account_address::AccountAddress;
use failure::prelude::*;
use std::{thread, time};
use logger::prelude::*;
use network::{{NetworkService, NetworkMessage}, Message};
use futures_01::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use state_cache::state_cache::AccountState;
use types::account_config::AccountResource;
use star_types::system_event::Event;
use types::language_storage::StructTag;
use futures_01::{future::Future, sync::oneshot,
                 sync::mpsc::channel,
};
use crate::message_processor::{MessageProcessor, MessageFuture};
use crypto::hash::CryptoHash;
use star_types::channel_transaction::ChannelTransaction;
use futures::compat::Future01CompatExt;
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use node_proto::{OpenChannelResponse, PayResponse, ConnectResponse, DepositResponse, WithdrawResponse, ChannelBalanceResponse};
use futures::future::err;


pub struct Node<C: ChainClient + Send + Sync + 'static> {
    executor: TaskExecutor,
    node_inner: Arc<Mutex<NodeInner<C>>>,
    event_sender: UnboundedSender<Event>,
    default_max_deposit:u64,
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
    pub fn new(executor: TaskExecutor, wallet: Wallet<C>, keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
               mut network_service: NetworkService, sender: UnboundedSender<NetworkMessage>, receiver: UnboundedReceiver<NetworkMessage>,net_close_tx: oneshot::Sender<()>,
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
            default_max_deposit:10000000,
        }
    }

    pub fn open_channel_negotiate(&self, negotiate_message: OpenChannelNodeNegotiateMessage) -> Result<()> {
        self.node_inner.clone().lock().unwrap().open_channel_negotiate(negotiate_message)
    }

    pub fn open_channel_oneshot(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> futures::channel::oneshot::Receiver<Result<OpenChannelResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = self.open_channel_async(receiver, sender_amount, receiver_amount).unwrap();
        let f_to_channel = async {
            match f.compat().await{
                Ok(sender) => resp_sender
                    .send(Ok(OpenChannelResponse{}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor.spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn open_channel_async(&self, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<MessageFuture> {
        if (receiver_amount > self.default_max_deposit) {
            bail!("deposit coin amount too big")
        }
        if (receiver_amount > sender_amount) {
            bail!("sender amount should bigger than receiver amount.")
        }
        let is_receiver_connected = self.node_inner.clone().lock().unwrap().network_service.is_connected(receiver);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        info!("start open channel ");
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.open(receiver, sender_amount, receiver_amount)?;
        info!("get open channel txn");
        let open_channel_message = ChannelTransactionMessage::new(channel_txn);
        let f = self.node_inner.clone().lock().unwrap().channel_txn_onchain(open_channel_message, MessageType::ChannelTransactionMessage);
        f
    }

    pub fn deposit_oneshot(&self,asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> futures::channel::oneshot::Receiver<Result<DepositResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = self.deposit_async(asset_tag,receiver, sender_amount, receiver_amount).unwrap();
        let f_to_channel = async {
            match f.compat().await{
                Ok(sender) => resp_sender
                    .send(Ok(DepositResponse{}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor.spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn deposit_async(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<MessageFuture> {
        if (receiver_amount > self.default_max_deposit) {
            bail!("deposit coin amount too big")
        }
        if (receiver_amount > sender_amount) {
            bail!("sender amount should bigger than receiver amount.")
        }
        let is_receiver_connected = self.node_inner.clone().lock().unwrap().network_service.is_connected(receiver);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.deposit_by_tag(asset_tag, receiver, sender_amount, receiver_amount)?;
        let open_channel_message = ChannelTransactionMessage::new(channel_txn);
        let f = self.node_inner.clone().lock().unwrap().channel_txn_onchain(open_channel_message, MessageType::ChannelTransactionMessage);
        f
    }

    pub fn withdraw_oneshot(&self,asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> futures::channel::oneshot::Receiver<Result<WithdrawResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = self.withdraw_async(asset_tag,receiver, sender_amount, receiver_amount).unwrap();
        let f_to_channel = async {
            match f.compat().await{
                Ok(sender) => resp_sender
                    .send(Ok(WithdrawResponse{}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor.spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn withdraw_async(&self, asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64, receiver_amount: u64) -> Result<MessageFuture> {
        if (receiver_amount < sender_amount) {
            bail!("sender amount should smaller than receiver amount.")
        }

        let is_receiver_connected = self.node_inner.clone().lock().unwrap().network_service.is_connected(receiver);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        info!("start to withdraw with {:?} {} {}", receiver, sender_amount, receiver_amount);
        let channel_txn = self.node_inner.clone().lock().unwrap().wallet.withdraw_by_tag(asset_tag, receiver, sender_amount, receiver_amount)?;
        let open_channel_message = ChannelTransactionMessage::new(channel_txn);
        let f = self.node_inner.clone().lock().unwrap().channel_txn_onchain(open_channel_message, MessageType::ChannelTransactionMessage);
        f
    }

    pub fn off_chain_pay(&self, coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64) -> Result<()> {
        let f = self.off_chain_pay_async(coin_resource_tag, receiver_address, amount);
        f.unwrap().wait().unwrap();
        Ok(())
    }

    pub fn off_chain_pay_oneshot(&self,asset_tag: StructTag, receiver: AccountAddress, sender_amount: u64) -> futures::channel::oneshot::Receiver<Result<PayResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();
        let f = self.off_chain_pay_async(asset_tag,receiver, sender_amount).unwrap();
        let f_to_channel = async {
            match f.compat().await{
                Ok(sender) => resp_sender
                    .send(Ok(PayResponse{}))
                    .expect("Did open channel processor thread panic?"),
                Err(e) => resp_sender
                    .send(Err(failure::Error::from(e)))
                    .expect("Failed to send error message."),
            }
        };
        self.executor.spawn(f_to_channel.boxed().unit_error().compat());
        resp_receiver
    }

    pub fn off_chain_pay_async(&self, coin_resource_tag: StructTag, receiver_address: AccountAddress, amount: u64) -> Result<MessageFuture> {
        let is_receiver_connected = self.node_inner.clone().lock().unwrap().network_service.is_connected(receiver_address);
        if (!is_receiver_connected) {
            bail!("could not connect to receiver")
        }
        let f = self.node_inner.clone().lock().unwrap().off_chain_pay(coin_resource_tag, receiver_address, amount);
        f
    }

    pub fn start_server(&self) {
        let receiver = self.node_inner.lock().unwrap().receiver.take().expect("receiver already taken");
        let event_receiver = self.node_inner.lock().unwrap().event_receiver.take().expect("receiver already taken");
        self.executor.spawn(Self::start(self.node_inner.clone(), receiver, event_receiver).boxed().unit_error().compat());
    }

    pub fn local_balance(&self) -> Result<AccountResource> {
        let account_state_data = self.node_inner.clone().lock().unwrap().wallet.get_account_state();
        let account_state = AccountState::from_account_state_blob(account_state_data).unwrap().get_account_resource();
        match account_state {
            Some(state) => Ok(state),
            None => bail!("data is not ok")
        }
    }

    pub fn channel_balance(&self, participant: AccountAddress, asset_tag: StructTag) -> Result<u64> {
        self.node_inner.clone().lock().unwrap().wallet.channel_balance_by_tag(participant, asset_tag)
    }

    pub fn set_default_timeout(&self, timeout: u64) {
        self.node_inner.clone().lock().unwrap().default_future_timeout = timeout;
    }

    pub fn shutdown(&self) {
        debug!("node send shutdown event");
        self.event_sender.unbounded_send(Event::SHUTDOWN);
    }

    async fn start(node_inner: Arc<Mutex<NodeInner<C>>>, mut receiver: UnboundedReceiver<NetworkMessage>, mut event_receiver: UnboundedReceiver<Event>) {
        info!("start receive message");
        let mut receiver = receiver.compat().fuse();
        let mut event_receiver = event_receiver.compat().fuse();
        let net_close_tx = node_inner.clone().lock().unwrap().network_service_close_tx.take();

        loop {
            futures::select! {
                message = receiver.select_next_some() => {
                    info!("receive message ");
                    if let Message::Payload(payload) = message.unwrap().msg {
                        let data = bytes::Bytes::from(payload.data);

                    let msg_type=parse_message_type(&data);
                    debug!("message type is {:?}",msg_type);
                    match msg_type {
                        MessageType::OpenChannelNodeNegotiateMessage => node_inner.clone().lock().unwrap().handle_open_channel_negotiate(data[2..].to_vec()),
                        MessageType::ChannelTransactionMessage => node_inner.clone().lock().unwrap().handle_channel(data[2..].to_vec()),
                        MessageType::OffChainPayMessage => node_inner.clone().lock().unwrap().handle_off_chain_pay(data[2..].to_vec()),
                        MessageType::ErrorMessage => node_inner.clone().lock().unwrap().handle_error_message(data[2..].to_vec()),
                        _=>warn!("message type not found {:?}",msg_type),
                    };
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
        };
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

    fn handle_channel(&mut self, data: Vec<u8>) {
        debug!("handle_open_channel");
        let open_channel_message:ChannelTransactionMessage;

        match ChannelTransactionMessage::from_proto_bytes(&data){
            Ok(msg)  => {open_channel_message=msg;},
            Err(e) => {
                warn!("get wrong message");
                return;
            },
        }
        let sender_addr = open_channel_message.transaction.txn().clone().sender().clone();
        if (&open_channel_message.transaction.receiver() == &self.wallet.get_address()) {
            // sign message ,verify messsage,no send back
            let wallet = self.wallet.clone();
            let txn = open_channel_message.transaction.clone();
            let sender = self.sender.clone();
            let hash_value = open_channel_message.transaction.clone().txn.into_raw_transaction().hash();
            let f = async move {
                let receiver_open_txn:ChannelTransaction;
                match wallet.verify_txn(&txn){
                    Ok(tx)  => {receiver_open_txn=tx;},
                    Err(e) => {
                        sender.unbounded_send(NetworkMessage{ peer_id: sender_addr, msg: Message::new_message(error_message(e,hash_value).to_vec())});
                        return;
                    },
                }
                let channel_txn_msg = ChannelTransactionMessage::new(receiver_open_txn);
                let msg = add_message_type(channel_txn_msg.into_proto_bytes().unwrap(), MessageType::ChannelTransactionMessage);
                debug!("send msg to {:?}", sender_addr);
                sender.unbounded_send(NetworkMessage{ peer_id: sender_addr, msg: Message::new_message(msg.to_vec())});
                match wallet.apply_txn(&txn).await {
                    Ok(_)  => {},
                    Err(e) => {
                        warn!("apply tx fail");
                        sender.unbounded_send(NetworkMessage{ peer_id: sender_addr, msg: Message::new_message(error_message(e,hash_value).to_vec())});
                        return;
                    },
                };
            };
            self.executor.spawn(f.boxed().unit_error().compat());
        }
        if (&open_channel_message.transaction.txn().sender() == &self.wallet.get_address()) {
            let wallet = self.wallet.clone();
            let txn = open_channel_message.transaction;
            let txn_clone = txn.clone();
            let mut message_processor = self.message_processor.clone();
            let f = async move {
                match wallet.apply_txn(&txn).await{
                    Ok(_)  => {},
                    Err(e) => {
                        warn!("apply tx fail");
                        return;
                    },
                };
                message_processor.send_response(txn_clone);
            };
            self.executor.spawn(f.boxed().unit_error().compat());
        }
    }

    fn handle_off_chain_pay(&mut self, data: Vec<u8>) {
        debug!("off chain pay");
        let off_chain_pay_message:OffChainPayMessage ;

        match OffChainPayMessage::from_proto_bytes(&data){
            Ok(msg)  => {off_chain_pay_message=msg;},
            Err(e) => {
                warn!("get wrong message");
                return;
            },
        }
        let txn = off_chain_pay_message.transaction.clone();
        let txn_clone = txn.clone();
        let local_addr = self.wallet.get_address();
        let sender_addr = off_chain_pay_message.transaction.txn().clone().sender().clone();
        let sender = self.sender.clone();
        if (&txn.receiver() == &local_addr) {
            // sign message ,verify messsage, execute tx local
            debug!("off chain txn as receiver");
            let wallet = self.wallet.clone();
            let sender = self.sender.clone();
            let hash_value = off_chain_pay_message.transaction.clone().txn.into_raw_transaction().hash();
            let f = async move {
                let receiver_open_txn:ChannelTransaction;
                match wallet.verify_txn(&txn){
                    Ok(tx)  => {receiver_open_txn=tx;},
                    Err(e) => {
                        sender.unbounded_send(NetworkMessage{ peer_id: sender_addr, msg: Message::new_message(error_message(e,hash_value).to_vec())});
                        return;
                    },
                }
                match wallet.apply_txn(&txn).await {
                    Ok(_)  => {},
                    Err(e) => {
                        warn!("apply tx fail");
                        sender.unbounded_send(NetworkMessage{ peer_id: sender_addr, msg: Message::new_message(error_message(e,hash_value).to_vec())});
                        return;
                    },
                };
                let channel_txn_msg = OffChainPayMessage::new(receiver_open_txn);
                let msg = add_message_type(channel_txn_msg.into_proto_bytes().unwrap(), MessageType::OffChainPayMessage);
                info!("send msg to {:?}", sender_addr);
                sender.unbounded_send(NetworkMessage{ peer_id: sender_addr, msg: Message::new_message(msg.to_vec())});
            };
            self.executor.spawn(f.boxed().unit_error().compat());
        }
        if (&txn_clone.txn().sender() == &local_addr) {
            debug!("receive feed back pay");
            let wallet = self.wallet.clone();
            let txn = txn_clone.clone();
            let mut message_processor = self.message_processor.clone();
            let f = async move {
                match wallet.apply_txn(&txn).await{
                    Ok(_)  => {},
                    Err(e) => {
                        warn!("apply tx fail");
                        return;
                    },
                };
                message_processor.send_response(txn_clone);
            };
            self.executor.spawn(f.boxed().unit_error().compat());
            info!("tx succ");
        }
    }

    fn handle_error_message(&mut self, data: Vec<u8>){
        debug!("off error message");
        let err_message:ErrorMessage ;

        match ErrorMessage::from_proto_bytes(&data){
            Ok(msg)  => {
                self.message_processor.remove_future(msg.raw_transaction_hash);
                err_message=msg;
            },
            Err(e) => {
                warn!("get wrong message");
                return;
            },
        }
    }

    fn open_channel_negotiate(&mut self, negotiate_message: OpenChannelNodeNegotiateMessage) -> Result<()> {
        let addr = negotiate_message.raw_negotiate_message.receiver_addr;
        let msg = negotiate_message.into_proto_bytes()?;
        let msg = add_message_type(msg, MessageType::OpenChannelNodeNegotiateMessage);
        self.sender.unbounded_send(NetworkMessage{ peer_id: addr, msg: Message::new_message(msg.to_vec())});
        Ok(())
    }

    fn channel_txn_onchain(&mut self, open_channel_message: ChannelTransactionMessage, msg_type: MessageType) -> Result<MessageFuture> {
        let sender = self.sender.clone();

        let hash_value = open_channel_message.transaction.clone().txn.into_raw_transaction().hash();
        let addr = open_channel_message.transaction.receiver().clone();
        let msg = add_message_type(open_channel_message.into_proto_bytes().unwrap(), msg_type);
        self.sender.unbounded_send(NetworkMessage{ peer_id: addr, msg: Message::new_message(msg.to_vec())});
        let (tx, rx) = channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor.add_future(hash_value.clone(), tx);
        self.future_timeout(hash_value,self.default_future_timeout);

        Ok(message_future)
    }

    fn off_chain_pay(&mut self, coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64) -> Result<MessageFuture> {
        let off_chain_pay_tx = self.wallet.transfer_by_tag(coin_resource_tag, receiver_address, amount)?;
        let sender = self.sender.clone();
        let hash_value = off_chain_pay_tx.clone().txn.into_raw_transaction().hash();
        let off_chain_pay_msg = OffChainPayMessage {
            transaction: off_chain_pay_tx,
        };
        let msg = add_message_type(off_chain_pay_msg.into_proto_bytes().unwrap(), MessageType::OffChainPayMessage);

        self.sender.unbounded_send(NetworkMessage{ peer_id: receiver_address, msg: Message::new_message(msg.to_vec())});
        let (tx, rx) = channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor.add_future(hash_value.clone(), tx.clone());
        self.future_timeout(hash_value,self.default_future_timeout);

        Ok(message_future)
    }

    fn future_timeout(&self,hash:HashValue,timeout:u64){
        if(timeout==0){
            return
        }
        let processor=self.message_processor.clone();
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

fn error_message(e:Error,hash_value:HashValue)->bytes::Bytes{
    let error_message :ErrorMessage;
    if let Some(err) = e.downcast_ref::<SgError>() {
        info!("this is a sg error");
        error_message=ErrorMessage::new(hash_value,err.clone());
    } else {
        info!("this is a common error");
        error_message=ErrorMessage::new(hash_value,SgError::new(0,format!("{:?}", e)));
    }
    let msg = add_message_type(error_message.into_proto_bytes().unwrap(), MessageType::ErrorMessage);
    msg
}