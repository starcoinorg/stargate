use switch::{switch::Switch};
use netcore::transport::{Transport};
use parity_multiaddr::Multiaddr;
use tokio::{codec::{Framed,LengthDelimitedCodec}, runtime::TaskExecutor};
use futures::{
    compat::{Sink01CompatExt,Stream01CompatExt,Compat01As03Sink,Compat01As03},
    future::{FutureExt},
    stream::{Stream,Fuse,StreamExt,FuturesUnordered},
    io::{AsyncRead, AsyncWrite},
    prelude::*,
    sink::{SinkExt},
    channel::mpsc::{UnboundedReceiver,UnboundedSender},
};
use std::sync::{Arc,Mutex};
use sgwallet::wallet::Wallet;
use chain_client::{ChainClient};
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crypto::SigningKey;
use crypto::test_utils::KeyPair;
use tokio::sync::mpsc::{channel,Sender,Receiver};
use star_types::message::{*};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes,IntoProto};
use std::collections::HashMap;
use types::account_address::AccountAddress;
use failure::prelude::*;
use std::{thread, time};
use std::borrow::Borrow;
use logger::prelude::*;


pub struct Node <C: ChainClient+ Send+Sync+'static,TTransport:Transport+Sync+Send+'static>
    where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
    executor: TaskExecutor,
    //switch:Switch<S>,
    node_inner:Option<NodeInner<C,TTransport>>,
    dial_request_tx:UnboundedSender<(Multiaddr,AccountAddress)>,
    open_channel_negotiate_tx:UnboundedSender<OpenChannelNodeNegotiateMessage>,
    open_channel_message_tx:UnboundedSender<OpenChannelTransactionMessage>,
    off_chain_pay_message_tx:UnboundedSender<(types::language_storage::StructTag,AccountAddress,u64)>,
}

struct NodeInner<C: ChainClient+ Send+Sync+'static,TTransport:Transport+ Send+Sync+'static> 
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
    executor:TaskExecutor,
    transport: TTransport,
    node_data : Arc<Mutex<NodeData<C>>>,  
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    dial_request_rx:UnboundedReceiver<(Multiaddr,AccountAddress)>,
    open_channel_negotiate_rx:UnboundedReceiver<OpenChannelNodeNegotiateMessage>,
    open_channel_message_rx:UnboundedReceiver<OpenChannelTransactionMessage>,
    off_chain_pay_message_rx:UnboundedReceiver<(types::language_storage::StructTag,AccountAddress,u64)>,
}

struct NodeData<C: ChainClient+ Send+Sync+'static> {
    local_addr:Option<Multiaddr>,
    wallet:Wallet<C>,
    sender_map:HashMap<Multiaddr,UnboundedSender<bytes::Bytes>>,   
    addr_sender_map:HashMap<AccountAddress,Multiaddr>,
}

impl<C:ChainClient+ Send+Sync +'static,TTransport:Transport+ Send+Sync+'static> Node<C,TTransport>
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{

    pub fn new(executor: TaskExecutor,wallet:Wallet<C>,keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        transport:TTransport)->Self{
        let executor_clone = executor.clone();
        let (mut tx,  rx) = futures::channel::mpsc::unbounded();
        let (mut tx_on,  rx_on) = futures::channel::mpsc::unbounded();
        let (mut tx_oc,  rx_oc) = futures::channel::mpsc::unbounded();
        let (mut tx_op,  rx_op) = futures::channel::mpsc::unbounded();

        let node_data = NodeData {
                wallet,
                sender_map:HashMap::new(),
                addr_sender_map:HashMap::new(),
                local_addr:None,             
        };
        let node_inner=NodeInner{
                executor:executor_clone,                
                transport,
                node_data:Arc::new(Mutex::new(node_data)),
                keypair,
                dial_request_rx:rx,
                open_channel_message_rx:rx_oc,
                open_channel_negotiate_rx:rx_on,
                off_chain_pay_message_rx:rx_op,
            };
        Self{
            executor,
            //switch:switch,
            node_inner:Some(node_inner),
            dial_request_tx:tx,
            open_channel_message_tx:tx_oc,
            open_channel_negotiate_tx:tx_on,
            off_chain_pay_message_tx:tx_op,
        }
    }

    pub fn start_server(&mut self,
        listen_addr: Multiaddr,
    )  {
        let node_inner = self
            .node_inner
            .take()
            .expect("node inner already taken");
        self.executor.spawn(node_inner.start_listen(listen_addr).boxed().unit_error().compat());
    }

    pub fn connect(&self,addr: Multiaddr,remote_addr:AccountAddress){
        self.dial_request_tx.unbounded_send((addr,remote_addr));
        let ten_millis = time::Duration::from_micros(3000);  
        thread::sleep(ten_millis);
    }

    pub fn open_channel_negotiate(&self,negotiate_message:OpenChannelNodeNegotiateMessage){
        self.open_channel_negotiate_tx.unbounded_send(negotiate_message);
    }

    pub fn open_channel(&self,open_channel_message:OpenChannelTransactionMessage){
        self.open_channel_message_tx.unbounded_send(open_channel_message);
    }

    pub fn off_chain_pay(&self,coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64)->Result<()>{
        self.off_chain_pay_message_tx.unbounded_send((coin_resource_tag,receiver_address,amount));
        Ok(())
    }

}

impl<C: ChainClient+ Send+Sync+'static,TTransport:Transport+ Send+Sync+'static> NodeInner<C,TTransport>
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{

    async fn start_listen(mut self, listen_addr: Multiaddr){
        let (mut listener, listen_addr) = self.transport
            .listen_on(listen_addr.clone())
            .expect("Transport listen on fails");

        let mut listener = listener.fuse();
        self.node_data.clone().lock().unwrap().local_addr = Some(listen_addr);
        loop {
            futures::select! {
                (addr,account_addr) = self.dial_request_rx.select_next_some() => {
                    self.connect(addr,account_addr);
                },
                incoming_connection = listener.select_next_some() => {
                    match incoming_connection {
                        Ok((f_stream, addr)) => {
                            let (mut tx,  rx) = futures::channel::mpsc::unbounded();
                            let node_data = self.node_data.clone();
                            self.executor.spawn(Self::handle_stream(f_stream.await.unwrap(),addr.clone(),tx,rx,node_data).boxed().unit_error().compat());                                                        
                        }
                        Err(e) => {
                            warn!("Incoming connection error {}", e);
                        }
                    }
                },
                msg=self.open_channel_negotiate_rx.select_next_some() => {
                    self.open_channel_negotiate(msg);
                },
                msg=self.open_channel_message_rx.select_next_some() => {
                    self.open_channel(msg);
                },
                (resource_type,account_addr,amount)=self.off_chain_pay_message_rx.select_next_some() => {
                    self.off_chain_pay(resource_type,account_addr,amount);
                },
                complete => break,
            }
        }

        while let Some(Ok((f_stream, addr))) = listener.next().await {
        }
    }

    async fn handle_stream<S>(output:S,addr:Multiaddr,tx:UnboundedSender<bytes::Bytes>,mut rx:UnboundedReceiver<bytes::Bytes>,node_data:Arc<Mutex<NodeData<C>>>)
    where S:AsyncRead+AsyncWrite+Unpin+Send,{
        let mut f_stream = Framed::new(output.compat(), LengthDelimitedCodec::new()).sink_compat().fuse();
        loop {
            futures::select! {
                data = f_stream.select_next_some() => {
                    debug!("received msg");
                    let data = bytes::Bytes::from(data.unwrap());
                    let msg_type=parse_message_type(&data);
                    match msg_type {
                        MessageType::OpenChannelNodeNegotiateMessage =>  Self::handle_open_channel_negotiate(data[2..].to_vec(),node_data.clone()),
                        MessageType::OpenChannelTransactionMessage => Self::handle_open_channel(data[2..].to_vec(),node_data.clone()),
                        MessageType::OffChainPayMessage => Self::handle_off_chain_pay(data[2..].to_vec(),node_data.clone()),
                        MessageType::AddressMessage => Self::handle_addr(data[2..].to_vec(),tx.clone(),node_data.clone()),
                        _=>warn!("message type not found {:?}",msg_type),
                    };                                        
                },
                data = rx.select_next_some() => {//send data
                    debug!("send real data");
                    f_stream.send(data).await;
                },
                complete => break,
            }
        };

    }

    fn send_message(account_addr:&AccountAddress,msg:bytes::Bytes,node_data:Arc<Mutex<NodeData<C>>>){
        let nd=node_data.lock().unwrap();
        match nd.addr_sender_map.get(account_addr) {
            Some(addr) => {
                match nd.sender_map.get(addr){
                    Some(sender) => {
                        sender.unbounded_send(msg);
                    },
                    _ => warn!("can't find sender by multi addr {:?}",addr),
                }
            },
            _ => warn!("can't find multi addr by account addr {:?}",account_addr),
        }        
    }

    fn handle_addr(data:Vec<u8>,tx:UnboundedSender<bytes::Bytes>,node_data:Arc<Mutex<NodeData<C>>>){
        let account_addr = AddressMessage::from_proto_bytes(&data).unwrap();        
        node_data.lock().unwrap().addr_sender_map.insert(account_addr.addr.clone(),account_addr.ip_addr.clone());
        node_data.lock().unwrap().sender_map.insert(account_addr.ip_addr,tx);
    }

    fn handle_open_channel_negotiate(data:Vec<u8>,node_data:Arc<Mutex<NodeData<C>>>){
        debug!("handle_open_channel_negotiate");
        let negotiate_message = OpenChannelNodeNegotiateMessage::from_proto_bytes(&data).unwrap();
        let raw_message = &(negotiate_message.raw_negotiate_message);
        if (raw_message.sender_addr == node_data.lock().unwrap().wallet.get_address()){
            match negotiate_message.receiver_sign {
                Some(sign)=>{
                    debug!("receive 2 sign");
                    // TODO send open channel msg
                },
                None=>debug!("none"),
            }
        }
        if (raw_message.receiver_addr == node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage,send back
            debug!("receive sender neg msg");    
        }
    }

    fn handle_open_channel(data:Vec<u8>,node_data:Arc<Mutex<NodeData<C>>>){
        debug!("handle_open_channel");
        let open_channel_message = OpenChannelTransactionMessage::from_proto_bytes(&data).unwrap();
        if (&open_channel_message.transaction.receiver() == &node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage,send back    
        }
        if (&open_channel_message.transaction.txn().sender() == &node_data.lock().unwrap().wallet.get_address()) {
            if (open_channel_message.transaction.output_signatures().len()==2){
                // wallet open channel
            }else {
                debug!("sign should eq 2");
            }
        }
    }

    fn handle_off_chain_pay(data:Vec<u8>,mut node_data:Arc<Mutex<NodeData<C>>>){ 
        debug!("off chain pay");
        let off_chain_pay_message = OffChainPayMessage::from_proto_bytes(&data).unwrap();
        let raw_transaction = off_chain_pay_message.transaction.borrow();
        let local_addr =node_data.lock().unwrap().wallet.get_address();
        if (&raw_transaction.receiver() == &local_addr){
            // sign message ,verify messsage, execute tx local            
            node_data.lock().unwrap().wallet.apply_txn(raw_transaction).unwrap();
            let receiver_addr = &&raw_transaction.txn().sender(); //send to tx sender
            let off_chain_pay_message = OffChainPayMessage::new(raw_transaction.clone());
            let msg = add_message_type(off_chain_pay_message.into_proto_bytes().unwrap(), MessageType::OffChainPayMessage);
            Self::send_message(receiver_addr,msg,node_data.clone());
        }
        if (&raw_transaction.txn().sender() == &local_addr) {
            debug!("receive feed back pay");
            node_data.lock().unwrap().wallet.apply_txn(raw_transaction).unwrap();
            info!("tx succ");
        }
    }

    fn connect(&self,addr: Multiaddr,remote_addr:AccountAddress){
        let (tx, rx)= futures::channel::mpsc::unbounded();
        let outbound = self.transport.dial(addr.clone()).unwrap();        

        let local_addr=self.node_data.clone().lock().unwrap().wallet.get_address().clone();
        let node_data = self.node_data.clone();
        let tx_clone = tx.clone();
        let executor = self.executor.clone();        

        let dialer = async move {
            let mut socket = outbound.await.unwrap();

            let addr_msg_bytes=AddressMessage::new(local_addr,node_data.lock().unwrap().local_addr.as_ref().unwrap().clone()).into_proto_bytes().unwrap();
            let addr_msg_bytes = add_message_type(addr_msg_bytes,MessageType::AddressMessage);                
            node_data.lock().unwrap().sender_map.insert(addr.clone(),tx_clone);
            node_data.lock().unwrap().addr_sender_map.insert(remote_addr,addr.clone());

            tx.clone().unbounded_send(addr_msg_bytes);
        
            executor.spawn(Self::handle_stream(socket,addr.clone(),tx.clone(),rx,node_data).boxed().unit_error().compat());                                                        
        };

        self.executor.spawn(dialer.boxed().unit_error().compat());        
    }

    fn open_channel_negotiate(&self,negotiate_message:OpenChannelNodeNegotiateMessage)->Result<()>{  
        let addr = negotiate_message.raw_negotiate_message.receiver_addr;
        let msg = negotiate_message.into_proto_bytes()?;
        let msg = add_message_type(msg, MessageType::OpenChannelNodeNegotiateMessage);
        Self::send_message(&addr,msg,self.node_data.clone());
        Ok(())
    }

    fn open_channel(&self,open_channel_message:OpenChannelTransactionMessage)->Result<()>{
        let addr = &open_channel_message.transaction.receiver();
        let msg = add_message_type(open_channel_message.into_proto_bytes()?, MessageType::OpenChannelTransactionMessage);
        Self::send_message( addr,msg,self.node_data.clone());
        Ok(())
    }

    fn off_chain_pay(&self,coin_resource_tag: types::language_storage::StructTag, receiver_address: AccountAddress, amount: u64)->Result<()>{
        let off_chain_pay_tx = self.node_data.clone().lock().unwrap().wallet.transfer(coin_resource_tag,receiver_address,amount)?;
        let off_chain_pay_msg = OffChainPayMessage {
            transaction:off_chain_pay_tx,
        };
        let msg = add_message_type(off_chain_pay_msg.into_proto_bytes()?, MessageType::OffChainPayMessage);
        Self::send_message(&receiver_address ,msg,self.node_data.clone());
        Ok(())
    }

}

fn parse_message_type(data:&bytes::Bytes)->MessageType{
    let data_slice = &data[0..2];
    let type_u16=u16::from_be_bytes([data_slice[0],data_slice[1]]);    
    MessageType::from_type(type_u16).unwrap()
}

fn add_message_type(data:Vec<u8>,messaget_type:MessageType)->bytes::Bytes{
    let len =u16::to_be_bytes(messaget_type.get_type());
    let mut result_vec = Vec::new();
    result_vec.extend_from_slice(&len);
    result_vec.extend_from_slice(&data);
    bytes::Bytes::from(result_vec)
}
