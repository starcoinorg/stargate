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
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use nextgen_crypto::SigningKey;
use nextgen_crypto::test_utils::KeyPair;
use tokio::sync::mpsc::{channel,Sender,Receiver};
use star_types::message::{*};
use proto_conv::{IntoProtoBytes,FromProto,FromProtoBytes,IntoProto};
use std::collections::HashMap;
use types::account_address::AccountAddress;
use failure::prelude::*;


pub struct Node <C: ChainClient+ Send+Sync+'static,TTransport:Transport+Sync+Send+'static>
    where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
    executor: TaskExecutor,
    //switch:Switch<S>,
    node_inner:Option<NodeInner<C,TTransport>>,
}

struct NodeInner<C: ChainClient+ Send+Sync+'static,TTransport:Transport+ Send+Sync+'static> 
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
    executor:TaskExecutor,
    transport: TTransport,
    //addr_map:HashMap<Multiaddr,Sender<bytes::Bytes>>,  
    node_data : Arc<Mutex<NodeData<C>>>,  
    dial_request_rx: UnboundedReceiver<Multiaddr>,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
}

struct NodeData<C: ChainClient+ Send+Sync+'static> {
    wallet:Wallet<C>,
    sender_map:HashMap<Multiaddr,UnboundedSender<bytes::Bytes>>,   
    addr_sender_map:HashMap<AccountAddress,Multiaddr>,
}

impl<C:ChainClient+ Send+Sync +'static,TTransport:Transport+ Send+Sync+'static> Node<C,TTransport>
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{

    pub fn new(executor: TaskExecutor,wallet:Wallet<C>,keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        transport:TTransport,dial_request_rx:UnboundedReceiver<Multiaddr>)->Self{
        let executor_clone = executor.clone();
        let node_data = NodeData {
                wallet,
                sender_map:HashMap::new(),
                addr_sender_map:HashMap::new(),
        };
        let node_inner=NodeInner{
                executor:executor_clone,                
                transport,
                node_data:Arc::new(Mutex::new(node_data)),
                dial_request_rx,
                keypair,
            };
        Self{
            executor,
            //switch:switch,
            node_inner:Some(node_inner),
        }
    }

    pub fn start_server(mut self,
        listen_addr: Multiaddr,
    )  {
        let node_inner = self
            .node_inner
            .take()
            .expect("node inner already taken");
        self.executor.spawn(node_inner.start_listen(listen_addr).boxed().unit_error().compat());
    }

}

impl<C: ChainClient+ Send+Sync+'static,TTransport:Transport+ Send+Sync+'static> NodeInner<C,TTransport>
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{

    async fn start_listen(mut self, listen_addr: Multiaddr){
        let (listener, listen_addr) = self.transport
            .listen_on(listen_addr)
            .expect("Transport listen on fails");

        let mut listener = listener.fuse();        
        loop {
            futures::select! {
                dial_request = self.dial_request_rx.select_next_some() => {
                    //if let Some(fut) = self.dial_peer(dial_request) {
                        //pending_outbound_connections.push(fut);
                    //}
                },
                incoming_connection = listener.select_next_some() => {
                    match incoming_connection {
                        Ok((upgrade, addr)) => {
                            //debug!("Incoming connection from {}", addr);
                            //pending_inbound_connections.push(upgrade.map(|out| (out, addr)));
                            let (mut tx,  rx) = futures::channel::mpsc::unbounded();
                            let node_data = self.node_data.clone();
                            node_data.lock().unwrap().sender_map.insert(addr.clone(),tx);
                            self.executor.spawn(Self::handle_stream(upgrade.await.unwrap(),addr.clone(),rx,node_data).boxed().unit_error().compat());                                                        
                        }
                        Err(e) => {
                            //warn!("Incoming connection error {}", e);
                        }
                    }
                },
                complete => break,
            }
        };

    }

    async fn handle_stream<S>(output:S,addr:Multiaddr,mut rx:UnboundedReceiver<bytes::Bytes>,node_data:Arc<Mutex<NodeData<C>>>)
    where S:AsyncRead+AsyncWrite+Unpin+Send,{
        let mut f_stream = Framed::new(output.compat(), LengthDelimitedCodec::new()).sink_compat().fuse();
        loop {
            futures::select! {
                data = f_stream.select_next_some() => {
                    let data = bytes::Bytes::from(data.unwrap());
                    let msg_type=parse_message_type(&data);
                    match msg_type {
                        MessageType::OpenChannelNodeNegotiateMessage =>  Self::handle_open_channel_negotiate(data[2..].to_vec(),node_data.clone()),
                        MessageType::OpenChannelTransactionMessage => Self::handle_open_channel(data[2..].to_vec(),node_data.clone()),
                        MessageType::OffChainPayMessage => Self::handle_off_chain_pay(data[2..].to_vec(),node_data.clone()),
                        MessageType::AddressMessage => Self::handle_addr(data[2..].to_vec(),node_data.clone()),
                    };                                        
                },
                data = rx.select_next_some() => {//send data
                    f_stream.send(data).await;
                },
                complete => break,
            }
        };

    }

    fn send_message(account_addr:&AccountAddress,msg:Vec<u8>,node_data:Arc<Mutex<NodeData<C>>>){
        match node_data.lock().unwrap().addr_sender_map.get(account_addr) {
            Some(addr) => {
                match node_data.lock().unwrap().sender_map.get(addr){
                    Some(sender) => {
                        sender.unbounded_send(bytes::Bytes::from(msg));
                    },
                    _ => println!("Don't have Ashley's number."),
                }
            },
            _ => println!("Don't have Ashley's number."),
        }        
    }

    fn handle_addr(data:Vec<u8>,node_data:Arc<Mutex<NodeData<C>>>){    
    }

    fn handle_open_channel_negotiate(data:Vec<u8>,node_data:Arc<Mutex<NodeData<C>>>){
        let negotiate_message = OpenChannelNodeNegotiateMessage::from_proto_bytes(&data).unwrap();
        let raw_message = &(negotiate_message.raw_negotiate_message);
        if (raw_message.sender_addr == node_data.lock().unwrap().wallet.get_address()){
            match negotiate_message.receiver_sign {
                Some(sign)=>{
                    println!("sign");
                    // TODO send open channel msg
                },
                None=>println!("none"),
            }
        }
        if (raw_message.receiver_addr == node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage,send back    
        }
    }

    fn handle_open_channel(data:Vec<u8>,node_data:Arc<Mutex<NodeData<C>>>){
        let open_channel_message = OpenChannelTransactionMessage::from_proto_bytes(&data).unwrap();
        if (&open_channel_message.transaction.receiver() == &node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage,send back    
        }
        if (&open_channel_message.transaction.txn().sender() == &node_data.lock().unwrap().wallet.get_address()) {
            if (open_channel_message.transaction.output_signatures().len()==2){
                // wallet open channel
            }else {
                println!("sign should eq 2");
            }
        }
    }

    fn handle_off_chain_pay(data:Vec<u8>,node_data:Arc<Mutex<NodeData<C>>>){    
        let off_chain_pay_message = OffChainPayMessage::from_proto_bytes(&data).unwrap();
         if (off_chain_pay_message.transaction.receiver() == node_data.lock().unwrap().wallet.get_address()){
            // sign message ,verify messsage, execute tx local
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

            let addr_msg_bytes=AddressMessage::new(local_addr).into_proto_bytes().unwrap();                
            tx.clone().unbounded_send(bytes::Bytes::from(addr_msg_bytes));
            node_data.lock().unwrap().sender_map.insert(addr.clone(),tx_clone);
            node_data.lock().unwrap().addr_sender_map.insert(remote_addr,addr.clone());
        
            executor.spawn(Self::handle_stream(socket,addr.clone(),rx,node_data).boxed().unit_error().compat());                                                        
        };

        self.executor.spawn(dialer.boxed().unit_error().compat());        
    }

    fn open_channel_negotiate(self,negotiate_message:OpenChannelNodeNegotiateMessage)->Result<()>{        
        let addr = negotiate_message.raw_negotiate_message.receiver_addr;
        let msg = negotiate_message.into_proto_bytes()?;
        Self::send_message(&addr,msg,self.node_data.clone());
        Ok(())
    }

    fn open_channel(self,open_channel_message:OpenChannelTransactionMessage)->Result<()>{
        Self::send_message( &open_channel_message.transaction.receiver(),open_channel_message.into_proto_bytes()?,self.node_data.clone());
        Ok(())
    }

    fn off_chain_pay(self,off_chain_pay_message:OffChainPayMessage)->Result<()>{
        Self::send_message( &off_chain_pay_message.transaction.receiver(),off_chain_pay_message.into_proto_bytes()?,self.node_data.clone());
        Ok(())
    }

}

fn parse_message_type(data:&bytes::Bytes)->MessageType{
    let data_slice = &data[0..2];
    let type_u16=u16::from_be_bytes([data_slice[0],data_slice[1]]);
    MessageType::from_type(type_u16).unwrap()
}

fn add_message_type(data:bytes::Bytes,messaget_type:MessageType)->bytes::Bytes{
    let len =u16::to_be_bytes(messaget_type.get_type());
    let mut result_vec = Vec::new();
    result_vec.extend_from_slice(&len);
    result_vec.extend_from_slice(&data[..]);
    bytes::Bytes::from(result_vec)
}