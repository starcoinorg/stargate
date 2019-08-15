use network_libp2p::{PeerId, NetworkConfiguration, RegisteredProtocol, ProtocolId, start_service, Service, ServiceEvent, CustomMessage};
use parity_multiaddr::{Multiaddr, Protocol};
use crossbeam_channel::{self as channel, Receiver, Sender, TryRecvError};
use futures::{Async, future, Stream, stream, sync::oneshot, try_ready, Future};
use std::io;
use std::sync::Arc;
use parking_lot::Mutex;

pub type NetworkMsg = Vec<u8>;


pub struct Message {
    pub peer_id: PeerId,
    pub msg: NetworkMsg,
}


pub trait NetSpecific {
    fn on_receive_message(peer_id: PeerId, msg: NetworkMsg);
    fn on_connected(peer_id: PeerId);
}

pub fn build_network_service(cfg: NetworkConfiguration) -> Result<Arc<Mutex<Service<NetworkMsg>>>, io::Error> {
    let protocol = network_libp2p::RegisteredProtocol::<NetworkMsg>::new(&b"tst"[..], &[1]);
    match start_service(cfg, protocol) {
        Ok((srv, _)) => Ok(Arc::new(Mutex::new(srv))),
        Err(err) => {
            Err(err.into())
        }
    }
}

pub struct NetMsgChan {
    pub msg_receiver: Receiver<Message>,
    pub msg_sender: Sender<Message>,
    rx: Arc<Receiver<Message>>,
    tx: Arc<Sender<Message>>,
}

impl NetMsgChan {
    fn new() -> NetMsgChan {
        let (tx, net_rx) = channel::unbounded();
        let (net_tx, rx) = channel::unbounded::<Message>();
        Self {
            msg_receiver: net_rx,
            msg_sender: net_tx,
            rx: Arc::new(rx),
            tx: Arc::new(tx),
        }
    }
}

pub struct Network {
    pub net_msg_bus: NetMsgChan
}


impl Network {
    pub fn start_network(cfg: NetworkConfiguration, net_msg_chan: NetMsgChan) -> impl Future<Item=(), Error=io::Error> {
        let net_srv = build_network_service(cfg).unwrap();
        let net_srv_sender = net_srv.clone();
        let tx = net_msg_chan.tx.clone();
        let net_fut = stream::poll_fn(move || net_srv.lock().poll())
            .for_each(move |event| {
                match event {
                    ServiceEvent::CustomMessage { peer_id, message } => {
                        tx.try_send(Message { peer_id, msg: message });
                    }
                    _ => {}
                }
                Ok(())
            });

        let rx = net_msg_chan.rx.clone();
        let sender_fut = stream::poll_fn(move || {
            match rx.try_recv() {
                Ok(msg) => Ok(Async::Ready(Some(msg))),
                Err(TryRecvError::Empty) => Ok(Async::NotReady),
                Err(TryRecvError::Disconnected) => Err(()),
            }
        }).for_each(move |msg| {
            net_srv_sender.lock().send_custom_message(&msg.peer_id, msg.msg);
            Ok(())
        }).then(|res| {
            match res {
                Ok(()) => (),
                Err(_) => (), //todo:logger it
            };
            Ok(())
        });

        let futures: Vec<Box<Future<Item=(), Error=io::Error> + Send>> = vec![
            Box::new(net_fut) as Box<_>,
            Box::new(sender_fut) as Box<_>,
        ];
        let futs = futures::select_all(futures)
            .and_then(move |_| { Ok(()) })
            .map_err(|(r, _, _)| r);
        futs
    }
}