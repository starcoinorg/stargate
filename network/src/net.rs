use crate::{convert_account_address_to_peer_id, convert_peer_id_to_account_address, helper::convert_boot_nodes};
use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
};
use futures::{future, stream::Stream, sync::mpsc, Async, Future, sync::oneshot, stream, try_ready};
use network_libp2p::{
    identity, start_service, NetworkConfiguration, NodeKeyConfig, PeerId, Secret,
    Service as Libp2pService, ServiceEvent,
};
use parking_lot::Mutex;
use sg_config::config::NetworkConfig;
use std::{io, sync::Arc};
use types::account_address::AccountAddress;
use tokio::runtime::TaskExecutor;
use logger::prelude::*;
use crate::message::{Message, PayloadMsg};
use crate::message::Message::{ACK, Payload};
use futures::sync::oneshot::{Canceled, Sender};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct NetworkMessage {
    pub peer_id: AccountAddress,
    pub msg: Message,
}

pub struct NetworkService {
    pub libp2p_service: Arc<Mutex<Libp2pService<Message>>>,
    pub close_tx: Option<oneshot::Sender<()>>,
    acks: Arc<Mutex<HashMap<u64, Sender<()>>>>,
}

pub fn build_network_service(
    cfg: &NetworkConfig,
    key_pair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    executor: TaskExecutor,
) -> (
    NetworkService,
    mpsc::UnboundedSender<NetworkMessage>,
    mpsc::UnboundedReceiver<NetworkMessage>,
) {
    let config = NetworkConfiguration {
        listen_addresses: vec![cfg.listen.parse().unwrap()],
        boot_nodes: convert_boot_nodes(cfg.seeds.clone()),
        node_key: {
            let secret =
                identity::ed25519::SecretKey::from_bytes(&mut key_pair.private_key.to_bytes())
                    .unwrap();
            NodeKeyConfig::Ed25519(Secret::Input(secret))
        },
        ..NetworkConfiguration::default()
    };
    NetworkService::new(config, executor)
}

fn build_libp2p_service(
    cfg: NetworkConfiguration,
) -> Result<Arc<Mutex<Libp2pService<Message>>>, io::Error> {
    let protocol = network_libp2p::RegisteredProtocol::<Message>::new(&b"tst"[..], &[1]);
    match start_service(cfg, protocol) {
        Ok((srv, _)) => Ok(Arc::new(Mutex::new(srv))),
        Err(err) => Err(err.into()),
    }
}

fn run_network(
    net_srv: Arc<Mutex<Libp2pService<Message>>>,
    acks: Arc<Mutex<HashMap<u64, Sender<()>>>>,
) -> (
    mpsc::UnboundedSender<NetworkMessage>,
    mpsc::UnboundedReceiver<NetworkMessage>,
    impl Future<Item=(), Error=std::io::Error>,
) {
    let (mut _tx, net_rx) = mpsc::unbounded();
    let (net_tx, mut _rx) = mpsc::unbounded::<NetworkMessage>();
    let net_srv_1 = net_srv.clone();
    let connected_fut = future::poll_fn(move || {
        match try_ready!(net_srv_1.lock().poll()) {
            Some(ServiceEvent::OpenedCustomProtocol { peer_id, .. }) => {
                debug!("Connected peer: {}", convert_peer_id_to_account_address(&peer_id).unwrap());
            }
            _ => { debug!("Connected checked"); }
        }
        Ok(Async::Ready(()))
    });


    let net_srv_2 = net_srv.clone();
    let net_srv_3 = net_srv.clone();
    let network_fut = stream::poll_fn(move || net_srv_2.lock().poll()).for_each(
        move |event| {
            match event {
                ServiceEvent::CustomMessage { peer_id, message } => {
                    match message {
                        Message::Payload(payload) => {
                            //receive message
                            debug!("Receive custom message");
                            let _ = _tx.unbounded_send(NetworkMessage {
                                peer_id: convert_peer_id_to_account_address(&peer_id).unwrap(),
                                msg: Message::Payload(payload.clone()),
                            });
                            net_srv_3.lock().send_custom_message(&peer_id, Message::ACK(payload.id));
                        }

                        Message::ACK(message_id) => {
                            debug!("Receive message ack");
                            if let Some(tx) = acks.lock().remove(&message_id) {
                                let _ = tx.send(());
                            } else {
                                error!("Receive a invalid ack, message id:{}, peer id:{}", message_id, peer_id);
                            }
                        }
                    }
                }
                ServiceEvent::OpenedCustomProtocol { peer_id, version: _, debug_info: _ } => {
                    info!(
                        "Connected peer {:?}",
                        convert_peer_id_to_account_address(&peer_id).unwrap()
                    );
                }
                ServiceEvent::ClosedCustomProtocol { peer_id: _, debug_info: _ } => { debug!("Network close custom protol") }
                ServiceEvent::Clogged { peer_id: _, messages: _ } => { debug!("Network clogged") }
            };
            Ok(())
        }
    ).then(|_| {
        debug!("Finish network poll");
        Ok(())
    });

    let protocol_fut = stream::poll_fn(move || _rx.poll()).for_each(
        move |message| {
            let peer_id = convert_account_address_to_peer_id(message.peer_id).unwrap();
            net_srv
                .lock()
                .send_custom_message(&peer_id, message.msg);
            if net_srv.lock().is_open(&peer_id) == false {
                error!("Message send to peer :{} is not connected", convert_peer_id_to_account_address(&peer_id).unwrap());
            }
            debug!("Already send message");
            Ok(())
        }
    ).then(|res| {
        match res {
            Ok(()) => {
                debug!("Finish prototol poll");
            }
            Err(_) => error!("protocol disconnected"),
        };
        Ok(())
    });
    let futures: Vec<Box<Future<Item=(), Error=io::Error> + Send>> = vec![
        Box::new(network_fut) as Box<_>,
        Box::new(protocol_fut) as Box<_>,
    ];

    let futs = futures::select_all(futures)
        .and_then(move |_| {
            debug!("Networking ended");
            Ok(())
        })
        .map_err(|(r, _, _)| r);

    let futs = connected_fut.and_then(move |_| futs);

    (net_tx, net_rx, futs)
}

fn spawn_network(
    libp2p_service: Arc<Mutex<Libp2pService<Message>>>,
    acks: Arc<Mutex<HashMap<u64, Sender<()>>>>,
    executor: TaskExecutor,
    close_rx: oneshot::Receiver<()>,
) -> (
    mpsc::UnboundedSender<NetworkMessage>,
    mpsc::UnboundedReceiver<NetworkMessage>,
) {
    let (network_sender, network_receiver, network_future) = run_network(libp2p_service, acks);
    let fut = network_future
        .select(close_rx.then(|_| {
            debug!("Shutdown network");
            Ok(())
        }))
        .map(|(val, _)| val)
        .map_err(|(err, _)| ());


    executor.spawn(fut);
    (network_sender, network_receiver)
}

impl NetworkService {
    fn new(
        cfg: NetworkConfiguration,
        executor: TaskExecutor,
    ) -> (
        NetworkService,
        mpsc::UnboundedSender<NetworkMessage>,
        mpsc::UnboundedReceiver<NetworkMessage>,
    ) {
        let (close_tx, close_rx) = oneshot::channel::<()>();
        let libp2p_service = build_libp2p_service(cfg).unwrap();
        let net_srv = libp2p_service.clone();
        let acks = Arc::new(Mutex::new(HashMap::new()));
        let (network_sender, network_receiver) =
            spawn_network(libp2p_service.clone(), acks.clone(), executor, close_rx);
        info!("Network started, connected peers:");
        for p in libp2p_service.lock().connected_peers() {
            info!("peer_id:{}", p);
        }

        (
            Self {
                libp2p_service,
                close_tx: Some(close_tx),
                acks,
            },
            network_sender,
            network_receiver,
        )
    }

    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.libp2p_service.lock().is_open(peer_id)
    }

    pub fn identify(&self) -> AccountAddress {
        convert_peer_id_to_account_address(self.libp2p_service.lock().peer_id()).unwrap()
    }

    pub fn send_message(&mut self, account_address: AccountAddress, message: Vec<u8>) -> impl Future<Item=(), Error=Canceled> {
        let (tx, rx) = oneshot::channel::<()>();
        let (protocol_msg, message_id) = Message::new_payload(message);
        let peer_id = convert_account_address_to_peer_id(account_address).expect("Invalid account address");

        self.libp2p_service.lock().send_custom_message(&peer_id, protocol_msg);
        debug!("Send message with ack");
        self.acks.lock().insert(message_id, tx);
        rx
    }

    pub fn send_message_block(&mut self, account_address: AccountAddress, message: Vec<u8>) -> Result<(), Canceled> {
        self.send_message(account_address, message).wait()
    }
}

impl Drop for NetworkService {
    fn drop(&mut self) {
        if let Some(sender) = self.close_tx.take() {
            let _ = sender.send(());
        }
    }
}

pub type NetworkComponent = (
    NetworkService,
    mpsc::UnboundedSender<NetworkMessage>,
    mpsc::UnboundedReceiver<NetworkMessage>,
);
