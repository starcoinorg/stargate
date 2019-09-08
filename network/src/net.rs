use crate::{convert_account_address_to_peer_id, convert_peer_id_to_account_address, helper::convert_boot_nodes};
use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    hash::{
        CryptoHash, CryptoHasher, TestOnlyHasher,
    },
    HashValue,
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

#[derive(Clone, Debug)]
pub struct NetworkMessage {
    pub peer_id: AccountAddress,
    pub msg: Vec<u8>,
}

impl CryptoHash for NetworkMessage {
    type Hasher = TestOnlyHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        let mut bytes_vec = self.peer_id.to_vec();
        bytes_vec.extend_from_slice(&self.msg);
        state.write(&bytes_vec);
        state.finish()
    }
}

pub struct NetworkService {
    pub libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
    pub close_tx: Option<oneshot::Sender<()>>,
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
) -> Result<Arc<Mutex<Libp2pService<Vec<u8>>>>, io::Error> {
    let protocol = network_libp2p::RegisteredProtocol::<Vec<u8>>::new(&b"tst"[..], &[1]);
    match start_service(cfg, protocol) {
        Ok((srv, _)) => Ok(Arc::new(Mutex::new(srv))),
        Err(err) => Err(err.into()),
    }
}

fn run_network(
    net_srv: Arc<Mutex<Libp2pService<Vec<u8>>>>,
) -> (
    mpsc::UnboundedSender<NetworkMessage>,
    mpsc::UnboundedReceiver<NetworkMessage>,
    impl Future<Item=(), Error=std::io::Error>,
) {
    let (mut _tx, net_rx) = mpsc::unbounded();
    let (net_tx, mut _rx) = mpsc::unbounded::<NetworkMessage>();
    let net_srv_sender = net_srv.clone();
    let net_srv_1 = net_srv.clone();
    let connected_fut = future::poll_fn(move || {
        match try_ready!(net_srv_1.lock().poll()) {
            Some(ServiceEvent::OpenedCustomProtocol { peer_id, .. }) => {
                info!("Connected peer: {}", convert_peer_id_to_account_address(&peer_id).unwrap());
                Ok(Async::Ready(()))
            }
            _ => { panic!("Not hannpen") }
        }
    });

    let network_fut = stream::poll_fn(move || net_srv.lock().poll()).for_each(
        move |event| {
            match event {
                ServiceEvent::CustomMessage { peer_id, message } => {
                    info!("Receive custom message.");
                    let _ = _tx.unbounded_send(NetworkMessage {
                        peer_id: convert_peer_id_to_account_address(&peer_id).unwrap(),
                        msg: message,
                    });
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
            info!("account:{:?}", message.peer_id);
            let peer_id = convert_account_address_to_peer_id(message.peer_id).unwrap();
            net_srv_sender
                .lock()
                .send_custom_message(&peer_id, message.msg);
            info!("peer id:{:?}", peer_id);

            if net_srv_sender.lock().is_open(&peer_id) == false {
                error!("Message send to peer :{} is not connected", convert_peer_id_to_account_address(&peer_id).unwrap());
            }
            info!("Already send message");
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
    libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
    executor: TaskExecutor,
    close_rx: oneshot::Receiver<()>,
) -> (
    mpsc::UnboundedSender<NetworkMessage>,
    mpsc::UnboundedReceiver<NetworkMessage>,
) {
    let (network_sender, network_receiver, network_future) = run_network(libp2p_service);
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
        let (network_sender, network_receiver) =
            spawn_network(libp2p_service.clone(), executor, close_rx);


        info!("Network started, connected peers:");
        for p in libp2p_service.lock().connected_peers() {
            info!("peer_id:{}", p);
        }
        (
            Self {
                libp2p_service,
                close_tx: Some(close_tx),
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
