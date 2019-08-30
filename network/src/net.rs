use crate::{convert_account_address_to_peer_id, convert_peer_id_to_account_address, helper::convert_boot_nodes};
use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
};
use futures::{future, stream::Stream, sync::mpsc, Async, Future, sync::oneshot};
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
pub struct Message {
    pub peer_id: AccountAddress,
    pub msg: Vec<u8>,
}

pub struct NetworkService {
    pub libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
    close_tx: oneshot::Sender<()>,
}

pub fn build_network_service(
    cfg: &NetworkConfig,
    key_pair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    executor: TaskExecutor,
) -> (
    NetworkService,
    mpsc::UnboundedSender<Message>,
    mpsc::UnboundedReceiver<Message>,
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
    mpsc::UnboundedSender<Message>,
    mpsc::UnboundedReceiver<Message>,
    impl Future<Item=(), Error=()>,
) {
    let (mut _tx, net_rx) = mpsc::unbounded();
    let (net_tx, mut _rx) = mpsc::unbounded::<Message>();
    let net_srv_sender = net_srv.clone();

    let network_fut = future::poll_fn(move || {
        loop {
            match net_srv.lock().poll().unwrap() {
                Async::Ready(Some(ServiceEvent::CustomMessage { peer_id, message })) => {
                    debug!("Receive custom message");
                    let _ = _tx.unbounded_send(Message {
                        peer_id: convert_peer_id_to_account_address(&peer_id).unwrap(),
                        msg: message,
                    });
                }
                Async::Ready(Some(ServiceEvent::OpenedCustomProtocol { peer_id, .. })) => {
                    info!(
                        "Connected peer {:?}",
                        convert_peer_id_to_account_address(&peer_id).unwrap()
                    );
                }
                Async::NotReady => {
                    break;
                }
                Async::Ready(None) => {
                    //Network closed
                    return Ok(Async::Ready(()));
                }
                _ => {
                    error!("Error happened");
                    break;
                }
            }
        }

        loop {
            match _rx.poll() {
                Ok(Async::Ready(Some(message))) => {
                    let peer_id = convert_account_address_to_peer_id(message.peer_id).unwrap();
                    net_srv_sender
                        .lock()
                        .send_custom_message(&peer_id, message.msg);
                    if net_srv_sender.lock().is_open(&peer_id) == false {
                        error!("Messge send to peer :{} is not connected", convert_peer_id_to_account_address(&peer_id).unwrap());
                    }

                    debug!("Already send message");
                    break;
                }
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => {
                    info!("Network channel closed");
                    return Err(());
                }
                Err(_) => {
                    error!("Error in poll network channel");
                    return Err(());
                }
            }
        }
        Ok(Async::NotReady)
    });

    (net_tx, net_rx, network_fut)
}

fn spawn_network(
    libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
    executor: TaskExecutor,
    close_rx: oneshot::Receiver<()>,
) -> (
    mpsc::UnboundedSender<Message>,
    mpsc::UnboundedReceiver<Message>,
) {
    let (network_sender, network_receiver, network_future) = run_network(libp2p_service);
    let fut = network_future
        .select(close_rx.then(|_| Ok(())))
        .map(|(val, _)| val)
        .map_err(|(err, _)| err);


    executor.spawn(fut);

    (network_sender, network_receiver)
}

impl NetworkService {
    fn new(
        cfg: NetworkConfiguration,
        executor: TaskExecutor,
    ) -> (
        NetworkService,
        mpsc::UnboundedSender<Message>,
        mpsc::UnboundedReceiver<Message>,
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
                close_tx,
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
    pub fn shutdown(self) {
        let _ = self.close_tx.send(());
    }
}

pub type NetworkComponent = (
    NetworkService,
    mpsc::UnboundedSender<Message>,
    mpsc::UnboundedReceiver<Message>,
);
