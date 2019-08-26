use crate::{convert_account_address_to_peer_id, convert_peer_id_to_account_address};
use crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
};
use futures::{future, stream::Stream, sync::mpsc, Async, Future};
use logger::prelude::*;
use network_libp2p::{
    identity, start_service, NetworkConfiguration, NodeKeyConfig, PeerId, Secret,
    Service as Libp2pService, ServiceEvent,
};
use parking_lot::Mutex;
use sg_config::config::NetworkConfig;
use std::{io, sync::Arc, thread};
use tokio::runtime::Builder as RuntimeBuilder;
use types::account_address::AccountAddress;

#[derive(Clone, Debug)]
pub struct Message {
    pub peer_id: AccountAddress,
    pub msg: Vec<u8>,
}

pub struct NetworkService {
    pub network_thread: thread::JoinHandle<()>,
    pub libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
}

pub fn build_network_service(
    cfg: &NetworkConfig,
    key_pair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
) -> (
    NetworkService,
    mpsc::UnboundedSender<Message>,
    mpsc::UnboundedReceiver<Message>,
) {
    let config = NetworkConfiguration {
        listen_addresses: vec![cfg.listen.parse().unwrap()],
        boot_nodes: cfg.seeds.clone(),
        node_key: {
            let secret =
                identity::ed25519::SecretKey::from_bytes(&mut key_pair.private_key.to_bytes())
                    .unwrap();
            NodeKeyConfig::Ed25519(Secret::Input(secret))
        },
        ..NetworkConfiguration::default()
    };
    NetworkService::new(config)
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
    impl Future<Item = (), Error = ()>,
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
                        peer_id: convert_peer_id_to_account_address(peer_id).unwrap(),
                        msg: message,
                    });
                }
                Async::Ready(Some(ServiceEvent::OpenedCustomProtocol { peer_id, .. })) => {
                    println!(
                        "Connected peer {:?}",
                        convert_peer_id_to_account_address(peer_id).unwrap()
                    );
                }
                Async::NotReady => {
                    break;
                }
                _ => {
                    println!("Error happend");
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
                    println!("Already send message to {:?}", &message.peer_id);
                    break;
                }
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => {
                    println!("Network channel closed");
                    return Err(());
                }
                Err(_) => {
                    println!("Error in poll network channel");
                    return Err(());
                }
            }
        }
        Ok(Async::NotReady)
    });

    (net_tx, net_rx, network_fut)
}

fn start_network_thread(
    libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
) -> (
    mpsc::UnboundedSender<Message>,
    mpsc::UnboundedReceiver<Message>,
    thread::JoinHandle<()>,
) {
    let mut rt = RuntimeBuilder::new()
        .name_prefix("starnet-")
        .build()
        .unwrap();
    let (network_sender, network_receiver, network_future) = run_network(libp2p_service);
    let thread = thread::Builder::new()
        .name("starnet".to_string())
        .spawn(move || {
            match rt.block_on(network_future) {
                Ok(()) => println!("Network finish"),
                Err(_e) => println!("Error in network"),
            };
        })
        .unwrap();

    (network_sender, network_receiver, thread)
}

impl NetworkService {
    fn new(
        cfg: NetworkConfiguration,
    ) -> (
        NetworkService,
        mpsc::UnboundedSender<Message>,
        mpsc::UnboundedReceiver<Message>,
    ) {
        let libp2p_service = build_libp2p_service(cfg).unwrap();
        let (network_sender, network_receiver, network_thread) =
            start_network_thread(libp2p_service.clone());
        (
            Self {
                network_thread,
                libp2p_service,
            },
            network_sender,
            network_receiver,
        )
    }

    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.libp2p_service.lock().is_open(peer_id)
    }
}
