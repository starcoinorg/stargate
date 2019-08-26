use futures::{future, stream::Stream, sync::mpsc, Async, Future};
use network_libp2p::{
    start_service, NetworkConfiguration, PeerId, Service as Libp2pService, ServiceEvent,
};
use parking_lot::Mutex;
use std::sync::Arc;
use std::{io, thread};
use tokio::runtime::Builder as RuntimeBuilder;

#[derive(Clone, Debug)]
pub struct Message {
    pub peer_id: PeerId,
    pub msg: Vec<u8>,
}

pub fn build_libp2p_service(
    cfg: NetworkConfiguration,
) -> Result<Arc<Mutex<Libp2pService<Vec<u8>>>>, io::Error> {
    let protocol = network_libp2p::RegisteredProtocol::<Vec<u8>>::new(&b"tst"[..], &[1]);
    match start_service(cfg, protocol) {
        Ok((srv, _)) => Ok(Arc::new(Mutex::new(srv))),
        Err(err) => Err(err.into()),
    }
}

pub fn run_network(
    net_srv: Arc<Mutex<Libp2pService<Vec<u8>>>>,
) -> (
    mpsc::Sender<Message>,
    mpsc::Receiver<Message>,
    impl Future<Item = (), Error = ()>,
) {
    println!("Start listen");
    let (mut _tx, net_rx) = mpsc::channel(10);
    let (net_tx, mut _rx) = mpsc::channel::<Message>(10);
    let net_srv_sender = net_srv.clone();

    let network_fut = future::poll_fn(move || {
        loop {
            match net_srv.lock().poll().unwrap() {
                Async::Ready(Some(ServiceEvent::CustomMessage { peer_id, message })) => {
                    println!("Receive custom message");
                    //TODO: error check
                    let _ = _tx.try_send(Message {
                        peer_id,
                        msg: message,
                    });
                }
                Async::Ready(Some(ServiceEvent::OpenedCustomProtocol { peer_id, .. })) => {
                    println!("Connected peer {:?}", peer_id);
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
                    net_srv_sender
                        .lock()
                        .send_custom_message(&message.peer_id, message.msg);
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

pub fn start_network_thread(
    libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
) -> (
    mpsc::Sender<Message>,
    mpsc::Receiver<Message>,
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

pub struct Service {
    pub network_thread: thread::JoinHandle<()>,
    pub libp2p_service: Arc<Mutex<Libp2pService<Vec<u8>>>>,
    pub network_receiver: mpsc::Receiver<Message>,
    pub network_sender: mpsc::Sender<Message>,
}

impl Service {
    pub fn new(cfg: NetworkConfiguration) -> Self {
        let libp2p_service = build_libp2p_service(cfg).unwrap();
        let (network_sender, network_receiver, network_thread) =
            start_network_thread(libp2p_service.clone());
        Self {
            network_thread,
            libp2p_service,
            network_receiver,
            network_sender,
        }
    }
}
