use futures::{future, stream::Stream, Async};
use network_libp2p::{start_service, NetworkConfiguration, PeerId, Service, ServiceEvent};
use parking_lot::Mutex;
use std::io;
use std::sync::Arc;
use tokio::{runtime::TaskExecutor, sync::mpsc};

#[derive(Clone, Debug)]
pub struct Message {
    pub peer_id: PeerId,
    pub msg: Vec<u8>,
}

pub trait NetSpecific {
    fn on_receive_message(peer_id: PeerId, msg: Vec<u8>);
    fn on_connected(peer_id: PeerId);
}

pub fn build_network_service(
    cfg: NetworkConfiguration,
) -> Result<Arc<Mutex<Service<Vec<u8>>>>, io::Error> {
    let protocol = network_libp2p::RegisteredProtocol::<Vec<u8>>::new(&b"tst"[..], &[1]);
    match start_service(cfg, protocol) {
        Ok((srv, _)) => Ok(Arc::new(Mutex::new(srv))),
        Err(err) => Err(err.into()),
    }
}

pub struct Network {
    executor: TaskExecutor,
}

impl Network {
    pub fn new(executor: TaskExecutor) -> Self {
        Self { executor }
    }
    pub fn start_listen_network(
        &mut self,
        net_srv: Arc<Mutex<Service<Vec<u8>>>>,
    ) -> (mpsc::Sender<Message>, mpsc::Receiver<Message>) {
        println!("Sart listen");
        let (mut _tx, net_rx) = mpsc::channel(10);
        let (net_tx, mut _rx) = mpsc::channel::<Message>(10);
        let net_srv_sender = net_srv.clone();

        let network_fut = future::poll_fn(move || {
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
            Ok(Async::NotReady)
        });

        self.executor.spawn(network_fut);
        (net_tx, net_rx)
    }
}
