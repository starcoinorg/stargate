#![feature(async_await)]

pub mod net;

#[cfg(test)]
mod tests {
    use crate::net::{build_network_service, Message, Network};
    use futures::{future, prelude::Async, stream};
    use futures::{future::Future, stream::Stream};
    use libp2p::PeerId;
    use network_libp2p::{build_multiaddr, NetworkConfiguration, Service};
    use parity_multiaddr::{Multiaddr, Protocol};
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::{fmt, io, thread, time};
    use tokio::runtime::Runtime;
    use tokio::sync::mpsc::error::TrySendError;

    fn new_local_srv_cfg(port: u16, boot_nodes: Vec<String>) -> NetworkConfiguration {
        let config = network_libp2p::NetworkConfiguration {
            listen_addresses: vec![build_multiaddr![Ip4([127, 0, 0, 1]), Tcp(port)]],
            boot_nodes,
            ..network_libp2p::NetworkConfiguration::default()
        };
        config
    }

    fn start_boot_nodes() -> (Arc<Mutex<Service<Vec<u8>>>>, Vec<String>) {
        let mut boot_nodes = Vec::new();
        let cfg = new_local_srv_cfg(0, Vec::new());
        let node = build_network_service(cfg).unwrap();
        boot_nodes.push(format!(
            "/ip4/127.0.0.1/tcp/0/p2p/{}",
            node.lock().peer_id()
        ));
        (node, boot_nodes)
    }

    fn build_nodes(num: usize, base_port: u16) -> Vec<Arc<Mutex<Service<Vec<u8>>>>> {
        let mut result: Vec<Arc<Mutex<Service<Vec<u8>>>>> = Vec::with_capacity(num);
        let mut first_addr = None::<Multiaddr>;

        for index in 0..num {
            let mut boot_nodes = Vec::new();

            if let Some(first_addr) = first_addr.as_ref() {
                boot_nodes.push(
                    first_addr
                        .clone()
                        .with(Protocol::P2p(result[0].lock().peer_id().clone().into()))
                        .to_string(),
                );
            }

            let config = network_libp2p::NetworkConfiguration {
                listen_addresses: vec![build_multiaddr![
                    Ip4([127, 0, 0, 1]),
                    Tcp(base_port + index as u16)
                ]],
                boot_nodes,
                ..network_libp2p::NetworkConfiguration::default()
            };

            if first_addr.is_none() {
                first_addr = Some(config.listen_addresses.iter().next().unwrap().clone());
            }
            let server = build_network_service(config).unwrap();
            result.push(server);
        }
        result
    }

    #[test]
    fn test_send_receive() {
        let rt = Runtime::new().unwrap();
        let executor = rt.executor();
        let (mut node1, node2) = {
            let mut l = build_nodes(2, 50400).into_iter();
            let a = l.next().unwrap();
            let b = l.next().unwrap();
            (a, b)
        };
        let msg_peer_id = node1.lock().peer_id().clone();
        let mut net1 = Network::new(executor.clone());
        let mut net2 = Network::new(executor.clone());
        let (sender_1, receiver_1) = net1.start_listen_network(node1);
        let (mut sender_2, receiver_2) = net2.start_listen_network(node2);

        let sender_fut = stream::repeat(1)
            .and_then(move |_| {
                match sender_2.try_send(Message {
                    peer_id: msg_peer_id.clone(),
                    msg: vec![1, 2],
                }) {
                    Ok(()) => Ok(Async::Ready(Some(()))),
                    Err(e) => match e.is_full() {
                        true => Ok(Async::NotReady),
                        false => return Err(()),
                    },
                    Err(_) => Err(()),
                }
            })
            .for_each(|_| Ok(()));

        executor.clone().spawn(sender_fut);
        rt.shutdown_on_idle().wait().unwrap();
    }
}
