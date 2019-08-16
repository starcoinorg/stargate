#![feature(async_await)]


pub mod net;

#[cfg(test)]
mod tests {
    use crate::net::{Network, Message, build_network_service, NetworkMsg};
    use tokio::runtime::Runtime;
    use futures::{future, prelude::Async};
    use network_libp2p::{NetworkConfiguration, Service, build_multiaddr};
    use std::{io, fmt};
    use futures::future::IntoFuture;
    use futures::future::Future;
    use parity_multiaddr::{Multiaddr, Protocol};
    use std::sync::Arc;
    use parking_lot::Mutex;
    use libp2p::PeerId;

    fn new_local_srv_cfg(port: u16, boot_nodes: Vec<String>) -> NetworkConfiguration {
        let config = network_libp2p::NetworkConfiguration {
            listen_addresses: vec![build_multiaddr![Ip4([127, 0, 0, 1]), Tcp(port)]],
            boot_nodes,
            ..network_libp2p::NetworkConfiguration::default()
        };
        config
    }

    fn start_boot_nodes() -> (Arc<Mutex<Service<NetworkMsg>>>, Vec<String>) {
        let mut boot_nodes = Vec::new();
        let cfg = new_local_srv_cfg(0, Vec::new());
        let node = build_network_service(cfg).unwrap();
        boot_nodes.push(format!("/ip4/127.0.0.1/tcp/0/p2p/{}", node.lock().peer_id()));
        (node, boot_nodes)
    }


    fn build_nodes(num: usize, base_port: u16) -> Vec<Arc<Mutex<Service<Vec<u8>>>>> {
        let mut result: Vec<Arc<Mutex<Service<Vec<u8>>>>> = Vec::with_capacity(num);
        let mut first_addr = None::<Multiaddr>;

        for index in 0..num {
            let mut boot_nodes = Vec::new();

            if let Some(first_addr) = first_addr.as_ref() {
                boot_nodes.push(first_addr.clone()
                    .with(Protocol::P2p(result[0].lock().peer_id().clone().into()))
                    .to_string());
            }

            let config = network_libp2p::NetworkConfiguration {
                listen_addresses: vec![build_multiaddr![Ip4([127, 0, 0, 1]), Tcp(base_port + index as u16)]],
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
        let (mut node1, mut node2) = {
            let mut l = build_nodes(2, 50400).into_iter();
            let a = l.next().unwrap();
            let b = l.next().unwrap();
            (a, b)
        };

        let msg = Message {
            peer_id: node2.lock().peer_id().clone(),
            msg: vec![1, 2],
        };
        println!("{:?},{:?}", node1.lock().peer_id(), node2.lock().peer_id());
        let (net_srv1, bus_1) = Network::start_listen_network(node1);
        let (net_srv2, bus_2) = Network::start_listen_network(node2);


        let recv = bus_1.1;
        let recv_fut = future::poll_fn(move || -> io::Result<_> {
            println!("in recv");
            let msg = recv.recv().unwrap().msg;
            println!("the {:?}", msg);
            Ok(Async::Ready(()))
        });

        let futures: Vec<Box<Future<Item=(), Error=io::Error> + Send>> = vec![
            Box::new(net_srv1) as Box<_>,
            Box::new(net_srv2) as Box<_>,
            Box::new(recv_fut) as Box<_>,
        ];
        let futs = futures::select_all(futures)
            .and_then(move |_| { Ok(()) })
            .map_err(|(r, _, _)| r);

        let sender = bus_2.0;
        match sender.send(msg) {
            Ok(()) => { println!("send ok") }
            Err(e) => { panic!("send err") }
        }

        rt.block_on_all(futs).unwrap();
    }
}
