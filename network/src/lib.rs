#![feature(async_await)]

pub mod net;

use failure::prelude::*;
use network_libp2p::PeerId;
use std::convert::TryFrom;
use types::account_address::AccountAddress;

pub fn convert_peer_id_to_account_address(peer_id: PeerId) -> Result<AccountAddress> {
    let peer_id_bytes = &peer_id.into_bytes()[2..];
    AccountAddress::try_from(peer_id_bytes)
}

pub fn convert_account_address_to_peer_id(
    address: AccountAddress,
) -> std::result::Result<PeerId, Vec<u8>> {
    let mut peer_id_vec = address.to_vec();
    peer_id_vec.insert(0, 32);
    peer_id_vec.insert(0, 22);
    PeerId::from_bytes(peer_id_vec)
}

#[cfg(test)]
mod tests {
    use crate::net::{Message, NetworkService};
    use crate::{convert_account_address_to_peer_id, convert_peer_id_to_account_address};
    use crypto::ed25519::compat;
    use futures::{
        future::Future,
        stream,
        stream::Stream,
        sync::mpsc::{UnboundedReceiver, UnboundedSender},
    };
    use libp2p::{
        build_multiaddr,
        multiaddr::{Multiaddr, Protocol},
        multihash,
        multihash::Multihash,
    };
    use network_libp2p::{identity, NodeKeyConfig, PeerId, PublicKey, Secret};
    use std::thread;
    use std::time::Duration;
    use tokio::prelude::Async;
    use tokio::runtime::Runtime;
    use types::account_address::AccountAddress;

    fn build_network_service(
        num: usize,
        base_port: u16,
    ) -> Vec<(
        NetworkService,
        UnboundedSender<Message>,
        UnboundedReceiver<Message>,
    )> {
        let mut result: Vec<(
            NetworkService,
            UnboundedSender<Message>,
            UnboundedReceiver<Message>,
        )> = Vec::with_capacity(num);
        let mut first_addr = None::<Multiaddr>;

        for index in 0..num {
            let mut boot_nodes = Vec::new();

            if let Some(first_addr) = first_addr.as_ref() {
                boot_nodes.push(
                    first_addr
                        .clone()
                        .with(Protocol::P2p(
                            result[0].0.libp2p_service.lock().peer_id().clone().into(),
                        ))
                        .to_string(),
                );
            }
            println!("boot nodes:{:?}", boot_nodes);
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
            //let server = NetworkService::new(config);
            //result.push(server);
        }
        result
    }

    #[test]
    fn test_send_receive() {
        let (service1, mut service2) = {
            let mut l = build_network_service(2, 50400).into_iter();
            let a = l.next().unwrap();
            let b = l.next().unwrap();
            (a, b)
        };
        let msg_peer_id = service1.0.libp2p_service.lock().peer_id().clone();
        let sender_fut = stream::repeat(1)
            .and_then(move |_| {
                match service2.1.unbounded_send(Message {
                    peer_id: msg_peer_id.clone(),
                    msg: vec![1, 2],
                }) {
                    Ok(()) => Ok(Async::Ready(Some(()))),
                    Err(e) => return Err(()),
                }
            })
            .for_each(|_| Ok(()));

        let rt = Runtime::new().unwrap();
        let executor = rt.executor();
        executor.spawn(sender_fut);
        rt.shutdown_on_idle().wait().unwrap();
    }

    #[test]
    fn test_generate_account_and_peer_id() {
        let (private_key, public_key) = compat::generate_keypair(Option::None);

        let mut cfg = network_libp2p::NetworkConfiguration::new();
        let seckey = identity::ed25519::SecretKey::from_bytes(&mut private_key.to_bytes()).unwrap();
        cfg.node_key = NodeKeyConfig::Ed25519(Secret::Input(seckey));
        let libp2p_public_key = cfg.node_key.into_keypair().unwrap().public();
        let libp2p_public_key_byte;
        if let PublicKey::Ed25519(key) = libp2p_public_key {
            libp2p_public_key_byte = key.encode();
            assert_eq!(libp2p_public_key_byte, public_key.to_bytes());
        } else {
            panic!("failed");
        }

        let address = AccountAddress::from_public_key(&public_key).to_vec();
        let peer_id = multihash::encode(multihash::Hash::SHA3256, &public_key.to_bytes())
            .unwrap()
            .into_bytes();
        println!("{:?}", peer_id);
        PeerId::from_bytes(peer_id.clone()).unwrap();
        assert_eq!(address, &peer_id[2..]);
    }

    #[test]
    fn test_connected_nodes() {
        let (service1, service2) = {
            let mut l = build_network_service(2, 50400).into_iter();
            let a = l.next().unwrap();
            let b = l.next().unwrap();
            (a, b)
        };
        thread::sleep(Duration::new(1, 0));
        for (peer_id, peer) in service1.0.libp2p_service.lock().state().connected_peers {
            println!("id: {:?}, peer: {:?}", peer_id, peer);
        }
    }

    #[test]
    fn test_convert_address_peer_id() {
        let (private_key, public_key) = compat::generate_keypair(Option::None);

        let mut cfg = network_libp2p::NetworkConfiguration::new();
        let seckey = identity::ed25519::SecretKey::from_bytes(&mut private_key.to_bytes()).unwrap();
        cfg.node_key = NodeKeyConfig::Ed25519(Secret::Input(seckey));

        let account_address = AccountAddress::from_public_key(&public_key);
        let peer_id = convert_account_address_to_peer_id(account_address).unwrap();
        let account_address_1 = convert_peer_id_to_account_address(peer_id).unwrap();
        assert_eq!(account_address, account_address_1);
    }
}
