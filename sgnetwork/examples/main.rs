pub use sgnetwork::{build_network_service, NetworkComponent, NetworkService, get_unix_ts};
use crypto::test_utils::KeyPair;
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crypto::traits::Uniform;
use rand::prelude::*;
use tokio::runtime::{Runtime, TaskExecutor};
use tokio::timer::Interval;
use futures::stream::Stream;
use sgnetwork::{Message, NetworkMessage};
use std::time::{Instant, Duration};
use types::account_address::AccountAddress;
use futures::future::Future;
use std::convert::TryFrom;
use crypto::hash::CryptoHash;
fn main() {
    env_logger::init();
    ::logger::init_for_e2e_testing();
    let mut peer_id = "".to_string();
    let (seeds, port) = match std::env::args().nth(1) {
        Some(seed) => {
            peer_id = seed.clone();
            (vec![format!("/ip4/127.0.0.1/tcp/7000/p2p/{}", seed)], 7001)
        }
        None => { (vec![], 7000) }
    };
    let config = sg_config::config::NetworkConfig {
        listen: format!("/ip4/127.0.0.1/tcp/{}", port),
        seeds,
    };
    let key_pair = {
        let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts() as u64);
        KeyPair::<Ed25519PrivateKey, Ed25519PublicKey>::generate_for_testing(&mut rng)
    };
    let (net_srv, tx, rx, close_tx) = build_network_service(&config, key_pair);

    println!("the network identify is {:?}", hex::encode(net_srv.identify()));

    let rt = Runtime::new().unwrap();
    let executor = rt.executor();

    if peer_id.len() == 0 {
        let receive_fut = rx.for_each(|msg| {
            println!("{:?}", msg.hash());
            Ok(())
        });
        executor.spawn(receive_fut);
    } else {
        let sender_fut = Interval::new(Instant::now(), Duration::from_millis(10))
            .take(1000)
            .map_err(|_e| ())
            .for_each(move |_| {
                let random_bytes: Vec<u8> = (0..10240).map(|_| { rand::random::<u8>() }).collect();
                let message = Message::new_message(random_bytes);
                let peer_id_hex = format!("0x{}", &peer_id);
                let peer_id = AccountAddress::from_hex_literal(&peer_id_hex).unwrap();
                let _ = tx.unbounded_send(NetworkMessage {
                    peer_id,
                    msg: message,
                });
                Ok(())
            });
        executor.spawn(sender_fut);
    }
    rt.shutdown_on_idle().wait().unwrap();
}