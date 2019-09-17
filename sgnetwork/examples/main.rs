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

fn main() {
    let mut peer_id = "".to_string();
    let seeds = match std::env::args().nth(1) {
        Some(seed) => {
            peer_id = seed.clone();
            vec![format!("/ip4/127.0.0.1/tcp/7000/p2p/{}", seed)]
        }
        None => { vec![] }
    };
    let config = sg_config::config::NetworkConfig {
        listen: format!("/ip4/127.0.0.1/tcp/{}", 7000),
        seeds,
    };
    let key_pair = {
        let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts() as u64);
        KeyPair::<Ed25519PrivateKey, Ed25519PublicKey>::generate_for_testing(&mut rng)
    };
    let (net_srv, tx, rx, close_tx) = build_network_service(&config, key_pair);
    println!("the network identify is {:?}", net_srv.identify());

    let rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let sender_fut = Interval::new(Instant::now(), Duration::from_millis(1))
        .take(10000)
        .map_err(|_e| ())
        .for_each(move |_| {
            let random_bytes: Vec<u8> = (0..10240).map(|_| { rand::random::<u8>() }).collect();
            let message = Message::new_message(random_bytes);
            match tx.unbounded_send(NetworkMessage {
                peer_id:AccountAddress::from_hex_literal(&peer_id).unwrap(),
                msg: message,
            }){
                Ok(()) => Ok(()),
                Err(_e) => Err(()),
            }
        });
}