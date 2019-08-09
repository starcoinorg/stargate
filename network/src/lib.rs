#![feature(async_await)]

#[cfg(test)]
pub mod error;
pub mod mem_stream;
pub mod p2p;
pub mod net;

mod tests {
    use crate::net::build_network;
    use futures::{Stream, Future, future};
    use sg_config::config::NodeNetworkConfig;
    use parity_multiaddr::Multiaddr;
    use memsocket::MemoryListener;


    #[test]
    fn test_new_network() {
        let cfg = NodeNetworkConfig {
            addr: "".to_string(),
            max_sockets: 0,
            in_memory: true,
            seeds: vec![],
        };
        let network = build_network(cfg).unwrap();
    }
}
