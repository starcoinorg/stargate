#![feature(async_await)]

#[cfg(test)]
mod message;
mod peer;
mod error;
mod mem_stream;
pub mod p2p;


mod tests {
    use crate::p2p::{new_network, NetConfig};
    use crate::mem_stream::{MemTcpStream, MemNetwork};
    use std::net::SocketAddr;
    use futures::{Stream, Future,future};

    #[test]
    fn test_new_network() {
        let cfg = NetConfig {
            bootstrap: vec![],
            max_sockets: 0,
            memory_stream: false,
        };
        let network = new_network::<
            MemTcpStream,
            future::Ready<MemTcpStream>,
            Stream<Item=MemTcpStream>,
            MemNetwork,
        >(cfg);
        
    }
}