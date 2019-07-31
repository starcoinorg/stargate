use network::p2p::{new_network,NetConfig};
use network::mem_stream::{MemTcpStream, MemNetwork,MemListener};
use std::net::SocketAddr;
use futures::{Stream, Future,future};


fn main(){
    let cfg = NetConfig {
        bootstrap: vec![],
        max_sockets: 0,
        memory_stream: false,
    };
    let network = new_network::<
        MemTcpStream,
        future::Ready<MemTcpStream>,
        MemListener,
        MemNetwork,
    >(cfg);
    
    
}