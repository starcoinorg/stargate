use std::net::SocketAddr;
use crate::error::Error;
use std::str::Bytes;
extern crate tokio;

pub struct NetConfig {
    pub bootstrap: Vec<SocketAddr>,
    pub max_sockets: u64,
}

pub struct MemorySocket {
    incoming: UnboundedReceiver<Vec<u8>>,
    outgoing: UnboundedSender<Vec<u8>>,
    addr: SocketAddr,
}

pub trait Network {
    fn start(net_cfg: NetConfig) -> Result<(), Error>;
    fn join(forward: bool, peer_id: String) -> Result<(), Error>;
    async fn connect(peer_id: String);
    async fn memory_connect() -> Result<MemorySocket, Error>;
}


pub struct P2pNetwork {}

impl Network for P2pNetwork {
    fn start(net_cfg: NetConfig) -> Result<(), Error> {
        unimplemented!()
    }

    fn join(forward: bool, peer_id: String) -> Result<(), Error> {
        unimplemented!()
    }

    fn connect(peer_id: String) {
        unimplemented!()
    }

    fn memory_connect() -> Result<MemorySocket, Error> {
        unimplemented!()
    }
}