use std::net::SocketAddr;
use crate::error::Error;

extern crate tokio;


pub struct NetConfig {
    pub bootstrap: Vec<SocketAddr>,
    pub max_sockets: u64,
}

pub struct ConnectedExecutor {}


pub trait Network {
    fn start(net_cfg: NetConfig) -> Result<(), Error>;
    fn join(forward: bool, peer_id: String) -> Result<(), Error>;
    fn connect(peer_id: String);
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
}