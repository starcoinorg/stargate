use std::net::SocketAddr;
use crate::error::Error;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::io::{AsyncRead, AsyncWrite};
use std::marker::Unpin;

pub struct NetConfig {
    pub bootstrap: Vec<SocketAddr>,
    pub max_sockets: u64,
}

pub struct TSocket {
    incoming: UnboundedReceiver<Vec<u8>>,
    outgoing: UnboundedSender<Vec<u8>>,
    addr: SocketAddr,
}



pub trait Network

{
    fn start(net_cfg: NetConfig) -> Result<(), Error>;
    fn stop() -> Result<(), Error>;
    fn join(forward: bool, peer_id: String) -> Result<(), Error>;
    fn connect<T>(peer_id: String) -> Result<T, Error> where T: AsyncRead + AsyncWrite + Unpin;
}

pub struct P2pNetwork {}

impl Network for P2pNetwork {
    fn start(net_cfg: NetConfig) -> Result<(), Error> {
        unimplemented!()
    }

    fn stop() -> Result<(), Error> {
        unimplemented!()
    }

    fn join(forward: bool, peer_id: String) -> Result<(), Error> {
        unimplemented!()
    }

    fn connect<T>(peer_id: String) -> Result<T, Error> where T: AsyncRead + AsyncWrite + Unpin {
        unimplemented!()
    }
}