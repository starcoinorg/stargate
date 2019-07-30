use std::net::SocketAddr;
use crate::error::Error;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::io::{AsyncRead, AsyncWrite};
use std::marker::{Unpin, Sized};
use futures::stream::Stream;

pub struct NetConfig {
    pub bootstrap: Vec<SocketAddr>,
    pub max_sockets: u64,
}

pub struct TSocket {
    incoming: UnboundedReceiver<Vec<u8>>,
    outgoing: UnboundedSender<Vec<u8>>,
    addr: SocketAddr,
}


pub trait TTcpSteam: AsyncWrite + AsyncRead + Unpin {}

pub trait Network {
    fn start(net_cfg: NetConfig) -> Result<(), Error>;
    fn stop() -> Result<(), Error>;
    fn join(forward: bool, peer_id: String) -> Result<(), Error>;
    fn connect<T>(addr: SocketAddr) -> Result<T, Error> where T: TTcpSteam;
    fn listen<T>() -> Result<Box<dyn Stream<Item=T>>, Error> where T: TTcpSteam;
}