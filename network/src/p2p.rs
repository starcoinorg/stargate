use std::{
    net::SocketAddr,
    marker::{Unpin, Sized},
};

use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    io::{AsyncRead, AsyncWrite},
    stream::Stream,
    Future,
};

use crate::error::Error;

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
    fn connect<T>(addr: SocketAddr) -> Result<Box<Future<Output=T>>, Error> where T: TTcpSteam;
    fn listen<T>() -> Result<Box<dyn Stream<Item=T>>, Error> where T: TTcpSteam;
}