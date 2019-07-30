use std::{
    net::SocketAddr,
    marker::Unpin,
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
    pub memory_stream: bool,
}

pub struct TSocket {
    incoming: UnboundedReceiver<Vec<u8>>,
    outgoing: UnboundedSender<Vec<u8>>,
    addr: SocketAddr,
}


pub trait TTcpSteam: AsyncWrite + AsyncRead + Unpin {}

pub trait Network<T, S, F>
    where T: TTcpSteam, F: Future<Output=T>, S: Stream<Item=T>
{
    fn start(net_cfg: NetConfig) -> Result<(), Error>;
    fn stop() -> Result<(), Error>;
    fn join(forward: bool, peer_id: String) -> Result<(), Error>;
    fn connect(addr: SocketAddr) -> Result<F, Error>;
    fn listen() -> Result<S, Error>;
}

pub fn new_network<'a, T, F, S, N>(net_cfg: NetConfig) -> N
    where T: TTcpSteam, F: Future<Output=T>, S: Stream<Item=T>, N: Network<T, S, F>
{
    unimplemented!()
}