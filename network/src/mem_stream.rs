use std::{pin::Pin, result, net::SocketAddr};
use futures::{
    io::{AsyncRead, AsyncWrite, Result},
    stream::Stream,
    Future,
    Poll,
    task::Context,
};
use crate::{
    p2p::{TTcpSteam, Network, NetConfig},
    error::Error,
};

pub struct MemTcpStream {}

pub struct MemNetwork {}

pub struct MemListener {}

impl Stream for MemListener {
    type Item = MemTcpStream;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>>{
        unimplemented!()
    }
}

impl AsyncWrite for MemTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        unimplemented!()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        unimplemented!()
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        unimplemented!()
    }
}

impl AsyncRead for MemTcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8])
                 -> Poll<Result<usize>> {
        unimplemented!()
    }
}

impl TTcpSteam for MemTcpStream {}


impl<T, S, F> Network<T, S, F> for MemNetwork
    where T: TTcpSteam, F: Future<Output=T>, S: Stream<Item=T>
{
    fn start(net_cfg: NetConfig) -> result::Result<(), Error> {
        unimplemented!()
    }

    fn stop() -> result::Result<(), Error> {
        unimplemented!()
    }

    fn join(forward: bool, peer_id: String) -> result::Result<(), Error> {
        unimplemented!()
    }

    fn connect(addr: SocketAddr) -> result::Result<F, Error> {
        unimplemented!()
    }

    fn listen() -> result::Result<S, Error> {
        unimplemented!()
    }
}
