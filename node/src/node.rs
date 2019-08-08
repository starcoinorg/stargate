use switch::{switch::Switch};
use netcore::transport::{Transport};
use parity_multiaddr::Multiaddr;
use tokio::{codec::{Framed,LengthDelimitedCodec}, runtime::TaskExecutor};
use futures::{
    compat::Sink01CompatExt,
    future::{FutureExt},
    stream::Stream,
    io::{AsyncRead, AsyncWrite},
    prelude::*,
};

pub struct Node <S:AsyncRead + AsyncWrite,T:Transport>{
    switch:Switch<S>,
    transport:T,
}

impl<S:AsyncRead + AsyncWrite,T:Transport> Node<S,T>{

}

pub fn start_server<T, L, I, S, E>(
        executor: &TaskExecutor,
        transport: T,
        listen_addr: Multiaddr,
) -> Multiaddr
where
    T: Transport<Output = S,Error = E, Listener = L, Inbound = I>,
    L: Stream<Item = Result<(I, Multiaddr), E>> + Unpin + Send + 'static,
    I: Future<Output = Result<S, E>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: ::std::error::Error + Send + Sync + 'static,
{
    let (listener, server_addr) = transport.listen_on(listen_addr).unwrap();
    executor.spawn(
        start_listen(listener)
        .boxed()
        .unit_error()
        .compat(),
    );
    server_addr
}

async fn start_listen<L, I, S, E>(mut server_listener: L)
    where
        L: Stream<Item = Result<(I, Multiaddr), E>> +Unpin,
        I: Future<Output = Result<S, E>>,
        S: AsyncRead + AsyncWrite +Unpin,
        E: ::std::error::Error, {
    while let Some(Ok((f_stream, _client_addr))) = server_listener.next().await {
        let stream = f_stream.await.unwrap();
        let mut stream = Framed::new(stream.compat(), LengthDelimitedCodec::new()).sink_compat();

        while let Some(_) = stream.next().await {}
        stream.close().await.unwrap();
    }

}
