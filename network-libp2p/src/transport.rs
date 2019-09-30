use futures::prelude::*;
use libp2p::{
    bandwidth,
    core::{self, muxing::StreamMuxerBox, transport::boxed::Boxed},
    dns, identity, mplex, secio, tcp, websocket, yamux, InboundUpgradeExt, OutboundUpgradeExt,
    PeerId, Transport,
};
use std::{io, sync::Arc, time::Duration, usize};

pub use self::bandwidth::BandwidthSinks;

/// Builds the transport that serves as a common ground for all connections.
///
/// Returns a `BandwidthSinks` object that allows querying the average bandwidth produced by all
/// the connections spawned with this transport.
pub fn build_transport(
    keypair: identity::Keypair,
) -> (
    Boxed<(PeerId, StreamMuxerBox), io::Error>,
    Arc<bandwidth::BandwidthSinks>,
) {
    let mut mplex_config = mplex::MplexConfig::new();
    mplex_config.max_buffer_len_behaviour(mplex::MaxBufferBehaviour::Block);
    mplex_config.max_buffer_len(usize::MAX);

    let transport = tcp::TcpConfig::new();
    let transport = websocket::WsConfig::new(transport.clone()).or_transport(transport);
    let transport = dns::DnsConfig::new(transport);
    let (transport, sinks) = bandwidth::BandwidthLogging::new(transport, Duration::from_secs(5));

    // TODO: rework the transport creation (https://github.com/libp2p/rust-libp2p/issues/783)
    let transport = transport
        .with_upgrade(secio::SecioConfig::new(keypair))
        .and_then(move |out, endpoint| {
            //TODO: Use from mutilihash to generate peer id instread of from key.
            let peer_id = out.remote_key.into_peer_id();

            let peer_id2 = peer_id.clone();
            let upgrade = core::upgrade::SelectUpgrade::new(yamux::Config::default(), mplex_config)
                .map_inbound(move |muxer| (peer_id, muxer))
                .map_outbound(move |muxer| (peer_id2, muxer));

            core::upgrade::apply(out.stream, upgrade, endpoint)
                .map(|(id, muxer)| (id, core::muxing::StreamMuxerBox::new(muxer)))
        })
        .with_timeout(Duration::from_secs(20))
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        .boxed();

    (transport, sinks)
}
