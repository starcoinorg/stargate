use netcore::transport::{memory, Transport};
use netcore::transport::tcp::TcpTransport;
use parity_multiaddr::Multiaddr;
use memsocket::MemorySocket;
use sg_config::config::NodeNetworkConfig;


pub struct Network<TTransport>
    where TTransport: Transport {
    transport: TTransport
}

impl<TTransport> Network<TTransport>
    where TTransport: Transport,
          TTransport::Listener: 'static,
          TTransport::Inbound: 'static,
          TTransport::Outbound: 'static,
{
    fn new(transport: TTransport) -> Self {
        Self { transport }
    }

    fn connect(&self, addr: Multiaddr) -> Result<TTransport::Outbound, TTransport::Error>
        where
            Self: Sized {
        return self.transport.dial(addr);
    }

    fn listen(&self, addr: Multiaddr) -> Result<(TTransport::Listener, Multiaddr), TTransport::Error>
        where
            Self: Sized {
        return self.transport.listen_on(addr);
    }
}


fn build_memory_transport() -> impl Transport {
    let transport = memory::MemoryTransport::default();
    transport
}

pub fn build_network(cfg: NodeNetworkConfig) -> Option<Network<impl Transport>> {
    match cfg.memory_stream {
        true => {
            let transport = build_memory_transport();
            Some(Network::new(transport))
        }
        _ => None
    }
}

