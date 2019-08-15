#![feature(async_await)]


pub mod net;

#[cfg(test)]
mod tests {
    use crate::net::{Network, Message};
    use network_libp2p::NetworkConfiguration;
    use libp2p::PeerId;

    #[test]
    fn test_send_receive() {
        let cfg = NetworkConfiguration::new_local();
        let msg_chan = Network::start_network(cfg.clone());
        println!("{:?}", cfg.listen_addresses[0]);

        let msg = {
            let pub_key = cfg.node_key.clone().into_keypair().unwrap().public();
            let peer_id = PeerId::from(pub_key);
            Message {
                peer_id,
                msg: vec![1, 2],
            }
        };
        let rt = tokio::runtime::Runtime::new();
        msg_chan.msg_sender.send(msg);
        let receive_msg = msg_chan.msg_receiver.recv().unwrap();
        println!("{:?}", receive_msg.msg);
    }
}
