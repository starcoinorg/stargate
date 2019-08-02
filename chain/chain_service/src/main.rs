use chain_service::chain_node::{ChainNode, ServiceConfig};

fn main() {
    let service_name = String::from("chain_service");
    let address = String::from("127.0.0.1");
    let port:u16 = 8080;
    let conf = ServiceConfig { service_name, address, port };
    let node = ChainNode::new(conf);
    node.run().unwrap();
}