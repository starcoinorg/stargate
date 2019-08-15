use chain_service::chain_node::{ChainNode, ServiceConfig};
use clap::{value_t, Arg, App};

const IP_ARG: &str = "ip";
const PORT_ARG: &str = "port";
const SERVICE_NAME_ARG: &str = "service_name";

fn main() {
    let args = App::new("chain_node")
        .author("Star Labs")
        .about("Tool to manage and create chain config")
        .arg(
            Arg::with_name(IP_ARG)
            .short("i")
            .long(IP_ARG)
            .takes_value(true)
            .default_value("127.0.0.1")
            .help("ip"),
        ).arg(
            Arg::with_name(PORT_ARG)
            .short("p")
            .long(PORT_ARG)
            .takes_value(true)
            .default_value("3000")
            .help("port")
        ).arg(
        Arg::with_name(SERVICE_NAME_ARG)
            .short("s")
            .long(SERVICE_NAME_ARG)
            .takes_value(true)
            .default_value("chain_service")
            .help("service name")
    ).get_matches();

    let address = value_t!(args, IP_ARG, String).expect("Missing ip.");
    let port = value_t!(args, PORT_ARG, u16).expect("Missing port.");
    let service_name = value_t!(args, SERVICE_NAME_ARG, String).expect("Missing service name.");
    let conf = ServiceConfig { service_name, address, port };
    let node = ChainNode::new(conf);
    node.run();
}