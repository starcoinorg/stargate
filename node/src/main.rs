use std::net::SocketAddr;
use futures::{Stream, Future, future};
use structopt::StructOpt;
use node_service::setup_node_service;
use sg_config::config::{NodeConfig, NetworkConfig, NodeNetworkConfig};
use node::client;

#[derive(Debug, StructOpt)]
#[structopt(
name = "stargate",
author = "star-team",
about = "stargate local node "
)]
struct Args {
    #[structopt(short = "l", long = "enable_logging")]
    pub enable_logging: bool,
    #[structopt(short = "s", long = "start_client")]
    pub start_client: bool,
    #[structopt(short = "c", long = "config_dir")]
    pub config_dir: Option<String>,
    #[structopt(short = "f", long = "faucet_key_path")]
    pub faucet_key_path: Option<String>,
}

pub struct Swarm {
    pub config: NodeConfig,
    tee_logs: bool,
}

fn launch_swarm(args: &Args) -> Swarm {
    Swarm {
        config: NodeConfig {
            network: NetworkConfig {
                address: "localhost".to_string(),
                port: 8080,
            },
            node_net_work: NodeNetworkConfig {
                addr: String::from("127.0.0.1:8000"),
                max_sockets: 0,
                in_memory: false,
                seeds: vec![String::from("127.0.0.1:8001")],
            },
        },
        tee_logs: true,
    }
}

fn main() {
    let args = Args::from_args();
    let swarm = launch_swarm(&args);

    let mut node_server = setup_node_service(&swarm.config);
    node_server.start();

    let cfg = NodeNetworkConfig {
        addr: "".to_string(),
        max_sockets: 0,
        in_memory: false,
        seeds: vec![]
    };
    if args.start_client {
        let client = client::InteractiveClient::new_with_inherit_io(
            swarm.config.network.port
            //Path::new(&faucet_key_file_path),
        );
        println!("Loading client...");
        let _output = client.output().expect("Failed to wait on child");
        println!("Exit client.");
    } else {
        let (tx, rx) = std::sync::mpsc::channel();
        ctrlc::set_handler(move || {
            tx.send(())
                .expect("failed to send unit when handling CTRL-C");
        })
            .expect("failed to set CTRL-C handler");
        println!("CTRL-C to exit.");
        rx.recv()
            .expect("failed to receive unit when handling CTRL-C");
    }
}
