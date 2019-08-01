use network::p2p::{new_network,NetConfig};
use network::mem_stream::{MemTcpStream, MemNetwork,MemListener};
use std::net::SocketAddr;
use futures::{Stream, Future,future};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "stargate",
    author = "star-team",
    about = "stargate local node "
)]
struct Args {
    /// Enable logging
    #[structopt(short = "l", long = "enable_logging")]
    pub enable_logging: bool,
    /// Start client
    #[structopt(short = "s", long = "start_client")]
    pub start_client: bool,
    /// Directory used by launch_swarm to output LibraNodes' config files, logs, libradb, etc,
    /// such that user can still inspect them after exit.
    /// If unspecified, a temporary dir will be used and auto deleted.
    #[structopt(short = "c", long = "config_dir")]
    pub config_dir: Option<String>,
    /// If specified, load faucet key from this file. Otherwise generate new keypair file.
    #[structopt(short = "f", long = "faucet_key_path")]
    pub faucet_key_path: Option<String>,
}


fn main(){
    let args = Args::from_args();
    if args.start_client {
    }else {
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

    let cfg = NetConfig {
        bootstrap: vec![],
        max_sockets: 0,
        memory_stream: false,
    };
    let network = new_network::<
        MemTcpStream,
        future::Ready<MemTcpStream>,
        MemListener,
        MemNetwork,
    >(cfg);
    
    
}