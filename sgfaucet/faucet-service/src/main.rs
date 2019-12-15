use std::thread;
use ::faucet_service::FaucetNode;
use libra_logger::prelude::*;

fn main() {
    let _handle = FaucetNode::load_and_run();

    info!("Started Storage Service");
    loop {
        thread::park();
    }
}