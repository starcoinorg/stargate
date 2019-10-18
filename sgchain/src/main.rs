// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use executable_helpers::helpers::setup_executable;
use logger::prelude::*;
use signal_hook;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use libra_node::main_node;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "Libra Node")]
struct Args {
    #[structopt(short = "f", long, parse(from_os_str))]
    /// Path to NodeConfig
    config: Option<PathBuf>,
    #[structopt(short = "d", long)]
    /// Disable logging
    no_logging: bool,
}

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn register_signals(term: Arc<AtomicBool>) {
    for signal in &[
        signal_hook::SIGTERM,
        signal_hook::SIGINT,
        signal_hook::SIGHUP,
    ] {
        let term_clone = Arc::clone(&term);
        let thread = std::thread::current();
        unsafe {
            signal_hook::register(*signal, move || {
                term_clone.store(true, Ordering::Release);
                thread.unpark();
            })
            .expect("failed to register signal handler");
        }
    }
}

fn main() {
    let args = Args::from_args();

    let (mut config, _logger) =
        setup_executable(args.config.as_ref().map(PathBuf::as_path), args.no_logging);

    debug!("config : {:?}", config);
    sgchain::star_chain_client::genesis_blob(&config);

    let _handle = main_node::setup_environment(&mut config);

    let term = Arc::new(AtomicBool::new(false));
    register_signals(Arc::clone(&term));

    while !term.load(Ordering::Acquire) {
        std::thread::park();
    }
}
