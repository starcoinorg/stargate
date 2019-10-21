// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use signal_hook;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use sgchain::main_node::run_node;
use std::path::PathBuf;
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
    let (_config, _logger, _handler) =
        run_node(args.config.as_ref().map(PathBuf::as_path), args.no_logging);
    let term = Arc::new(AtomicBool::new(false));
    register_signals(Arc::clone(&term));
    while !term.load(Ordering::Acquire) {
        std::thread::park();
    }
}
