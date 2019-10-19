// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use signal_hook;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use sgchain::main_node::{run_node, Args};
use structopt::StructOpt;

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
    let (_handle, _config, _logger) = run_node(args);
    let term = Arc::new(AtomicBool::new(false));
    register_signals(Arc::clone(&term));
    while !term.load(Ordering::Acquire) {
        std::thread::park();
    }
}
