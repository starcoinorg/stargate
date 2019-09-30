// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use config::trusted_peers::ConfigHelpers;
use executable_helpers::helpers::{
    setup_executable, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING, ARG_PEER_ID,
};
use logger::prelude::*;
use signal_hook;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

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
    let (mut config, _logger, _args) = setup_executable(
        "Star single node".to_string(),
        vec![ARG_PEER_ID, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING],
    );
    debug!("config : {:?}", config);
    if config.consensus.get_consensus_peers().len() == 0 {
        let (_, single_peer_consensus_config) = ConfigHelpers::get_test_consensus_config(1, None);
        config.consensus.consensus_peers = single_peer_consensus_config;
        sgchain::star_chain_client::genesis_blob(&config.execution.genesis_file_location);
    }

    let (_ac_handle, _node_handle) = sgchain::setup_environment(&mut config);

    let term = Arc::new(AtomicBool::new(false));
    register_signals(Arc::clone(&term));

    while !term.load(Ordering::Acquire) {
        std::thread::park();
    }
}
