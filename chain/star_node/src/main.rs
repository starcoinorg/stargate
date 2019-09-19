// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use executable_helpers::helpers::{
    setup_executable, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING, ARG_PEER_ID,
};
use signal_hook;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use config::trusted_peers::ConfigHelpers;
use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};
use std::fs::File;
use proto_conv::{IntoProto, IntoProtoBytes};
use std::io::Write;
use std::path::Path;
use tools::tempdir::TempPath;
use logger::prelude::*;
use std::fs::create_dir_all;

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

fn genesis_blob() -> String {
    let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
    let genesis_txn = genesis_checked_txn.into_inner();
//    let tmp_dir = TempPath::new();
//    tmp_dir.create_as_dir().unwrap();
//    let path = tmp_dir.path().display();
    let path = "/tmp/data";
    let blob_path = Path::new(&path);
    if !blob_path.exists() {
        create_dir_all(blob_path).unwrap();
    }
    let file = format!("{}/{}", path, "genesis.blob");
    let mut genesis_file = File::create(Path::new(&file)).expect("open genesis file err.");
    genesis_file.write_all(genesis_txn.into_proto_bytes().expect("genesis_txn to bytes err.").as_slice()).expect("write genesis file err.");
    genesis_file.flush().unwrap();
    info!("genesis blob path: {}", file);
    file
}

fn main() {
    let (mut config, _logger, _args) = setup_executable(
        "Star single node".to_string(),
        vec![ARG_PEER_ID, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING],
    );
    if config.consensus.get_consensus_peers().len() == 0 {
        let (_, single_peer_consensus_config) = ConfigHelpers::get_test_consensus_config(1, None);
        config.consensus.consensus_peers = single_peer_consensus_config;
    }

    let genesis_path = genesis_blob();
    config.execution.genesis_file_location = genesis_path;
    let (_ac_handle, _node_handle) = star_node::star_node::setup_environment(&mut config);

    let term = Arc::new(AtomicBool::new(false));
    register_signals(Arc::clone(&term));

    while !term.load(Ordering::Acquire) {
        std::thread::park();
    }
}
