// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use libra_logger::prelude::*;
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use std::sync::Arc;

pub fn run_with_rpc_client<F, T>(mut f: F) -> T
where
    F: FnMut(Arc<dyn ChainClient>) -> T,
{
    libra_logger::try_init_for_testing();
    let _ = slog_stdlog::init();
    let (config, _logger, _handler) = sgchain::main_node::run_node(None, false, true);
    info!("node is running.");
    let ac_port = config.admission_control.admission_control_service_port;
    let rpc_client = Arc::new(StarChainClient::new("127.0.0.1", ac_port as u32));
    f(rpc_client.clone())
}
